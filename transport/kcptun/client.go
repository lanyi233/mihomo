package kcptun

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/randv2"
	"github.com/metacubex/smux"
)

const Mode = "kcptun"

type DialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

type Client struct {
	config Config
	block  kcp.BlockCrypt

	ctx    context.Context
	cancel context.CancelFunc

	numconn uint16
	muxes   []timedSession
	rr      uint16
	connMu  sync.Mutex

	chScavenger   chan timedSession
	scavengerDone chan struct{}
}

func NewClient(config Config) *Client {
	config.FillDefaults()
	block := config.NewBlock()

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config: config,
		block:  block,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (c *Client) Close() error {
	c.cancel()
	c.connMu.Lock()
	for _, mux := range c.muxes {
		if mux.session != nil {
			_ = mux.session.Close()
		}
	}
	done := c.scavengerDone
	c.connMu.Unlock()
	if done != nil {
		<-done
	}
	return nil
}

func (c *Client) createConn(ctx context.Context, dial DialFn) (*smux.Session, error) {
	// Opening a stream has the caller's deadline, but client shutdown must
	// also interrupt an in-flight dial before Close waits for connMu.
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	conn, addr, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	config := c.config
	convid := randv2.Uint32()
	kcpconn, err := kcp.NewConn4(convid, addr, c.block, config.DataShard, config.ParityShard, true, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)
	kcpconn.SetRateLimit(uint32(config.RateLimit))

	_ = kcpconn.SetDSCP(config.DSCP)
	_ = kcpconn.SetReadBuffer(config.SockBuf)
	_ = kcpconn.SetWriteBuffer(config.SockBuf)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.MaxFrameSize = config.FrameSize
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
		smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
	}

	if err := smux.VerifyConfig(smuxConfig); err != nil {
		_ = kcpconn.Close()
		return nil, err
	}

	var netConn net.Conn = kcpconn
	if !config.NoComp {
		netConn = NewCompStream(netConn)
	}
	// stream multiplex
	return smux.Client(netConn, smuxConfig)
}

func (c *Client) OpenStream(ctx context.Context, dial DialFn) (*smux.Stream, error) {
	c.connMu.Lock()
	if c.ctx.Err() != nil {
		c.connMu.Unlock()
		return nil, net.ErrClosed
	}
	if c.muxes == nil {
		// start scavenger if autoexpire is set
		if c.config.AutoExpire > 0 {
			c.chScavenger = make(chan timedSession, 128)
			c.scavengerDone = make(chan struct{})
			go func() {
				defer close(c.scavengerDone)
				scavenger(c.ctx, c.chScavenger, &c.config)
			}()
		}

		c.numconn = uint16(c.config.Conn)
		c.muxes = make([]timedSession, c.config.Conn)
		c.rr = uint16(0)
	}
	idx := c.rr % c.numconn

	// do auto expiration && reconnection
	if c.muxes[idx].session == nil || c.muxes[idx].session.IsClosed() ||
		(c.config.AutoExpire > 0 && time.Now().After(c.muxes[idx].expiryDate)) {
		var err error
		session, err := c.createConn(ctx, dial)
		if err != nil {
			c.connMu.Unlock()
			return nil, err
		}
		if c.ctx.Err() != nil {
			_ = session.Close()
			c.connMu.Unlock()
			return nil, net.ErrClosed
		}
		c.muxes[idx].session = session
		c.muxes[idx].expiryDate = time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
		if c.config.AutoExpire > 0 { // only when autoexpire set
			select {
			case c.chScavenger <- c.muxes[idx]:
			case <-c.ctx.Done():
				_ = session.Close()
				c.connMu.Unlock()
				return nil, net.ErrClosed
			case <-ctx.Done():
				_ = session.Close()
				c.connMu.Unlock()
				return nil, ctx.Err()
			}
		}

	}
	c.rr++
	session := c.muxes[idx].session
	c.connMu.Unlock()

	return session.OpenStream()
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

// scavenger goroutine is used to close expired sessions
func scavenger(ctx context.Context, ch chan timedSession, config *Config) {
	var ticker *time.Ticker
	var tick <-chan time.Time
	var sessionList []timedSession
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
		for _, item := range sessionList {
			_ = item.session.Close()
		}
		// Sessions accepted before cancellation may still be in the queue.
		for {
			select {
			case item := <-ch:
				_ = item.session.Close()
			default:
				return
			}
		}
	}()
	for {
		select {
		case item := <-ch:
			sessionList = append(sessionList, timedSession{
				item.session,
				item.expiryDate.Add(time.Duration(config.ScavengeTTL) * time.Second)})
			if tick == nil {
				if ticker == nil {
					ticker = time.NewTicker(scavengePeriod * time.Second)
				} else {
					ticker.Reset(scavengePeriod * time.Second)
				}
				tick = ticker.C
			}
		case <-tick:
			newList := sessionList[:0]
			now := time.Now()
			for k := range sessionList {
				s := sessionList[k]
				if s.session.IsClosed() {
					if log.DebugEnabled() {
						log.Debugln("scavenger: session normally closed: %s", s.session.LocalAddr())
					}
				} else if now.After(s.expiryDate) {
					s.session.Close()
					if log.DebugEnabled() {
						log.Debugln("scavenger: session closed due to ttl: %s", s.session.LocalAddr())
					}
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			clear(sessionList[len(newList):])
			sessionList = newList
			if len(sessionList) == 0 {
				ticker.Stop()
				tick = nil
			}
		case <-ctx.Done():
			return
		}
	}
}
