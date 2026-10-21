package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/skiplist"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex
	idleWake        chan struct{}

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.Pointer[padding.PaddingFactory]

	clientMetadata     string
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool
}

func NewClient(ctx context.Context, dialOut util.DialOutFunc, _padding *atomic.Pointer[padding.PaddingFactory], clientMetadata string, idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, disableReuse bool) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		clientMetadata:     clientMetadata,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		idleWake:           make(chan struct{}, 1),
		disableReuse:       disableReuse,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	if !c.disableReuse {
		go c.runIdleCleanup(idleSessionCheckInterval)
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	if !c.disableReuse {
		session = c.getIdleSession()
	}
	if session == nil {
		session, err = c.createSession(ctx)
	}
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err = session.OpenStream()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	stream.dieHook = func() {
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			if c.disableReuse {
				session.Close()
				return
			}

			select {
			case <-c.die.Done():
				// Now client has been closed
				session.Close()
			default:
				c.idleSessionLock.Lock()
				// Close may have canceled after the select above, or the
				// session may already have removed itself from this pool.
				if c.die.Err() == nil && !session.IsClosed() {
					session.idleSince = time.Now()
					c.idleSession.Insert(math.MaxUint64-session.seq, session)
					select {
					case c.idleWake <- struct{}{}:
					default:
					}
				}
				c.idleSessionLock.Unlock()
			}
		}
	}

	return stream, nil
}

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	if !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		idle = it.Value()
		c.idleSession.Remove(it.Key())
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	if c.die.Err() != nil {
		c.sessionsLock.Unlock()
		// A dialer may finish after Close has already drained the map.
		// Do not publish a session that no later Close would see.
		session.Close()
		return nil, io.ErrClosedPipe
	}
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) runIdleCleanup(interval time.Duration) {
	// Preserve the panic reporting previously supplied by util.StartRoutine.
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
		}
	}()
	timer := time.NewTimer(interval)
	timer.Stop()
	defer timer.Stop()
	var tick <-chan time.Time
	for {
		select {
		case <-c.die.Done():
			return
		case <-c.idleWake:
		case <-tick:
			tick = nil
			if c.die.Err() != nil {
				return
			}
			c.idleCleanup()
		}
		c.idleSessionLock.Lock()
		needsCleanup := c.idleSession.Len() > max(c.minIdleSession, 0)
		c.idleSessionLock.Unlock()
		if needsCleanup && tick == nil {
			timer.Reset(interval)
			tick = timer.C
		} else if !needsCleanup && tick != nil {
			timer.Stop()
			tick = nil
		}
	}
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0

	c.idleSessionLock.Lock()
	sessionToClose := make([]*Session, 0, c.idleSession.Len())

	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
