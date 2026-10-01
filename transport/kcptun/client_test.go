package kcptun

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/smux"
)

type trackedPacketConn struct {
	net.PacketConn
	once   sync.Once
	closed chan struct{}
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

func TestClientCloseStopsCurrentAndRetiredSessions(t *testing.T) {
	for _, autoExpire := range []int{0, 1} {
		t.Run(map[int]string{0: "no expiration", 1: "expiration"}[autoExpire], func(t *testing.T) {
			client := NewClient(Config{AutoExpire: autoExpire, ScavengeTTL: 1, NoComp: true, Crypt: "none"})
			defer client.Close()
			peer, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			var sockets []*trackedPacketConn
			dial := func(context.Context) (net.PacketConn, net.Addr, error) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				tracked := &trackedPacketConn{PacketConn: pc, closed: make(chan struct{})}
				sockets = append(sockets, tracked)
				return tracked, peer.LocalAddr(), nil
			}
			if _, err := client.OpenStream(context.Background(), dial); err != nil {
				t.Fatal(err)
			}
			first := client.muxes[0].session
			if autoExpire > 0 {
				client.connMu.Lock()
				client.muxes[0].expiryDate = time.Now().Add(-time.Second)
				client.connMu.Unlock()
				if _, err := client.OpenStream(context.Background(), dial); err != nil {
					t.Fatal(err)
				}
				if client.muxes[0].session == first {
					t.Fatal("session was not rotated")
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if !first.IsClosed() || !client.muxes[0].session.IsClosed() {
				t.Fatal("client close left a live session")
			}
			for _, socket := range sockets {
				select {
				case <-socket.closed:
				default:
					t.Fatal("client close left a UDP socket running")
				}
			}
			if _, err := client.OpenStream(context.Background(), dial); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("OpenStream after Close returned %v", err)
			}
		})
	}
}

func TestClientCloseInterruptsDial(t *testing.T) {
	client := NewClient(Config{})
	defer client.Close()
	started := make(chan struct{})
	opened := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			close(started)
			<-ctx.Done()
			return nil, nil, ctx.Err()
		})
		opened <- err
	}()
	<-started
	closed := make(chan struct{})
	go func() { _ = client.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the pending dial")
	}
	if err := <-opened; !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v", err)
	}
}

func TestClientCloseBeforeFirstStream(t *testing.T) {
	client := NewClient(Config{})
	_ = client.Close()
	_, err := client.OpenStream(context.Background(), func(context.Context) (net.PacketConn, net.Addr, error) {
		t.Fatal("closed client attempted to dial")
		return nil, nil, nil
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OpenStream error = %v", err)
	}
}

func TestClientCloseDisposesLateDialResult(t *testing.T) {
	client := NewClient(Config{NoComp: true})
	defer client.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &trackedPacketConn{PacketConn: pc, closed: make(chan struct{})}
	defer tracked.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	opened := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), func(context.Context) (net.PacketConn, net.Addr, error) {
			close(started)
			<-release // Simulate a dialer that returns success after cancellation.
			return tracked, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil
		})
		opened <- err
	}()
	<-started
	closed := make(chan struct{})
	go func() { _ = client.Close(); close(closed) }()
	<-client.ctx.Done()
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after the pending dial returned")
	}
	if err := <-opened; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late dial OpenStream error = %v", err)
	}
	select {
	case <-tracked.closed:
	default:
		t.Fatal("late dial socket was not closed")
	}
}

func TestScavengerExpiresAndRestartsAfterIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		queued := make(chan timedSession, 2)
		done := make(chan struct{})
		go func() { defer close(done); scavenger(ctx, queued, &Config{ScavengeTTL: 1}) }()
		for range 2 {
			time.Sleep(time.Hour)
			left, right := net.Pipe()
			defer right.Close()
			cfg := smux.DefaultConfig()
			cfg.KeepAliveDisabled = true
			session, err := smux.Client(left, cfg)
			if err != nil {
				t.Fatal(err)
			}
			queued <- timedSession{session: session, expiryDate: time.Now()}
			synctest.Wait()
			time.Sleep(5 * time.Second)
			synctest.Wait()
			if !session.IsClosed() {
				t.Fatal("scavenger did not expire session after waking from idle")
			}
		}
		cancel()
		<-done
	})
}
