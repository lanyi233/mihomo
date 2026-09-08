package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSConnectionPoolResetRejectsInflightReturn(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxIdle: 1})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })

	lease, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	pool.reset()
	pool.release(lease, true)
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("stale connection returned after reset: idle=%d", got)
	}

	var dials atomic.Int32
	secondClient, secondPeer := net.Pipe()
	t.Cleanup(func() { _ = secondPeer.Close() })
	second, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return secondClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(second, false)
	if got := dials.Load(); got != 1 {
		t.Fatalf("expected a fresh dial after reset, got %d", got)
	}
}

func TestDNSConnectionPoolRotatesByUseLimit(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{
		maxIdle: 1,
		maxUses: 2,
	})
	var dials atomic.Int32
	var peers []net.Conn
	t.Cleanup(func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	})
	dial := func(context.Context) (net.Conn, error) {
		dials.Add(1)
		client, peer := net.Pipe()
		peers = append(peers, peer)
		return client, nil
	}

	for range 3 {
		lease, err := pool.acquire(context.Background(), dial)
		if err != nil {
			t.Fatal(err)
		}
		pool.release(lease, true)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("expected connection rotation after two uses, got %d dials", got)
	}
}

func TestDNSConnectionPoolExpiresIdleConnection(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{
		maxIdle:     1,
		idleTimeout: 20 * time.Millisecond,
	})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	lease, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(lease, true)

	deadline := time.Now().Add(time.Second)
	for pool.idleCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("idle connection was not expired: idle=%d", got)
	}
}

func TestDNSConnectionPoolOpenLimitWaitsAndHonorsContext(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{
		maxOpen: 1,
		maxIdle: 1,
	})
	firstClient, firstPeer := net.Pipe()
	t.Cleanup(func() { _ = firstPeer.Close() })
	var dials atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return firstClient, nil
	}
	first, err := pool.acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = pool.acquire(waitCtx, dial)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected waiting acquire to honor deadline, got %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("open limit allowed an extra dial: %d", got)
	}

	pool.release(first, true)
	second, err := pool.acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	if !second.reused {
		t.Fatal("waiting capacity did not reuse released connection")
	}
	pool.release(second, false)
}

func TestDNSConnectionPoolReleaseWakesCapacityWaiter(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: 1, maxIdle: 1})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	first, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	waiterDone := make(chan *dnsConnectionLease, 1)
	waiterErr := make(chan error, 1)
	go func() {
		lease, acquireErr := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
			return nil, errors.New("waiter unexpectedly dialed")
		})
		if acquireErr != nil {
			waiterErr <- acquireErr
			return
		}
		waiterDone <- lease
	}()
	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		waiters := pool.state.waiters
		notify := pool.state.notify
		pool.mu.Unlock()
		if waiters == 1 {
			pool.release(first, true)
			select {
			case <-notify:
			case <-time.After(time.Second):
				t.Fatal("successful release did not signal capacity waiters")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second acquire did not wait for capacity")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case err = <-waiterErr:
		t.Fatal(err)
	case second := <-waiterDone:
		if !second.reused || second.connection != first.connection {
			t.Fatal("waiter did not receive the released connection")
		}
		pool.release(second, false)
	case <-time.After(time.Second):
		t.Fatal("capacity waiter was not woken by release")
	}
}

func TestDNSConnectionPoolCanceledContextDoesNotTakeIdle(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: 1, maxIdle: 1})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	first, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(first, true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = pool.acquire(ctx, func(context.Context) (net.Conn, error) {
		return nil, errors.New("canceled acquire unexpectedly dialed")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled acquire, got %v", err)
	}
	if got := pool.idleCount(); got != 1 {
		t.Fatalf("canceled acquire consumed idle connection: idle=%d", got)
	}
	pool.reset()
}

func TestDNSConnectionPoolFreshAcquireEvictsIdleAtOpenLimit(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: 1, maxIdle: 1})
	firstClient, firstPeer := net.Pipe()
	first, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return firstClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(first, true)

	secondClient, secondPeer := net.Pipe()
	t.Cleanup(func() { _ = secondPeer.Close() })
	var dials atomic.Int32
	second, err := pool.acquireFresh(context.Background(), func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return secondClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.reused {
		t.Fatal("fresh acquire reused an idle connection")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("fresh acquire did not dial exactly once: %d", got)
	}
	_ = firstPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = firstPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection was not evicted for fresh dial")
	}
	pool.release(second, false)
}

func TestDNSConnectionPoolKeepsIdleTimerAcrossBusyLease(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{
		maxOpen:     1,
		maxIdle:     1,
		idleTimeout: time.Minute,
	})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	first, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(first, true)
	pool.mu.Lock()
	firstTimer := pool.timer
	pool.mu.Unlock()
	if firstTimer == nil {
		t.Fatal("idle timer was not scheduled")
	}

	second, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.release(second, true)
	pool.mu.Lock()
	secondTimer := pool.timer
	pool.mu.Unlock()
	if secondTimer != firstTimer {
		t.Fatal("busy lease recreated the idle timer")
	}
	pool.reset()
}

func TestDNSConnectionPoolCloseUnblocksWaiter(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: 1})
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	first, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, acquireErr := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
			t.Error("waiter dialed past the open limit")
			return nil, net.ErrClosed
		})
		done <- acquireErr
	}()
	if err = pool.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected closed error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock capacity waiter")
	}
	pool.release(first, false)
}

func TestDNSConnectionPoolResetRejectsDialThatReturnsLate(t *testing.T) {
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: 1, maxIdle: 1})
	dialStarted := make(chan struct{})
	allowReturn := make(chan struct{})
	peerClosed := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		_, err := pool.acquire(context.Background(), func(context.Context) (net.Conn, error) {
			client, peer := net.Pipe()
			close(dialStarted)
			<-allowReturn
			go func() {
				buffer := make([]byte, 1)
				_, readErr := peer.Read(buffer)
				peerClosed <- readErr
				_ = peer.Close()
			}()
			return client, nil
		})
		done <- err
	}()
	<-dialStarted
	pool.reset()
	close(allowReturn)
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late dial returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not reject late dial")
	}
	select {
	case err := <-peerClosed:
		if err == nil {
			t.Fatal("late connection was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("late connection remained open")
	}
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("late connection entered replacement pool: idle=%d", got)
	}
}

func TestDNSConnectionPoolBoundsConcurrentDials(t *testing.T) {
	const maxOpen = 4
	pool := newDNSConnectionPool(dnsConnectionPoolOptions{maxOpen: maxOpen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allowDials := make(chan struct{})
	var activeDials atomic.Int32
	var peakDials atomic.Int32
	dial := func(ctx context.Context) (net.Conn, error) {
		active := activeDials.Add(1)
		for {
			peak := peakDials.Load()
			if active <= peak || peakDials.CompareAndSwap(peak, active) {
				break
			}
		}
		select {
		case <-allowDials:
		case <-ctx.Done():
			activeDials.Add(-1)
			return nil, ctx.Err()
		}
		activeDials.Add(-1)
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	}

	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			lease, err := pool.acquire(ctx, dial)
			if err == nil {
				pool.release(lease, false)
			}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for activeDials.Load() < maxOpen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := activeDials.Load(); got != maxOpen {
		t.Fatalf("expected %d concurrent dials, got %d", maxOpen, got)
	}
	time.Sleep(20 * time.Millisecond)
	if got := peakDials.Load(); got > maxOpen {
		t.Fatalf("open limit exceeded: peak dials=%d", got)
	}
	close(allowDials)
	waitGroup.Wait()
	if got := peakDials.Load(); got > maxOpen {
		t.Fatalf("open limit exceeded after release: peak dials=%d", got)
	}
}
