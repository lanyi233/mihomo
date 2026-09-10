//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/pool"
)

func TestDNSRelayLimiterBoundsConcurrency(t *testing.T) {
	limiter := newDNSRelayLimiter(context.Background(), 2)
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var running atomic.Int32
	var maximum atomic.Int32
	work := func(context.Context) {
		current := running.Add(1)
		for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
		}
		started <- struct{}{}
		<-release
		running.Add(-1)
	}

	if !limiter.start(nil, nil, work) || !limiter.start(nil, nil, work) {
		t.Fatal("the first two relays should acquire slots")
	}
	<-started
	<-started
	if limiter.start(nil, nil, func(context.Context) { t.Error("rejected relay ran") }) {
		t.Fatal("relay above the limit was accepted")
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", got)
	}

	close(release)
	limiter.close()
}

func TestDNSRelayLimiterCloseCancelsWaitsAndRejects(t *testing.T) {
	limiter := newDNSRelayLimiter(context.Background(), 2)
	canceled := make(chan struct{}, 2)
	finish := make(chan struct{})
	for range 2 {
		if !limiter.start(nil, nil, func(ctx context.Context) {
			<-ctx.Done()
			canceled <- struct{}{}
			<-finish
		}) {
			t.Fatal("relay was unexpectedly rejected")
		}
	}

	closed := make(chan struct{})
	go func() {
		limiter.close()
		close(closed)
	}()
	for range 2 {
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("in-flight relay was not canceled")
		}
	}
	select {
	case <-closed:
		t.Fatal("close returned before in-flight relays finished")
	default:
	}
	if limiter.start(nil, nil, func(context.Context) {}) {
		t.Fatal("relay was accepted after close began")
	}
	close(finish)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not wait for relays to finish")
	}
}

func TestDNSRelayLimiterUsesParentContextAndAcceptsNilParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	limiter := newDNSRelayLimiter(parent, 1)
	done := make(chan struct{})
	if !limiter.start(nil, nil, func(ctx context.Context) {
		<-ctx.Done()
		close(done)
	}) {
		t.Fatal("relay was unexpectedly rejected")
	}
	cancelParent()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach relay")
	}
	limiter.close()

	nilParent := newDNSRelayLimiter(nil, 1)
	if !nilParent.start(nil, nil, func(context.Context) {}) {
		t.Fatal("nil parent should fall back to a live background context")
	}
	nilParent.close()
}

func TestDNSRelayLimiterStartCloseRace(t *testing.T) {
	for range 100 {
		limiter := newDNSRelayLimiter(context.Background(), 8)
		start := make(chan struct{})
		var callers sync.WaitGroup
		for range 16 {
			callers.Add(1)
			go func() {
				defer callers.Done()
				<-start
				limiter.start(nil, nil, func(ctx context.Context) { <-ctx.Done() })
			}()
		}
		close(start)
		go limiter.close()
		callers.Wait()
		limiter.close()
	}
}

type lockedTrackingAllocator struct {
	pool.Allocator
	access   sync.Mutex
	returned [][]byte
}

func (a *lockedTrackingAllocator) Put(buffer []byte) error {
	a.access.Lock()
	a.returned = append(a.returned, buffer)
	a.access.Unlock()
	return nil
}

func (a *lockedTrackingAllocator) returnsOf(buffer []byte) int {
	a.access.Lock()
	defer a.access.Unlock()
	count := 0
	for _, returned := range a.returned {
		if len(returned) > 0 && &returned[0] == &buffer[0] {
			count++
		}
	}
	return count
}

func TestRejectedUDPDNSRelayReturnsPayloadWithoutRetainingClient(t *testing.T) {
	original := pool.DefaultAllocator
	tracker := &lockedTrackingAllocator{Allocator: original}
	pool.DefaultAllocator = tracker
	defer func() { pool.DefaultAllocator = original }()

	limiter := newDNSRelayLimiter(context.Background(), 1)
	release := make(chan struct{})
	if !limiter.start(nil, nil, func(context.Context) { <-release }) {
		t.Fatal("failed to occupy relay slot")
	}
	inbound := &Inbound{dnsRelays: limiter}
	clientState := &udpClientState{}
	payload := make([]byte, 64)
	inbound.startUDPDNSRelay(
		payload,
		netip.MustParseAddrPort("192.0.2.1:53000"),
		clientState,
		netip.MustParseAddrPort("1.1.1.1:53"),
	)
	if got := tracker.returnsOf(payload); got != 1 {
		t.Fatalf("rejected payload returned %d times, want 1", got)
	}
	if pending := clientState.activity.pending.Load(); pending != 0 {
		t.Fatalf("rejected relay retained client state: pending=%d", pending)
	}

	close(release)
	limiter.close()
}

func TestTCPDNSCloseUnblocksIdleReader(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	i := &Inbound{}
	i.startTCPDNSRelay(server)
	done := make(chan struct{})
	go func() { i.stopDNSRelays(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown left idle DNS TCP read blocked")
	}
}

func TestDNSRelayPinsClientUntilWorkFinishes(t *testing.T) {
	limiter := newDNSRelayLimiter(nil, 1)
	state := &udpClientState{}
	finish := make(chan struct{})
	if !limiter.start(state.activity.retain, state.activity.release, func(context.Context) { <-finish }) {
		t.Fatal("admission rejected")
	}
	state.activity.last.Store(1)
	if state.activity.idle(2) {
		t.Fatal("active DNS request considered idle")
	}
	close(finish)
	limiter.close()
	if state.activity.pending.Load() != 0 || state.activity.last.Load() <= 1 {
		t.Fatal("DNS did not release and refresh client")
	}
}
