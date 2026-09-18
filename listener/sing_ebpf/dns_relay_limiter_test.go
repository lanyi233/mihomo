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

	D "github.com/miekg/dns"
)

func TestDNSRelayLimiterBoundsConcurrency(t *testing.T) {
	limiter := newDNSRelayLimiterWithLimits(context.Background(), 2, 2, 2)
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

	if !limiter.startUDP(nil, nil, work) || !limiter.startUDP(nil, nil, work) {
		t.Fatal("the first two relays should acquire slots")
	}
	<-started
	<-started
	if limiter.startUDP(nil, nil, func(context.Context) { t.Error("rejected relay ran") }) {
		t.Fatal("relay above the limit was accepted")
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", got)
	}

	close(release)
	limiter.close()
}

// A hijacked TCP relay holds its slot for the whole connection while a UDP
// relay holds one for a single datagram, so they must not draw on the same
// budget: otherwise a handful of idle-but-open connections switches DNS off for
// every other client on the inbound.
func TestDNSRelayLimiterKeepsTCPAndUDPBudgetsSeparate(t *testing.T) {
	limiter := newDNSRelayLimiterWithLimits(context.Background(), 1, 1, 1)
	defer limiter.close()
	release := make(chan struct{})
	defer close(release)

	client := netip.MustParseAddr("192.0.2.5")
	if !limiter.startTCP(client, func(context.Context) { <-release }) {
		t.Fatal("first TCP relay should acquire a slot")
	}
	if limiter.startTCP(client, func(context.Context) { t.Error("rejected TCP relay ran") }) {
		t.Fatal("TCP relay above the limit was accepted")
	}
	if !limiter.startUDP(nil, nil, func(context.Context) { <-release }) {
		t.Fatal("an occupied TCP budget must not block UDP relays")
	}
}

// One client must not be able to take the whole TCP budget - but the share only
// binds under pressure, because in local mode every process reports the same
// source address and an always-on cap would be a cap on the whole host.
func TestDNSRelayLimiterCapsTCPRelaysPerClientUnderPressure(t *testing.T) {
	limiter := newDNSRelayLimiterWithLimits(context.Background(), 8, 8, 2)
	defer limiter.close()
	release := make(chan struct{})
	defer close(release)

	noisy := netip.MustParseAddr("192.0.2.5")
	// Half the budget is free, so one identity may use it all.
	for range 4 {
		if !limiter.startTCP(noisy, func(context.Context) { <-release }) {
			t.Fatal("relay was rejected while the TCP budget still had headroom")
		}
	}
	if limiter.startTCP(noisy, func(context.Context) { t.Error("rejected TCP relay ran") }) {
		t.Fatal("one client exceeded its share of a pressured TCP budget")
	}
	quiet := netip.MustParseAddr("192.0.2.6")
	if !limiter.startTCP(quiet, func(context.Context) { <-release }) {
		t.Fatal("a noisy client starved another client out of the TCP budget")
	}
}

func TestDNSRelayLimiterCloseCancelsWaitsAndRejects(t *testing.T) {
	limiter := newDNSRelayLimiterWithLimits(context.Background(), 2, 2, 2)
	canceled := make(chan struct{}, 2)
	finish := make(chan struct{})
	for range 2 {
		if !limiter.startUDP(nil, nil, func(ctx context.Context) {
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
	if limiter.startUDP(nil, nil, func(context.Context) {}) {
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
	limiter := newDNSRelayLimiterWithLimits(parent, 1, 1, 1)
	done := make(chan struct{})
	if !limiter.startUDP(nil, nil, func(ctx context.Context) {
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

	nilParent := newDNSRelayLimiterWithLimits(nil, 1, 1, 1)
	if !nilParent.startUDP(nil, nil, func(context.Context) {}) {
		t.Fatal("nil parent should fall back to a live background context")
	}
	nilParent.close()
}

func TestDNSRelayLimiterStartCloseRace(t *testing.T) {
	for range 100 {
		limiter := newDNSRelayLimiterWithLimits(context.Background(), 8, 8, 8)
		start := make(chan struct{})
		var callers sync.WaitGroup
		for range 16 {
			callers.Add(1)
			go func() {
				defer callers.Done()
				<-start
				limiter.startUDP(nil, nil, func(ctx context.Context) { <-ctx.Done() })
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

	limiter := newDNSRelayLimiterWithLimits(context.Background(), 1, 1, 1)
	release := make(chan struct{})
	if !limiter.startUDP(nil, nil, func(context.Context) { <-release }) {
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
	limiter := newDNSRelayLimiterWithLimits(nil, 1, 1, 1)
	state := &udpClientState{}
	finish := make(chan struct{})
	if !limiter.startUDP(state.activity.retain, state.activity.release, func(context.Context) { <-finish }) {
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

// Refusing beats dropping when the budget is gone: a dropped datagram is
// indistinguishable from a dead server, so the stub waits out its whole
// per-nameserver timeout and retransmits into the burst that caused the
// exhaustion, where REFUSED makes it fail over at once.
func TestRefusedDNSReplyAnswersTheQuestionItRefuses(t *testing.T) {
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	query.RecursionDesired = true
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	refused, ok := refusedDNSReply(packed)
	if !ok {
		t.Fatal("a well-formed query was not refused")
	}
	var reply D.Msg
	if err = reply.Unpack(refused); err != nil {
		t.Fatalf("refusal does not unpack: %v", err)
	}
	if !reply.Response {
		t.Fatal("refusal is not marked as a response, so the stub ignores it")
	}
	if reply.Id != query.Id {
		t.Fatalf("refusal id = %d, want %d -- a mismatched id is discarded", reply.Id, query.Id)
	}
	if reply.Rcode != D.RcodeRefused {
		t.Fatalf("refusal rcode = %d, want REFUSED", reply.Rcode)
	}
	if len(reply.Question) != 1 || reply.Question[0].Name != "example.com." {
		t.Fatalf("refusal did not echo the question: %+v", reply.Question)
	}
}

func TestRefusedDNSReplyDeclinesWhatItCannotAnswer(t *testing.T) {
	if _, ok := refusedDNSReply(nil); ok {
		t.Fatal("an empty datagram was answered")
	}
	if _, ok := refusedDNSReply([]byte{0x00, 0x01, 0x02}); ok {
		t.Fatal("a truncated datagram was answered")
	}
	response := new(D.Msg)
	response.SetQuestion("example.com.", D.TypeA)
	response.Response = true
	packed, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := refusedDNSReply(packed); ok {
		t.Fatal("a response was answered, which would bounce between two resolvers")
	}
}
