package netchange

import (
	"slices"
	"sync"
	"testing"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
)

const testTimeout = 5 * time.Second

// recorder collects the fan-out stages in the order they ran, which is what
// distinguishes a superseded run (stops after its stage) from a complete one.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) record(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

// stubProvider embeds the interface so only the method the fan-out calls needs
// an implementation; anything else would panic and fail the test loudly.
type stubProvider struct {
	P.ProxyProvider
	recorder *recorder
}

func (p *stubProvider) HealthCheck() {
	p.recorder.record("check")
}

func newTestNotifier(r *recorder, flushCache func()) *notifier {
	return &notifier{work: fanOut{
		flushCache: func() {
			r.record("flush")
			if flushCache != nil {
				flushCache()
			}
		},
		resetConnection: func() { r.record("reset") },
		providers: func() map[string]P.ProxyProvider {
			return map[string]P.ProxyProvider{"test": &stubProvider{recorder: r}}
		},
	}}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("fan-out did not finish")
	}
}

func TestNotifyRunsEveryStage(t *testing.T) {
	r := &recorder{}
	waitDone(t, newTestNotifier(r, nil).notify())

	if events := r.snapshot(); !slices.Equal(events, []string{"flush", "reset", "check"}) {
		t.Fatalf("unexpected fan-out: %v", events)
	}
}

func TestNotifySupersedesInFlightRun(t *testing.T) {
	r := &recorder{}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	n := newTestNotifier(r, func() {
		entered <- struct{}{}
		<-release
	})

	first := n.notify()
	select {
	case <-entered:
	case <-time.After(testTimeout):
		t.Fatal("first fan-out did not start")
	}

	// Every one of these lands while the first run holds runAccess, so they all
	// queue behind it and only the last one must survive.
	var superseding []<-chan struct{}
	for range 3 {
		superseding = append(superseding, n.notify())
	}

	close(release)
	waitDone(t, first)
	for _, done := range superseding {
		waitDone(t, done)
	}

	// Two flushes: the superseded first run and the surviving last one. The two
	// in between never get past their cancelled context.
	if events := r.snapshot(); !slices.Equal(events, []string{"flush", "flush", "reset", "check"}) {
		t.Fatalf("unexpected fan-out: %v", events)
	}
}

func TestSupersededRunStopsBeforeReset(t *testing.T) {
	r := &recorder{}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	n := newTestNotifier(r, func() {
		entered <- struct{}{}
		<-release
	})

	first := n.notify()
	select {
	case <-entered:
	case <-time.After(testTimeout):
		t.Fatal("first fan-out did not start")
	}
	second := n.notify()

	close(release)
	waitDone(t, first)
	waitDone(t, second)

	// The first run reached flushCache but must not have reset the resolver
	// afterwards, otherwise the stages would interleave as flush/reset/flush.
	if events := r.snapshot(); !slices.Equal(events, []string{"flush", "flush", "reset", "check"}) {
		t.Fatalf("unexpected fan-out: %v", events)
	}
}
