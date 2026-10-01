package updater

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/power"
)

func TestPeriodicUpdatesPauseResumeAndCancel(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan time.Time, 8)
	done := make(chan struct{})
	const interval = 100 * time.Millisecond
	go func() {
		defer close(done)
		runPeriodicUpdates(ctx, interval, true, func() { calls <- time.Now() })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("updater did not stop")
		}
	})
	select {
	case <-calls:
		t.Fatal("updater ran while paused")
	case <-time.After(30 * time.Millisecond):
	}
	resumed := time.Now()
	power.SetDevicePaused(false)
	var first time.Time
	select {
	case first = <-calls:
		if first.Sub(resumed) < interval/2 {
			t.Fatal("resumed updater skipped its settle window")
		}
	case <-time.After(time.Second):
		t.Fatal("updater did not resume")
	}
	select {
	case second := <-calls:
		if second.Sub(first) < interval {
			t.Fatal("overdue startup update immediately repeated")
		}
	case <-time.After(time.Second):
		t.Fatal("updater stopped after first update")
	}
}
