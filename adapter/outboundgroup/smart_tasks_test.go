package outboundgroup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/smart"
)

func TestSmartTaskReadinessStopsPollingWhilePaused(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var checks atomic.Int32
	var ready atomic.Bool
	done := make(chan struct{})
	ran := make(chan struct{}, 1)
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{runOnce: true, run: func() { ran <- struct{}{} }}}, func() bool { checks.Add(1); return ready.Load() }, time.Millisecond, func() time.Duration { return 0 })
	}()
	time.Sleep(30 * time.Millisecond)
	if n := checks.Load(); n > 1 {
		t.Fatalf("readiness polled %d times while paused", n)
	}
	ready.Store(true)
	power.SetDevicePaused(false)
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("readiness did not resume")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not exit")
	}
}

func TestSmartTaskSchedulePausesBackgroundWork(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := make(chan struct{}, 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			initialDelay: time.Millisecond, interval: 5 * time.Millisecond,
			run: func() { runs <- struct{}{} },
		}}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
	}()
	select {
	case <-runs:
		t.Fatal("maintenance ran while device paused")
	case <-time.After(20 * time.Millisecond):
	}
	power.SetDevicePaused(false)
	select {
	case <-runs:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not resume")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}
}

func TestSmartTaskSchedulePreventsOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32

	task := smartScheduledTask{
		initialDelay: 0,
		interval:     5 * time.Millisecond,
		name:         "slow",
		run: func() {
			calls.Add(1)
			current := active.Add(1)
			for {
				old := maxActive.Load()
				if current <= old || maxActive.CompareAndSwap(old, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
		},
	}

	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, []smartScheduledTask{task}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled task did not start")
	}
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("slow task overlapped: calls=%d", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent executions=%d, want 1", got)
	}

	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}

func TestSmartTaskScheduleCancelsWhileWaitingForTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			initialDelay: time.Hour,
			interval:     time.Hour,
			name:         "never",
			run:          func() { t.Error("task ran while tunnel was stopped") },
		}}, func() bool { return false }, 5*time.Millisecond, func() time.Duration { return 0 })
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler ignored cancellation while waiting for tunnel")
	}
}

func TestSmartTaskScheduleBatchesSharedDeadlines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan string, 2)
	tasks := []smartScheduledTask{
		{initialDelay: 0, interval: time.Hour, name: "first", run: func() { ran <- "first" }, runOnce: true},
		{initialDelay: 0, interval: time.Hour, name: "second", run: func() { ran <- "second" }, runOnce: true},
	}
	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, tasks, func() bool { return true }, time.Millisecond, func() time.Duration { return 5 * time.Millisecond })
		close(done)
	}()

	for i := 0; i < len(tasks); i++ {
		select {
		case <-ran:
		case <-time.After(time.Second):
			t.Fatal("tasks with a shared deadline were not dispatched together")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run-once schedule did not finish")
	}
}

func TestSmartGlobalRegistrySurvivesGroupReplacement(t *testing.T) {
	registry := &smartGlobalTaskRegistry{}
	store := smart.NewStore(nil)
	oldGroup := &Smart{store: store, configName: "old"}
	newGroup := &Smart{store: store, configName: "new"}

	run := registry.acquire(oldGroup)
	if got := registry.acquire(newGroup); got != run {
		t.Fatal("replacement group started a second global task run")
	}
	registry.release(oldGroup, run)

	select {
	case <-run.ctx.Done():
		t.Fatal("closing the old group canceled global tasks owned by the replacement")
	default:
	}
	groups := run.snapshotGroupsByConfig()
	if len(groups) != 1 || groups[0] != newGroup {
		t.Fatalf("global task retained a closed first group: %#v", groups)
	}

	registry.release(newGroup, run)
	select {
	case <-run.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("last group did not stop global tasks")
	}
}

func TestSmartBackgroundGateRejectsWorkAfterClose(t *testing.T) {
	var s Smart
	if !s.beginBackgroundWork() {
		t.Fatal("open group rejected statistics")
	}

	waiting := make(chan struct{})
	go func() {
		s.waitBackgroundWork()
		close(waiting)
	}()
	select {
	case <-waiting:
		t.Fatal("wait returned before accepted statistics completed")
	case <-time.After(10 * time.Millisecond):
	}

	s.disableBackgroundWork()
	if s.beginBackgroundWork() {
		t.Fatal("closing group accepted new statistics")
	}
	s.finishBackgroundWork()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("wait did not observe accepted statistics completion")
	}
}

func TestSmartCloseIsConcurrentAndIdempotent(t *testing.T) {
	store := smart.NewStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Smart{store: store, ctx: ctx, cancel: cancel}
	s.global = globalSmartTasks.acquire(s)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("close did not cancel group context")
	}
	if s.global != nil {
		t.Fatal("close retained global task ownership")
	}
}
