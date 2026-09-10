package provider

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	stdatomic "sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/power"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type healthCheckProbe struct {
	C.Proxy
	name  string
	calls chan string
}

func newHealthCheckProbe(name string) *healthCheckProbe {
	return &healthCheckProbe{name: name, calls: make(chan string, 256)}
}

func (p *healthCheckProbe) Name() string { return p.name }

func (p *healthCheckProbe) URLTest(ctx context.Context, url string, _ utils.IntRanges[uint16]) (uint16, error) {
	select {
	case p.calls <- url:
	default:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	return 1, nil
}

func (p *healthCheckProbe) AliveForTestUrl(string) bool       { return true }
func (p *healthCheckProbe) LastDelayForTestUrl(string) uint16 { return 1 }

type blockingHealthCheckProbe struct {
	C.Proxy
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	start    sync.Once
	cancel   sync.Once
}

func newBlockingHealthCheckProbe() *blockingHealthCheckProbe {
	return &blockingHealthCheckProbe{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (p *blockingHealthCheckProbe) Name() string { return "blocking" }

func (p *blockingHealthCheckProbe) URLTest(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
	p.start.Do(func() { close(p.started) })
	<-ctx.Done()
	p.cancel.Do(func() { close(p.canceled) })
	<-p.release
	return 0, ctx.Err()
}

func (p *blockingHealthCheckProbe) AliveForTestUrl(string) bool       { return false }
func (p *blockingHealthCheckProbe) LastDelayForTestUrl(string) uint16 { return 0 }

type slowHealthCheckProbe struct {
	C.Proxy
	started chan struct{}
	release chan struct{}
	start   sync.Once
	calls   stdatomic.Int32
}

func newSlowHealthCheckProbe() *slowHealthCheckProbe {
	return &slowHealthCheckProbe{started: make(chan struct{}), release: make(chan struct{})}
}

func (p *slowHealthCheckProbe) Name() string { return "slow" }

func (p *slowHealthCheckProbe) URLTest(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
	p.calls.Add(1)
	p.start.Do(func() { close(p.started) })
	select {
	case <-p.release:
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (p *slowHealthCheckProbe) AliveForTestUrl(string) bool       { return true }
func (p *slowHealthCheckProbe) LastDelayForTestUrl(string) uint16 { return 1 }

func testHealthCheck(t *testing.T, proxy C.Proxy, interval time.Duration, lazy bool) *HealthCheck {
	t.Helper()
	hc := NewHealthCheck([]C.Proxy{proxy}, "https://example.test", 1000, 1, lazy, nil)
	hc.interval = interval
	hc.singleDo = singledo.NewSingle[struct{}](0)
	hc.coalesceWindow = 0
	go hc.process()
	t.Cleanup(hc.close)
	return hc
}

func waitHealthCheckCall(t *testing.T, calls <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case url := <-calls:
		return url
	case <-time.After(timeout):
		t.Fatal("timed out waiting for health check")
		return ""
	}
}

func TestLazyHealthCheckStopsPeriodicWakeupsAndTouchRestarts(t *testing.T) {
	const interval = 20 * time.Millisecond
	proxy := newHealthCheckProbe("lazy")
	sub := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(sub) })

	hc := testHealthCheck(t, proxy, interval, true)
	waitHealthCheckCall(t, proxy.calls, time.Second) // startup check

	deadline := time.NewTimer(6 * interval)
	defer deadline.Stop()
	skips := 0
collect:
	for {
		select {
		case event := <-sub:
			if strings.Contains(event.Payload, "health check because we are lazy") {
				skips++
			}
		case <-deadline.C:
			break collect
		}
	}
	if skips > 1 {
		t.Fatalf("idle lazy health check woke %d times, want at most one transition to idle", skips)
	}

	hc.touch()
	waitHealthCheckCall(t, proxy.calls, 4*interval)
}

func TestLazyHealthCheckTouchDoesNotAllocate(t *testing.T) {
	hc := NewHealthCheck(nil, "https://example.test", 1000, 1, true, nil)
	if allocations := testing.AllocsPerRun(1000, hc.touch); allocations != 0 {
		t.Fatalf("Touch allocations = %v, want 0", allocations)
	}
}

func TestNonLazyHealthCheckRemainsPeriodic(t *testing.T) {
	const interval = 15 * time.Millisecond
	proxy := newHealthCheckProbe("periodic")
	testHealthCheck(t, proxy, interval, false)

	waitHealthCheckCall(t, proxy.calls, time.Second)
	waitHealthCheckCall(t, proxy.calls, 4*interval)
	waitHealthCheckCall(t, proxy.calls, 4*interval)
}

func TestAutomaticHealthCheckPausesWhileManualCheckStillWorks(t *testing.T) {
	const interval = 20 * time.Millisecond
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)

	proxy := newHealthCheckProbe("paused")
	hc := testHealthCheck(t, proxy, interval, false)

	select {
	case <-proxy.calls:
		t.Fatal("automatic health check ran while background work was paused")
	case <-time.After(3 * interval):
	}

	hc.check()
	waitHealthCheckCall(t, proxy.calls, interval)
	select {
	case <-proxy.calls:
		t.Fatal("automatic health check resumed while still paused")
	case <-time.After(3 * interval):
	}

	power.SetDevicePaused(false)
	waitHealthCheckCall(t, proxy.calls, 5*interval)
}

func TestAutomaticHealthCheckUpdateIsCoalescedWhilePaused(t *testing.T) {
	const interval = 20 * time.Millisecond
	proxy := newHealthCheckProbe("update")
	hc := testHealthCheck(t, proxy, interval, true)
	waitHealthCheckCall(t, proxy.calls, time.Second)
	time.Sleep(2 * interval) // let the lazy timer enter its idle state

	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	for i := 0; i < 8; i++ {
		hc.scheduleCheck()
	}
	select {
	case <-proxy.calls:
		t.Fatal("provider update triggered an automatic check while paused")
	case <-time.After(3 * interval):
	}

	power.SetDevicePaused(false)
	waitHealthCheckCall(t, proxy.calls, 5*interval)
	select {
	case <-proxy.calls:
		t.Fatal("coalesced provider updates scheduled more than one lazy check")
	case <-time.After(3 * interval):
	}
}

func TestResumeAndProviderUpdateCannotLosePeriodicTimer(t *testing.T) {
	const interval = 10 * time.Millisecond
	proxy := newHealthCheckProbe("resume-update")
	hc := testHealthCheck(t, proxy, interval, false)
	waitHealthCheckCall(t, proxy.calls, time.Second)

	for i := 0; i < 5; i++ {
		power.SetDevicePaused(true)
		time.Sleep(3 * interval)
		drainHealthCheckCalls(proxy.calls)

		// Queue an update before publishing resume so both notifications may be
		// ready in either select order inside the scheduler.
		hc.scheduleCheck()
		power.SetDevicePaused(false)
		waitHealthCheckCall(t, proxy.calls, 6*interval)
		waitHealthCheckCall(t, proxy.calls, 6*interval)
	}
}

func TestSlowAutomaticHealthCheckDoesNotAccumulateWaiters(t *testing.T) {
	proxy := newSlowHealthCheckProbe()
	testHealthCheck(t, proxy, time.Millisecond, false)
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("slow health check did not start")
	}

	baseline := runtime.NumGoroutine()
	time.Sleep(80 * time.Millisecond)
	if got := proxy.calls.Load(); got != 1 {
		t.Fatalf("overlapping automatic checks = %d, want 1", got)
	}
	if growth := runtime.NumGoroutine() - baseline; growth > 16 {
		t.Fatalf("slow automatic check accumulated %d waiter goroutines", growth)
	}
}

func TestCompletedSlowCheckRestoresPeriodicTimerAfterDuplicateTrigger(t *testing.T) {
	const interval = 10 * time.Millisecond
	proxy := newSlowHealthCheckProbe()
	hc := testHealthCheck(t, proxy, interval, false)
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("slow startup health check did not start")
	}

	// This represents the already queued setProxies notification whose version
	// was included in the startup check. It must not leave the timer stopped.
	hc.scheduleCheck()
	time.Sleep(3 * interval)
	close(proxy.release)
	deadline := time.Now().Add(8 * interval)
	for proxy.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := proxy.calls.Load(); got < 2 {
		t.Fatalf("periodic timer did not resume after slow check; calls = %d", got)
	}
}

func TestProviderUpdateDuringCheckRunsOneFreshFollowUp(t *testing.T) {
	slow := newSlowHealthCheckProbe()
	replacement := newHealthCheckProbe("replacement")
	hc := NewHealthCheck([]C.Proxy{slow}, "https://example.test", 1000, 1, false, nil)
	hc.interval = time.Hour
	hc.singleDo = singledo.NewSingle[struct{}](0)
	hc.coalesceWindow = 0
	go hc.process()
	t.Cleanup(hc.close)
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("startup health check did not start")
	}

	bp := &baseProvider{healthCheck: hc}
	bp.setProxies([]C.Proxy{replacement})
	close(slow.release)
	waitHealthCheckCall(t, replacement.calls, time.Second)
	if got := slow.calls.Load(); got != 1 {
		t.Fatalf("old proxy was checked %d times, want 1", got)
	}
}

func TestHealthCheckCloseWaitsForAcceptedCheck(t *testing.T) {
	proxy := newBlockingHealthCheckProbe()
	hc := NewHealthCheck([]C.Proxy{proxy}, "https://example.test", 1000, 1, false, nil)
	hc.interval = time.Hour
	hc.singleDo = singledo.NewSingle[struct{}](0)
	go hc.process()

	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("startup health check did not start")
	}

	closed := make(chan struct{})
	go func() {
		hc.close()
		close(closed)
	}()
	select {
	case <-proxy.canceled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel the in-flight health check")
	}
	select {
	case <-closed:
		t.Fatal("close returned before the accepted health check finished")
	default:
	}
	close(proxy.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not wait for the accepted health check")
	}
}

func TestHealthCheckSnapshotsConcurrentConfiguration(t *testing.T) {
	proxy := newHealthCheckProbe("snapshot")
	hc := NewHealthCheck([]C.Proxy{proxy}, "https://example.test", 1000, 0, true, nil)
	hc.singleDo = singledo.NewSingle[struct{}](0)
	t.Cleanup(hc.close)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			hc.setProxies([]C.Proxy{proxy})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			hc.registerHealthCheckTask(fmt.Sprintf("https://extra-%d.test", i), nil, "snapshot", 1)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			hc.check()
		}
	}()
	wg.Wait()
}

func TestHealthCheckPreservesExtraURLFilters(t *testing.T) {
	selected := newHealthCheckProbe("selected")
	other := newHealthCheckProbe("other")
	hc := NewHealthCheck([]C.Proxy{selected, other}, "https://default.test", 1000, 0, true, nil)
	hc.singleDo = singledo.NewSingle[struct{}](0)
	t.Cleanup(hc.close)

	hc.registerHealthCheckTask("https://extra.test", nil, "^selected$", 1)
	hc.check()
	if got := drainHealthCheckCalls(selected.calls); got["https://default.test"] != 1 || got["https://extra.test"] != 1 {
		t.Fatalf("selected proxy calls = %v, want default and extra URL", got)
	}
	if got := drainHealthCheckCalls(other.calls); got["https://default.test"] != 1 || got["https://extra.test"] != 0 {
		t.Fatalf("other proxy calls = %v, want only default URL", got)
	}

	// Registering the same URL merges filters without mutating a snapshot that
	// may still be in use by an accepted health check.
	hc.registerHealthCheckTask("https://extra.test", nil, "^other$", 1)
	hc.check()
	if got := drainHealthCheckCalls(selected.calls); got["https://extra.test"] != 1 {
		t.Fatalf("selected proxy calls after merge = %v", got)
	}
	if got := drainHealthCheckCalls(other.calls); got["https://extra.test"] != 1 {
		t.Fatalf("other proxy calls after merge = %v", got)
	}
}

func TestExtraHealthCheckEnablesAutomaticScheduling(t *testing.T) {
	proxy := newHealthCheckProbe("extra-only")
	hc := NewHealthCheck([]C.Proxy{proxy}, "", 1000, 0, true, nil)
	hc.registerHealthCheckTask("https://extra.test", nil, "", 1)
	hc.interval = 15 * time.Millisecond
	hc.singleDo = singledo.NewSingle[struct{}](0)
	go hc.process()
	t.Cleanup(hc.close)

	if got := waitHealthCheckCall(t, proxy.calls, time.Second); got != "https://extra.test" {
		t.Fatalf("startup URL = %q, want registered extra URL", got)
	}
}

func TestProviderUpdateBeforeInitialKeepsPendingAutomaticCheck(t *testing.T) {
	proxy := newHealthCheckProbe("pending")
	hc := NewHealthCheck(nil, "https://example.test", 1000, 1, true, nil)
	bp := &baseProvider{healthCheck: hc}
	bp.setProxies([]C.Proxy{proxy})
	if len(hc.trigger) != 1 {
		t.Fatal("provider update notification was lost before health check process started")
	}
	hc.interval = 15 * time.Millisecond
	hc.singleDo = singledo.NewSingle[struct{}](0)
	go hc.process()
	t.Cleanup(hc.close)
	waitHealthCheckCall(t, proxy.calls, time.Second)
}

func TestManualOnlyProviderUpdateDoesNotStartAutomaticCheck(t *testing.T) {
	proxy := newHealthCheckProbe("manual")
	hc := NewHealthCheck(nil, "https://example.test", 1000, 0, true, nil)
	bp := &baseProvider{healthCheck: hc}
	bp.setProxies([]C.Proxy{proxy})
	t.Cleanup(hc.close)

	select {
	case <-proxy.calls:
		t.Fatal("interval=0 provider update started an automatic check")
	case <-time.After(30 * time.Millisecond):
	}
	hc.check()
	waitHealthCheckCall(t, proxy.calls, time.Second)
}

func drainHealthCheckCalls(calls <-chan string) map[string]int {
	result := make(map[string]int)
	for {
		select {
		case url := <-calls:
			result[url]++
		default:
			return result
		}
	}
}

func TestHealthCheckCloseTouchAndProcessAreConcurrentSafe(t *testing.T) {
	proxy := newHealthCheckProbe("close")
	hc := NewHealthCheck([]C.Proxy{proxy}, "https://example.test", 1000, 1, true, nil)
	hc.interval = 10 * time.Millisecond
	hc.singleDo = singledo.NewSingle[struct{}](0)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); hc.process() }()
		go func() { defer wg.Done(); hc.touch() }()
		go func() { defer wg.Done(); hc.close() }()
	}
	wg.Wait()

	done := make(chan struct{})
	go func() {
		hc.check()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("check started after close did not return")
	}
}
