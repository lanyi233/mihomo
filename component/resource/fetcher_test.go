package resource

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/power"
	P "github.com/metacubex/mihomo/constant/provider"
)

type fetcherTestVehicle struct {
	P.Vehicle
	path  string
	reads chan time.Time
	err   error
}

func (v *fetcherTestVehicle) Type() P.VehicleType { return P.HTTP }
func (v *fetcherTestVehicle) Path() string        { return v.path }
func (v *fetcherTestVehicle) Write([]byte) error  { return nil }
func (v *fetcherTestVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	v.reads <- time.Now()
	buf := []byte("test resource")
	return buf, utils.MakeHash(buf), v.err
}

func newTestFetcher(t *testing.T, interval time.Duration) (*Fetcher[string], *fetcherTestVehicle) {
	t.Helper()
	v := &fetcherTestVehicle{path: filepath.Join(t.TempDir(), "resource"), reads: make(chan time.Time, 20)}
	f := NewFetcher("test", interval, v, nil, func(buf []byte) (string, error) { return string(buf), nil }, nil)
	t.Cleanup(func() { _ = f.Close() })
	return f, v
}

func runTestPullLoop(t *testing.T, f *Fetcher[string], force bool) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.pullLoop(force)
	}()
	t.Cleanup(func() {
		_ = f.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("pull loop did not stop")
		}
	})
}

func waitFetcherRead(t *testing.T, v *fetcherTestVehicle) time.Time {
	t.Helper()
	select {
	case at := <-v.reads:
		return at
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resource fetch")
		return time.Time{}
	}
}

func TestForceRefreshWaitsFullIntervalBeforeNextRead(t *testing.T) {
	const interval = 100 * time.Millisecond
	f, v := newTestFetcher(t, interval)
	f.setUpdatedAt(time.Now().Add(-time.Hour))
	runTestPullLoop(t, f, true)
	first := waitFetcherRead(t, v)
	second := waitFetcherRead(t, v)
	if elapsed := second.Sub(first); elapsed < interval {
		t.Fatalf("force refresh immediately repeated after %s; want at least %s", elapsed, interval)
	}
}

func TestFailedInitialFetchHonorsBackoff(t *testing.T) {
	const interval = 150 * time.Millisecond
	f, v := newTestFetcher(t, interval)
	v.err = errors.New("offline")
	if _, _, err := f.Update(); err == nil {
		t.Fatal("initial fetch unexpectedly succeeded")
	}
	first := waitFetcherRead(t, v)
	runTestPullLoop(t, f, false)
	second := waitFetcherRead(t, v)
	if elapsed := second.Sub(first); elapsed < interval {
		t.Fatalf("initial failure retried after %s; want backoff of at least %s", elapsed, interval)
	}
}

func TestAutomaticFetchPausesButManualUpdateStillWorks(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	f, v := newTestFetcher(t, 100*time.Millisecond)
	runTestPullLoop(t, f, true)
	select {
	case <-v.reads:
		t.Fatal("automatic resource fetch ran while paused")
	case <-time.After(150 * time.Millisecond):
	}
	if _, _, err := f.Update(); err != nil {
		t.Fatal(err)
	}
	waitFetcherRead(t, v)
	select {
	case <-v.reads:
		t.Fatal("manual update resumed the automatic fetcher")
	case <-time.After(150 * time.Millisecond):
	}
	power.SetDevicePaused(false)
	waitFetcherRead(t, v)
}

func TestRunningFetchLoopPausesAndResumes(t *testing.T) {
	f, v := newTestFetcher(t, 100*time.Millisecond)
	runTestPullLoop(t, f, true)
	waitFetcherRead(t, v)
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	select {
	case <-v.reads:
		t.Fatal("periodic resource fetch ran while paused")
	case <-time.After(200 * time.Millisecond):
	}
	power.SetDevicePaused(false)
	waitFetcherRead(t, v)
}
