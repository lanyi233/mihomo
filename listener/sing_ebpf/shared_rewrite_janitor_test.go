//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

type testFlowJanitorBackend struct {
	wake            chan struct{}
	sweeps          atomic.Int64
	maxIdle         atomic.Int64
	partialFirst    bool
	sweepErr        error
	releaseDeadline time.Time
	flushes         atomic.Int64
}

func (b *testFlowJanitorBackend) NextTCPFlowReleaseDelay(now time.Time) (time.Duration, bool) {
	return max(b.releaseDeadline.Sub(now), 0), !b.releaseDeadline.IsZero()
}

func (b *testFlowJanitorBackend) FlushReleasedTCPFlows(time.Time, uint32) (uint32, error) {
	b.flushes.Add(1)
	b.releaseDeadline = time.Time{}
	return 1, nil
}

func (b *testFlowJanitorBackend) TCPFlowWake() <-chan struct{} { return b.wake }
func (b *testFlowJanitorBackend) KnownFlowUsage() ECommon.MapUsage {
	return ECommon.MapUsage{Entries: 80, Capacity: 100}
}
func (b *testFlowJanitorBackend) TokenReservationFailures() (uint64, error) { return 0, nil }
func (b *testFlowJanitorBackend) SweepOrphanedFlows(maxIdle time.Duration, _ uint32) (ECommon.SharedNetworkFlowSweepResult, error) {
	b.maxIdle.Store(int64(maxIdle))
	count := b.sweeps.Add(1)
	return ECommon.SharedNetworkFlowSweepResult{
		Usage: b.KnownFlowUsage(), Complete: !b.partialFirst || count > 1,
	}, b.sweepErr
}

func TestSharedFlowJanitorBoundsScansDuringChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := &testFlowJanitorBackend{
			wake: make(chan struct{}, 1), partialFirst: true,
			releaseDeadline: time.Now().Add(2 * time.Second),
		}
		go runSharedFlowJanitor(ctx, b, func() bool { return true }, func(...any) {})
		wakeRepeatedly := func() {
			for n := 0; n < 100; n++ {
				b.wake <- struct{}{}
				synctest.Wait()
			}
		}
		wakeRepeatedly()
		if b.sweeps.Load() != 1 {
			t.Fatalf("flow churn caused %d immediate scans, want 1", b.sweeps.Load())
		}
		if time.Duration(b.maxIdle.Load()) != sharedFlowPressureMaxIdle {
			t.Fatalf("initial pressure scan used idle timeout %s", time.Duration(b.maxIdle.Load()))
		}
		time.Sleep(sharedFlowScanContinueInterval)
		synctest.Wait()
		if b.sweeps.Load() != 2 {
			t.Fatalf("partial scan was not continued: %d scans", b.sweeps.Load())
		}
		wakeRepeatedly()
		time.Sleep(time.Second)
		synctest.Wait()
		if b.flushes.Load() != 1 || b.sweeps.Load() != 2 {
			t.Fatalf("release flushes=%d, scans=%d", b.flushes.Load(), b.sweeps.Load())
		}
		time.Sleep(sharedFlowPressureSweepInterval - time.Second)
		synctest.Wait()
		if b.sweeps.Load() != 3 {
			t.Fatalf("pressure check was postponed by churn: %d scans", b.sweeps.Load())
		}
	})
}

func TestSharedFlowJanitorBacksOffScanErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := &testFlowJanitorBackend{wake: make(chan struct{}, 1), sweepErr: errors.New("map unavailable")}
		go runSharedFlowJanitor(ctx, b, func() bool { return true }, func(...any) {})
		for n := 0; n < 100; n++ {
			b.wake <- struct{}{}
			synctest.Wait()
		}
		if b.sweeps.Load() != 1 {
			t.Fatalf("failed scan retried %d times without backoff", b.sweeps.Load())
		}
		time.Sleep(sharedFlowPressureSweepInterval)
		synctest.Wait()
		if b.sweeps.Load() != 2 {
			t.Fatalf("failed scan was not retried: %d scans", b.sweeps.Load())
		}
	})
}
