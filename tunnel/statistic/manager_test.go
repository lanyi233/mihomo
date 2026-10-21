package statistic

import (
	"context"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestTrafficSamplingSleepsWhenIdleAndRestarts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &Manager{trafficWake: make(chan struct{}, 1)}
		go m.handle(ctx, time.Second)
		synctest.Wait()
		time.Sleep(time.Hour)
		if m.trafficActive.Load() {
			t.Fatal("idle manager activated sampling")
		}
		for round := 0; round < 3; round++ {
			m.PushUploaded(123)
			m.PushDownloaded(456)
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			if up, down := m.Now(); up != 123 || down != 456 {
				t.Fatalf("sample = %d/%d, want 123/456", up, down)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if up, down := m.Now(); up != 0 || down != 0 || m.trafficActive.Load() {
				t.Fatalf("idle sample = %d/%d, active = %v", up, down, m.trafficActive.Load())
			}
			time.Sleep(time.Hour)
		}
		if up, down := m.Total(); up != 369 || down != 1368 {
			t.Fatalf("totals = %d/%d", up, down)
		}
		m.PushUploaded(0)
		m.PushDownloaded(0)
		if m.trafficActive.Load() {
			t.Fatal("zero-byte traffic activated sampling")
		}
	})
}

func TestTrafficSamplingConcurrentWriters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &Manager{trafficWake: make(chan struct{}, 1)}
		go m.handle(ctx, time.Second)
		for round := 0; round < 10; round++ {
			var writers sync.WaitGroup
			for n := 0; n < 8; n++ {
				writers.Go(func() {
					for n := 0; n < 100; n++ {
						m.PushUploaded(1)
						m.PushDownloaded(2)
					}
				})
			}
			writers.Wait()
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			if up, down := m.Now(); up != 800 || down != 1600 {
				t.Fatalf("sample = %d/%d, want 800/1600", up, down)
			}
			time.Sleep(time.Second)
			synctest.Wait()
		}
	})
}

func TestManagerMemoryCachesSamplesAndFailures(t *testing.T) {
	m := &Manager{pid: -1, memoryUpdated: time.Now()}
	m.memory.Store(1234)
	updated := m.memoryUpdated
	if got := m.Memory(); got != 1234 {
		t.Fatalf("cached memory = %d, want 1234", got)
	}
	if m.memoryUpdated != updated {
		t.Fatal("fresh sample unexpectedly queried the process")
	}
	// An expired sample must be retried, retaining the last good measurement
	// if the process query fails. Cache the failure to avoid retry storms.
	m.memoryUpdated = time.Now().Add(-2 * time.Second)
	if got := m.Memory(); got != 1234 {
		t.Fatalf("memory after failed refresh = %d, want 1234", got)
	}
	if time.Since(m.memoryUpdated) >= time.Second {
		t.Fatal("expired sample was not refreshed")
	}
	updated = m.memoryUpdated
	m.Memory()
	if m.memoryUpdated != updated {
		t.Fatal("failed process query was not rate limited")
	}
}

func TestManagerMemoryConcurrentSnapshots(t *testing.T) {
	m := &Manager{pid: int32(os.Getpid())}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.Memory()
				m.Snapshot()
			}
		}()
	}
	wg.Wait()
}

func BenchmarkManagerMemory(b *testing.B) {
	m := &Manager{pid: int32(os.Getpid())}
	m.Memory()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Memory()
	}
}
