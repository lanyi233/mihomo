package statistic

import (
	"os"
	"sync"
	"testing"
	"time"
)

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
