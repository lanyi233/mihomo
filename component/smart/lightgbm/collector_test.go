package lightgbm

import (
	"path/filepath"
	"testing"
)

func TestDataCollectorCloseAllowsReopen(t *testing.T) {
	collector := &DataCollector{
		dataPath:           filepath.Join(t.TempDir(), "samples.csv"),
		smartCollectorSize: defaultSmartCollectorSize,
	}
	if err := collector.initializeWriter(); err != nil {
		t.Fatalf("initialize collector: %v", err)
	}
	if err := collector.Close(); err != nil {
		t.Fatalf("close collector: %v", err)
	}
	if collector.configured || collector.file != nil || collector.writer != nil {
		t.Fatal("close retained state that points at the closed file")
	}
	if err := collector.initializeWriter(); err != nil {
		t.Fatalf("reopen collector: %v", err)
	}
	if err := collector.Close(); err != nil {
		t.Fatalf("close reopened collector: %v", err)
	}
}

func TestInitCollectorKeepsExistingHandlesValid(t *testing.T) {
	collectMutex.Lock()
	previous := smartCollector
	smartCollector = nil
	collectMutex.Unlock()
	t.Cleanup(func() {
		collectMutex.Lock()
		smartCollector = previous
		collectMutex.Unlock()
	})

	InitCollector(1)
	first := GetCollector()
	InitCollector(2)
	second := GetCollector()
	if first != second {
		t.Fatal("collector reconfiguration replaced the shared object")
	}
	if got, want := second.smartCollectorSize, int64(2*1024*1024); got != want {
		t.Fatalf("collector size=%d, want %d", got, want)
	}
}
