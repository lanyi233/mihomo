package lightgbm

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectorBacksUpLegacySchemaBeforeAppending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "samples.csv")
	legacy := "success,cumul_loss_rate,weight\n10,0.1,0.7\n"
	require.NoError(t, os.WriteFile(path, []byte(legacy), 0o600))
	collector := &DataCollector{dataPath: path, smartCollectorSize: defaultSmartCollectorSize}
	t.Cleanup(func() { collector.Close() })
	require.NoError(t, collector.initializeWriter())
	require.NoError(t, collector.Close())
	backups, err := filepath.Glob(path + ".bak.*")
	require.NoError(t, err)
	require.Len(t, backups, 1)
	saved, err := os.ReadFile(backups[0])
	require.NoError(t, err)
	require.Equal(t, legacy, string(saved), "schema migration must preserve historical samples")
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Len(t, rows[0], expectedColumns)
	require.Equal(t, "exit_region", rows[0][30])
	require.Equal(t, "exit_asn_hash", rows[0][31])
}

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

// Reaching the size limit stops collection until the file is deleted, but a
// reload that raises the limit has to resume it.
func TestReconfigureRaisedLimitResumesCollection(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "samples.csv")
	collector := &DataCollector{
		dataPath:           dataPath,
		smartCollectorSize: defaultSmartCollectorSize,
		sizeLimited:        true,
	}
	t.Cleanup(func() { collector.Close() })

	if err := collector.reconfigure(dataPath, 2*defaultSmartCollectorSize); err != nil {
		t.Fatalf("reconfigure collector: %v", err)
	}
	if collector.sizeLimited {
		t.Fatal("a raised limit left collection stopped")
	}
}
