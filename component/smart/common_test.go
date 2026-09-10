package smart

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadProcMemoryUsageReadsOnce(t *testing.T) {
	reads := 0
	usage, ok := readProcMemoryUsage(func(path string) ([]byte, error) {
		reads++
		require.Equal(t, "/proc/meminfo", path)
		return []byte("MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\n"), nil
	})

	require.True(t, ok)
	require.Equal(t, 1, reads)
	require.InDelta(t, 0.75, usage, 0.0001)
}

func TestReadProcMemoryUsageRejectsIncompleteInput(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		err  error
	}{
		{name: "read error", err: errors.New("read failed")},
		{name: "missing available", data: "MemTotal: 1000 kB\n"},
		{name: "invalid total", data: "MemTotal: invalid kB\nMemAvailable: 100 kB\n"},
		{name: "zero total", data: "MemTotal: 0 kB\nMemAvailable: 0 kB\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ok := readProcMemoryUsage(func(string) ([]byte, error) {
				return []byte(test.data), test.err
			})
			require.False(t, ok)
		})
	}
}

func TestReadProcMemoryUsageClampsInvalidAvailability(t *testing.T) {
	usage, ok := readProcMemoryUsage(func(string) ([]byte, error) {
		return []byte("MemTotal: 1000 kB\nMemAvailable: 1200 kB\n"), nil
	})

	require.True(t, ok)
	require.Zero(t, usage)
}
