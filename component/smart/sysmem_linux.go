//go:build linux || android

package smart

import "os"

// systemMemoryUsage reads MemTotal/MemAvailable straight out of /proc/meminfo.
func systemMemoryUsage() (float64, bool) {
	return readProcMemoryUsage(os.ReadFile)
}
