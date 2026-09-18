//go:build !linux && !android && !windows

package smart

// systemMemoryUsage has no implementation on this platform, so callers fall
// back to the neutral usage figure.
func systemMemoryUsage() (float64, bool) {
	return 0, false
}
