package smart

import (
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// systemMemoryUsage asks the kernel directly through GlobalMemoryStatusEx.
// The previous implementation shelled out to wmic twice per call, which costs
// tens of milliseconds and, since wmic was removed in Windows 11 24H2 and
// Server 2025, silently reported the neutral fallback forever.
func systemMemoryUsage() (float64, bool) {
	status := memoryStatusEx{}
	status.Length = uint32(unsafe.Sizeof(status))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 || status.TotalPhys == 0 {
		return 0, false
	}

	available := status.AvailPhys
	if available > status.TotalPhys {
		available = status.TotalPhys
	}
	used := float64(status.TotalPhys - available)
	return math.Max(0, math.Min(used/float64(status.TotalPhys), 1.0)), true
}
