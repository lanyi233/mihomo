//go:build with_ebpf && (linux || android)

package ebpf

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCgroupUDPMapConfigurationKeepsFlowCacheWithoutSocketRelease(t *testing.T) {
	capacity := DefaultCgroupMapCapacity()
	for _, socketReleaseSupported := range []bool{false, true} {
		layout := cgroupUDPMapConfiguration(true, socketReleaseSupported, capacity)
		if layout.flowCapacity != capacity.UDPFlow {
			t.Fatalf("socket_release=%v: flow capacity=%d, want %d", socketReleaseSupported, layout.flowCapacity, capacity.UDPFlow)
		}
	}
	if layout := cgroupUDPMapConfiguration(false, false, capacity); layout.flowCapacity != 1 {
		t.Fatalf("UDP-disabled layout changed flow capacity: got %d, want 1", layout.flowCapacity)
	}
}

// Socket-release only speeds up UDP cleanup, so a kernel or policy that refuses
// the probe with a permission error must select the LRU fallback instead of
// failing the cgroup inbound. The classifier the required hooks use must keep
// treating permission errors as errors.
func TestSocketReleaseProbePermissionFallsBack(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES} {
		if !socketReleaseProbeUnavailable(fmt.Errorf("attach socket release: %w", errno)) {
			t.Fatalf("probe error %v did not select the LRU fallback", errno)
		}
		if socketReleaseUnavailable(errno) {
			t.Fatalf("permission error %v was treated as the hook being absent", errno)
		}
	}
	if socketReleaseProbeUnavailable(unix.EBADF) {
		t.Fatal("an unrelated probe error selected the LRU fallback")
	}
}
