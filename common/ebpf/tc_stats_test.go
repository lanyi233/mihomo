//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// newTestTCStatsBackend prepares the smallest real TC backend that still loads
// tc.bpf.c, which is what actually creates tc_stats.
func newTestTCStatsBackend(t *testing.T) *TCBackend {
	t.Helper()
	policy := newTestFakeIPPolicy(t, "", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 12345,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// TestTCStatsReadCleanlyWithNoDegradation is the counterpart of
// TestSharedNetworkStatsReadCleanlyWithNoFailures: every tc_stats counter must
// read back as zero, with no error, on a backend that has never seen a packet.
// Forcing the kernel paths themselves (a missing listener socket, a refused
// sk_assign) needs traffic through an attached qdisc, which the privileged
// program-run suite covers; what this proves is that the map exists, is the
// shape the Go side expects, and starts empty.
func TestTCStatsReadCleanlyWithNoDegradation(t *testing.T) {
	backend := newTestTCStatsBackend(t)
	stats, err := backend.TCStats()
	if err != nil {
		t.Fatalf("TCStats: %v", err)
	}
	if stats != (TCStats{}) {
		t.Fatalf("TCStats = %+v, want all zero on a backend that has processed nothing", stats)
	}
}

// TestTCStatsIndicesAreDistinct proves each field is read from its own key
// rather than several names sharing one counter -- the failure mode that would
// make the degradation report name the wrong condition. Seeding the kernel map
// directly is the only way to tell them apart without traffic.
func TestTCStatsIndicesAreDistinct(t *testing.T) {
	backend := newTestTCStatsBackend(t)
	statsMap := backend.runtime.maps["tc_stats"]
	if statsMap == nil {
		t.Fatal("tc_stats map is unavailable")
	}
	for index, expected := range map[uint32]func(TCStats) uint64{
		tcStatListenerSocketMissing:  func(s TCStats) uint64 { return s.ListenerSocketMissing },
		tcStatSKAssignFailed:         func(s TCStats) uint64 { return s.SKAssignFailed },
		tcStatAssignmentUpdateFailed: func(s TCStats) uint64 { return s.AssignmentUpdateFailed },
		tcStatDeliveryRewriteFailed:  func(s TCStats) uint64 { return s.DeliveryRewriteFailed },
	} {
		perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
		perCPU[0] = uint64(index) + 1
		if err := statsMap.Put(index, perCPU); err != nil {
			t.Fatalf("seed tc_stats[%d]: %v", index, err)
		}
		stats, err := backend.TCStats()
		if err != nil {
			t.Fatalf("TCStats: %v", err)
		}
		if got := expected(stats); got != uint64(index)+1 {
			t.Fatalf("tc_stats[%d] read back as %d, want %d", index, got, index+1)
		}
		clear(perCPU)
		if err := statsMap.Put(index, perCPU); err != nil {
			t.Fatalf("reset tc_stats[%d]: %v", index, err)
		}
	}
}
