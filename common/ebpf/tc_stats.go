//go:build with_ebpf && (linux || android)

package ebpf

import E "github.com/metacubex/sing/common/exceptions"

// This file is the Go half of tc.bpf.c's tc_stats map. The kernel half is
// native/abi.h's SB_TC_STAT_* keys, which is where each counter's operational
// meaning is written down; there is no generated binding for either side's
// constants, so the two comments plus the indices below are the whole ABI
// contract between them. Adding a key means adding it in both places --
// abi.h's _Static_assert pins the C side to itself, and TCStats checks this
// count against the map the kernel actually created.
const tcStatCount = 4

const (
	tcStatListenerSocketMissing uint32 = iota
	tcStatSKAssignFailed
	tcStatAssignmentUpdateFailed
	tcStatDeliveryRewriteFailed
)

// TCStats is one reading of every tc_stats counter. The counters are lifetime
// totals since the map was created, which is what makes them useless on their
// own: a caller wanting to know whether a datapath is degrading *now* has to
// difference two readings. They are returned together, under a single lock and
// from a single pass over the map, so a delta computed from two of these
// describes one interval rather than a smear across however long the reads
// took.
type TCStats struct {
	ListenerSocketMissing  uint64
	SKAssignFailed         uint64
	AssignmentUpdateFailed uint64
	DeliveryRewriteFailed  uint64
}

// TCStats reads the whole tc_stats map. Like the shared-network and fakeip
// ICMP counters, each entry is a PERCPU_ARRAY slot summed across CPUs on every
// call; the report that drives this polls on a 30s cadence, which is the rate
// this is sized for.
func (b *TCBackend) TCStats() (TCStats, error) {
	if b == nil {
		return TCStats{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCStats{}, errBackendClosed
	}
	statsMap := b.runtime.maps["tc_stats"]
	if statsMap == nil {
		return TCStats{}, errBackendClosed
	}
	// abi.h's asserts pin the C side to itself; nothing there can see this file.
	// A key added in C without a matching constant here would be written by the
	// program into a slot this map was never sized for, and record_tc_stat's
	// NULL check would swallow it -- a counter that silently never moves. The
	// map's real geometry is the only place the two sides actually meet.
	if entries := statsMap.MaxEntries(); entries != tcStatCount {
		return TCStats{}, E.New("tc_stats map holds ", entries, " counters, expected ", tcStatCount)
	}
	var totals [tcStatCount]uint64
	for offset := range totals {
		index := uint32(offset)
		var perCPU []uint64
		if err := statsMap.Lookup(&index, &perCPU); err != nil {
			return TCStats{}, err
		}
		for _, value := range perCPU {
			totals[offset] += value
		}
	}
	return TCStats{
		ListenerSocketMissing:  totals[tcStatListenerSocketMissing],
		SKAssignFailed:         totals[tcStatSKAssignFailed],
		AssignmentUpdateFailed: totals[tcStatAssignmentUpdateFailed],
		DeliveryRewriteFailed:  totals[tcStatDeliveryRewriteFailed],
	}, nil
}
