//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"golang.org/x/sys/unix"
	"time"
)

type TCAssignmentSweepResult struct {
	ReturnUsage      MapUsage
	ReturnUsageKnown bool
	ReturnScanned    uint32
	ReturnRemoved    uint32
	Usage            MapUsage
	Scanned          uint32
	Retired          uint32
	Removed          uint32
	Complete         bool
	// UsageKnown is true only after a complete traversal. A bounded partial
	// traversal must not be interpreted as an empty map by callers.
	UsageKnown bool
	Pressure   bool
	// Failure classifies a failed maintenance pass without requiring callers
	// to parse platform-specific errno text. An empty value means the pass
	// completed (or is a normal partial traversal).
	Failure    string
	FailureMap string
}

const (
	TCAssignmentSweepFailureClosed = "closed"
	TCAssignmentSweepFailureScan   = "scan"
	TCAssignmentSweepFailureLookup = "lookup"
	TCAssignmentSweepFailureDelete = "delete"
)

// SweepAssignments retires observed generations, never compare/deleting a
// concurrently replaced assignment. The bounded LRU reuses their storage.
func (b *TCBackend) SweepAssignments(maxIdle time.Duration, budget uint32) (result TCAssignmentSweepResult, sweepErr error) {
	if b == nil {
		return result, errBackendClosed
	}
	if maxIdle <= 0 || budget == 0 {
		return result, unix.EINVAL
	}
	maxIdle = max(maxIdle, 2*time.Second)
	b.assignmentSweepAccess.Lock()
	defer b.assignmentSweepAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return result, errBackendClosed
	}
	now := monotonicNowNS()
	cutoff := now - min(now, uint64(maxIdle))
	result.FailureMap = "sb_tc_assign"
	var retireErr error
	scan, err := b.assignmentSweepScratch.scan(b.runtime.maps["tc_assignment"], b.assignmentCapacity, budget, func(key tcAssignKey, value TCAssignment) {
		if retireErr != nil || value.Generation == 0 || value.LastSeenNS == 0 || value.LastSeenNS > cutoff {
			return
		}
		identity := tcRetiredKey{Flow: key, Generation: value.Generation}
		var retired uint8
		retiredMap := b.runtime.maps["tc_retired_assignment"]
		if err := retiredMap.Lookup(&identity, &retired); err == nil {
			return
		} else if !errors.Is(err, unix.ENOENT) {
			retireErr = err
			return
		}
		retired = 1
		retireErr = retiredMap.Update(&identity, &retired, 0)
		if retireErr == nil {
			result.Retired++
		}
	})
	if err == nil {
		err = retireErr
	}
	result.Scanned, result.Complete = scan.Scanned, scan.Complete
	result.Usage = MapUsage{Capacity: b.assignmentCapacity, Entries: scan.Entries}
	result.UsageKnown = scan.Complete && err == nil
	b.maintenance.record("sb_tc_assign", b.assignmentCapacity, scan, 0, scan.Entries, result.UsageKnown, err)
	b.maintenance.recordRetired("sb_tc_assign", result.Retired)
	if err != nil {
		result.Failure = TCAssignmentSweepFailureScan
		return result, err
	}
	if b.isolation {
		if err = b.sweepReturnRoutesLocked(maxIdle, budget, &result); err != nil {
			return result, err
		}
	}
	result.FailureMap = ""
	return result, nil
}
