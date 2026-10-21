//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/metacubex/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

type tcReturnValue struct {
	LastSeenNS     uint64
	Generation     uint64
	InterfaceIndex uint32
	Flags          uint32
	SourceMAC      MACAddress
	DestinationMAC MACAddress
	Reserved       uint32
}

type tcReturnReference struct {
	key        tcAssignKey
	generation uint64
}

// TCReturnHandle pins a tuple-preserving return route for one consumer. Every
// successful acquire must be released once, after the consumer stops writing.
// It is opaque and cannot be shared between backends or reconstructed by callers.
type TCReturnHandle struct {
	reference tcReturnReference
	owner     *TCBackend
	once      *sync.Once
}

func (h TCReturnHandle) IsValid() bool { return h.owner != nil && h.reference.generation != 0 }
func (h TCReturnHandle) Release() {
	if h.owner != nil {
		h.owner.ReleaseReturnRoute(h)
	}
}

func (b *TCBackend) retainReturnRouteLocked(key tcAssignKey, value tcReturnValue) TCReturnHandle {
	if b.returnReferences == nil {
		b.returnReferences = make(map[tcReturnReference]uint32)
	}
	ref := tcReturnReference{key: key, generation: value.Generation}
	b.returnReferences[ref]++
	return TCReturnHandle{reference: ref, owner: b, once: new(sync.Once)}
}

func (b *TCBackend) AcquireReturnRoute(protocol uint8, source, destination netip.AddrPort) (TCReturnHandle, error) {
	if b == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	key, err := makeTCAssignKey(protocol, destination, source, 0)
	if err != nil {
		return TCReturnHandle{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_return"] == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.returnAccess.Lock()
	defer b.returnAccess.Unlock()
	var value tcReturnValue
	if err = b.runtime.maps["tc_return"].Lookup(&key, &value); err != nil {
		return TCReturnHandle{}, err
	}
	if value.Generation == 0 {
		return TCReturnHandle{}, E.New("invalid TC return generation")
	}
	return b.retainReturnRouteLocked(key, value), nil
}

// AcquireReplyRoute allows a UDP consumer to reply from a different endpoint
// without changing a packet tuple (e.g. a DNS response selected by its router).
// The alias inherits only the already-pinned client's return path.
func (b *TCBackend) AcquireReplyRoute(original TCReturnHandle, source netip.AddrPort) (TCReturnHandle, error) {
	if b == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_return"] == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.returnAccess.Lock()
	defer b.returnAccess.Unlock()
	ref := original.reference
	if original.owner != b || ref.key.Protocol != ProtocolUDP || b.returnReferences[ref] == 0 {
		return TCReturnHandle{}, E.New("TC return route is not retained")
	}
	client := netip.AddrFrom16(ref.key.DestinationAddress)
	if ref.key.Family == unix.AF_INET {
		client = netip.AddrFrom4([4]byte(ref.key.DestinationAddress[:4]))
	}
	key, err := makeTCAssignKey(ProtocolUDP, source, netip.AddrPortFrom(client, ref.key.DestinationPort), 0)
	if err != nil {
		return TCReturnHandle{}, err
	}
	returnMap := b.runtime.maps["tc_return"]
	var value tcReturnValue
	if err = returnMap.Lookup(&ref.key, &value); err != nil {
		return TCReturnHandle{}, err
	}
	if value.Generation != ref.generation {
		return TCReturnHandle{}, E.New("TC return route generation changed")
	}
	value.LastSeenNS = monotonicNowNS()
	value.Generation = value.LastSeenNS
	if err = returnMap.Update(&key, &value, CiliumEBPF.UpdateNoExist); err != nil && !errors.Is(err, unix.EEXIST) {
		return TCReturnHandle{}, err
	}
	var current tcReturnValue
	if err = returnMap.Lookup(&key, &current); err != nil {
		return TCReturnHandle{}, err
	}
	if current.InterfaceIndex != value.InterfaceIndex || current.Flags != value.Flags || current.SourceMAC != value.SourceMAC || current.DestinationMAC != value.DestinationMAC {
		return TCReturnHandle{}, E.New("TC reply route belongs to another publisher")
	}
	return b.retainReturnRouteLocked(key, current), nil
}

func (b *TCBackend) ReleaseReturnRoute(handle TCReturnHandle) {
	if b == nil || handle.owner != b || !handle.IsValid() || handle.once == nil {
		return
	}
	handle.once.Do(func() {
		b.returnAccess.Lock()
		defer b.returnAccess.Unlock()
		ref := handle.reference
		count := b.returnReferences[ref]
		if count > 1 {
			b.returnReferences[ref] = count - 1
		} else if count == 1 {
			delete(b.returnReferences, ref)
			if b.returnReleased == nil {
				b.returnReleased = make(map[tcReturnReference]uint64)
			}
			b.returnReleased[ref] = monotonicNowNS()
		}
	})
}

// Caller holds b.access. The reference lock serializes acquisition with idle
// cleanup, so a live consumer cannot lose its route to a maintenance pass.
func (b *TCBackend) sweepReturnRoutesLocked(maxIdle time.Duration, budget uint32, result *TCAssignmentSweepResult) error {
	if err := b.sweepReturnMapLocked(maxIdle, budget, result); err != nil {
		return err
	}
	return b.sweepReturnFragmentsLocked(budget, result)
}

func (b *TCBackend) sweepReturnMapLocked(maxIdle time.Duration, budget uint32, result *TCAssignmentSweepResult) (sweepErr error) {
	result.FailureMap = "sb_tc_return"
	m := b.runtime.maps["tc_return"]
	if m == nil {
		result.Failure = TCAssignmentSweepFailureClosed
		return errBackendClosed
	}
	now := monotonicNowNS()
	cutoff := now - min(now, uint64(maxIdle))
	type candidate struct {
		key   tcAssignKey
		value tcReturnValue
	}
	var candidates []candidate
	scan, err := b.returnSweepScratch.scan(m, b.assignmentCapacity, budget, func(key tcAssignKey, value tcReturnValue) {
		if value.LastSeenNS != 0 && value.LastSeenNS <= cutoff {
			candidates = append(candidates, candidate{key, value})
		}
	})
	defer func() {
		b.maintenance.record("sb_tc_return", b.assignmentCapacity, scan, result.ReturnRemoved, result.ReturnUsage.Entries, result.ReturnUsageKnown, sweepErr)
	}()
	if err != nil {
		result.Failure = TCAssignmentSweepFailureScan
		return err
	}
	result.ReturnScanned = scan.Scanned
	result.Complete = result.Complete && scan.Complete
	if scan.Restarted {
		b.returnSweepRemoved = 0
	}
	for _, entry := range candidates {
		removed, failure, err := b.deleteIdleReturnRoute(m, entry.key, entry.value)
		if err != nil {
			result.Failure = failure
			return err
		}
		if removed {
			result.ReturnRemoved++
			b.returnSweepRemoved++
		}
	}
	if scan.Complete {
		result.ReturnUsageKnown = true
		result.ReturnUsage = MapUsage{Capacity: b.assignmentCapacity, Entries: scan.Entries - min(scan.Entries, b.returnSweepRemoved)}
		b.returnSweepRemoved = 0
		result.Pressure = result.Pressure || uint64(result.ReturnUsage.Entries)*100 >= uint64(result.ReturnUsage.Capacity)*70
	}
	return nil
}

func (b *TCBackend) sweepReturnFragmentsLocked(budget uint32, result *TCAssignmentSweepResult) (sweepErr error) {
	m := b.runtime.maps["tc_return_frag"]
	if m == nil {
		return nil
	}
	result.FailureMap = "sb_tc_rfrag"
	capacity := min(b.assignmentCapacity, 1024)
	now := monotonicNowNS()
	type candidate struct {
		key   tcAssignKey
		value tcReturnValue
	}
	var candidates []candidate
	scan, err := b.returnFragmentSweepScratch.scan(m, capacity, budget, func(key tcAssignKey, value tcReturnValue) {
		if now > value.LastSeenNS && now-value.LastSeenNS > uint64(2*time.Second) {
			candidates = append(candidates, candidate{key, value})
		}
	})
	removed := uint32(0)
	defer func() { b.maintenance.record("sb_tc_rfrag", capacity, scan, removed, 0, false, sweepErr) }()
	if err != nil {
		result.Failure = TCAssignmentSweepFailureScan
		return err
	}
	result.Complete = result.Complete && scan.Complete
	for _, entry := range candidates {
		var current tcReturnValue
		if err = m.Lookup(&entry.key, &current); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			result.Failure = TCAssignmentSweepFailureLookup
			return err
		}
		if current != entry.value {
			continue
		}
		if err = m.Delete(&entry.key); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			result.Failure = TCAssignmentSweepFailureDelete
			return err
		}
		removed++
	}
	return nil
}

func (b *TCBackend) deleteIdleReturnRoute(returnMap *CiliumEBPF.Map, key tcAssignKey, expected tcReturnValue) (bool, string, error) {
	b.returnAccess.Lock()
	defer b.returnAccess.Unlock()
	if b.returnReferences[tcReturnReference{key, expected.Generation}] != 0 {
		return false, "", nil
	}
	ref := tcReturnReference{key, expected.Generation}
	if released := b.returnReleased[ref]; released != 0 && monotonicNowNS()-released < uint64(2*time.Second) {
		return false, "", nil
	}
	var current tcReturnValue
	if err := returnMap.Lookup(&key, &current); errors.Is(err, unix.ENOENT) {
		return false, "", nil
	} else if err != nil {
		return false, TCAssignmentSweepFailureLookup, err
	}
	if current != expected {
		return false, "", nil
	}
	if err := returnMap.Delete(&key); errors.Is(err, unix.ENOENT) {
		return false, "", nil
	} else if err != nil {
		return false, TCAssignmentSweepFailureDelete, err
	}
	delete(b.returnReleased, ref)
	return true, "", nil
}
