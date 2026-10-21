//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCReturnRouteLifetimeIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC return-route pinning and idle cleanup")
	b := newTestAssignmentBackend(t)
	returnMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 44, ValueSize: uint32(unsafe.Sizeof(tcReturnValue{})), MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer returnMap.Close()
	b.runtime.maps["tc_return"] = returnMap
	b.assignmentCapacity = 2
	source, destination := netip.MustParseAddrPort("192.0.2.2:41000"), netip.MustParseAddrPort("203.0.113.10:9681")
	key, _ := makeTCAssignKey(ProtocolUDP, destination, source, 0)
	value := tcReturnValue{LastSeenNS: 1, Generation: 42, InterfaceIndex: 7, Flags: 1}
	if err = returnMap.Put(key, value); err != nil {
		t.Fatal(err)
	}
	first, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := b.AcquireReplyRoute(first, netip.MustParseAddrPort("203.0.113.20:8567"))
	if err != nil {
		t.Fatal(err)
	}
	foreign := &TCBackend{}
	foreign.ReleaseReturnRoute(first)
	first.Release()
	if b.returnReferences[second.reference] != 1 {
		t.Fatal("wrong reference ownership/count")
	}
	// A full map rejects new flows without evicting either retained route.
	thirdKey := key
	thirdKey.SourcePort++
	if err = returnMap.Put(thirdKey, value); err == nil {
		t.Fatal("full HASH admitted an extra route")
	}
	result := TCAssignmentSweepResult{Complete: true, UsageKnown: true}
	if err = b.sweepReturnRoutesLocked(time.Nanosecond, 16, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReturnRemoved != 0 || result.ReturnUsage.Entries != 2 || !result.Pressure {
		t.Fatalf("pinned sweep: %+v", result)
	}
	second.Release()
	alias.Release()
	grace := TCAssignmentSweepResult{Complete: true}
	if err = b.sweepReturnRoutesLocked(time.Nanosecond, 16, &grace); err != nil || grace.ReturnRemoved != 0 {
		t.Fatalf("last release skipped FIN/reply grace: %+v %v", grace, err)
	}
	for ref := range b.returnReleased {
		b.returnReleased[ref] = 1
	}

	result = TCAssignmentSweepResult{Complete: true, UsageKnown: true}
	if err = b.sweepReturnRoutesLocked(time.Nanosecond, 16, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReturnRemoved != 2 {
		t.Fatalf("released sweep: %+v", result)
	}
	if err = returnMap.Lookup(key, &value); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("released route retained: %v", err)
	}
	// Reusing a tuple creates a new generation; releasing a stale handle must
	// not decrement the new consumer's reference.
	value.Generation = 43
	if err = returnMap.Put(key, value); err != nil {
		t.Fatal(err)
	}
	current, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
	if b.returnReferences[current.reference] != 1 {
		t.Fatal("stale generation released current owner")
	}
	current.Release()
}

func TestTCAssignmentSweepGenerationAndBudgetIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify bounded assignment retirement preserves replacement generations")
	for _, fallback := range []bool{false, true} {
		name := "batch"
		if fallback {
			name = "key_iterator"
		}
		t.Run(name, func(t *testing.T) { testTCAssignmentSweepGenerationAndBudget(t, fallback) })
	}
}

func testTCAssignmentSweepGenerationAndBudget(t *testing.T, fallback bool) {
	b := newTestAssignmentBackend(t)
	if fallback {
		b.assignmentSweepScratch.lookupSupport.mode.Store(mapBatchUnsupported)
	}
	b.assignmentCapacity = 64
	source, destination := netip.MustParseAddrPort("192.0.2.2:41000"), netip.MustParseAddrPort("203.0.113.10:9681")
	for i := 0; i < 12; i++ {
		client := netip.AddrPortFrom(source.Addr(), source.Port()+uint16(i))
		writeTestAssignment(t, b, ProtocolUDP, client, destination, 0, TCAssignment{Generation: uint64(i + 1), LastSeenNS: 1})
	}
	var retired uint32
	complete := false
	for i := 0; i < 64; i++ {
		result, err := b.SweepAssignments(2*time.Second, 3)
		if err != nil {
			t.Fatal(err)
		}
		if result.Scanned > 3 {
			t.Fatalf("scan exceeded budget: %+v", result)
		}
		retired += result.Retired
		if result.Complete {
			if !result.UsageKnown || result.Usage.Entries != 12 || result.Removed != 0 {
				t.Fatalf("assignment storage must be retained: %+v", result)
			}
			complete = true
			break
		}
		if result.UsageKnown {
			t.Fatal("partial scan reported known usage")
		}
	}
	if !complete || retired != 12 {
		t.Fatalf("retirement did not finish: complete=%v retired=%d", complete, retired)
	}
	if _, err := b.LookupAssignment(ProtocolUDP, source, destination, 0, false); err == nil {
		t.Fatal("retired generation remained visible")
	}
	writeTestAssignment(t, b, ProtocolUDP, source, destination, 0, TCAssignment{Generation: 100, LastSeenNS: monotonicNowNS()})
	assignment, err := b.LookupAssignment(ProtocolUDP, source, destination, 0, false)
	if err != nil || assignment.Generation != 100 {
		t.Fatalf("old tombstone rejected replacement: %+v %v", assignment, err)
	}
	maintenance := b.MapMaintenance()
	if len(maintenance) != 1 || maintenance[0].Retired != 12 || maintenance[0].Removed != 0 || maintenance[0].Failures != 0 {
		t.Fatalf("maintenance: %+v", maintenance)
	}
}
