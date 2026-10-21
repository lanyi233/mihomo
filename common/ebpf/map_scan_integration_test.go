//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestMapScanBudgetAndRestartIntegration(t *testing.T) {
	requireEBPFIntegration(t, "scan real hash buckets with a bounded budget")
	m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for key := uint32(0); key < 64; key++ {
		if err := m.Update(key, key+1, CiliumEBPF.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for _, budget := range []uint32{1, 7, 64} {
		var scratch mapScanScratch[uint32, uint32]
		seen := make(map[uint32]bool)
		for pass := 0; pass < 256; pass++ {
			result, err := scratch.scan(m, 64, budget, func(key, value uint32) {
				if value != key+1 {
					t.Fatalf("corrupt map value: %d=%d", key, value)
				}
				seen[key] = true
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Scanned > budget {
				t.Fatalf("scan exceeded budget %d: %+v", budget, result)
			}
			if result.Complete {
				if result.Entries != 64 || len(seen) != 64 {
					t.Fatalf("incomplete traversal: %+v, seen=%d", result, len(seen))
				}
				break
			}
			if pass == 255 {
				t.Fatalf("scan with budget %d did not converge", budget)
			}
		}
	}
}

func TestSharedPurgeDoesNotReuseIdleSweepCursorIntegration(t *testing.T) {
	requireEBPFIntegration(t, "purge an interface during an unfinished idle sweep")
	originals, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 44, ValueSize: 40, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer originals.Close()
	tokens, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 40, ValueSize: 40, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer tokens.Close()
	b := &SharedNetworkBackend{
		mapCapacity: SharedNetworkMapCapacities{Proxy: 64},
		runtime: &sharedNetworkRuntime{maps: map[string]*CiliumEBPF.Map{"shared_flow_by_original": originals},
			flow_by_original_map_fd: originals.FD(), flow_by_token_map_fd: tokens.FD()},
	}
	// Force the legacy iterator so the test deterministically pauses after
	// visiting a key that a shared purge cursor would subsequently skip.
	b.flowSweepScratch.lookupSupport.mode.Store(mapBatchUnsupported)
	b.flowPurgeScratch.lookupSupport.mode.Store(mapBatchUnsupported)
	for index := uint16(0); index < 12; index++ {
		key := sharedNetworkOriginalKey{InterfaceIndex: 7, Family: addressFamilyIPv4, Protocol: ProtocolUDP, ClientPort: 10000 + index}
		value := sharedNetworkTokenValue{Generation: uint64(index) + 1, LastSeenNS: monotonicNowNS()}
		if err := originals.Update(key, value, CiliumEBPF.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	result, err := b.SweepOrphanedFlows(time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.Scanned != 1 {
		t.Fatalf("idle sweep did not pause: %+v", result)
	}
	var removed uint32
	for pass := 0; pass < 64; pass++ {
		count, complete, err := b.PurgeInterfaceFlows(7, 1)
		if err != nil {
			t.Fatal(err)
		}
		removed += count
		if complete {
			if removed != 12 {
				t.Fatalf("purge skipped previously scanned flows: removed %d", removed)
			}
			return
		}
	}
	t.Fatal("interface purge did not converge")
}
