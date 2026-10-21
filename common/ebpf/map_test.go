//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestPolicyUpdateError(t *testing.T) {
	updateErr := errors.New("update")
	rollbackErr := errors.New("rollback")
	if err := policyUpdateError(updateErr, nil); !errors.Is(err, updateErr) {
		t.Fatalf("unexpected update error: %v", err)
	}
	err := policyUpdateError(updateErr, rollbackErr)
	if !policyRollbackFailed(err) {
		t.Fatal("expected rollback failure marker")
	}
	if !errors.Is(err, updateErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("transaction error did not preserve causes: %v", err)
	}
}

func TestBatchScanResumesWithinBudget(t *testing.T) {
	var scratch mapScanScratch[uint32, uint32]
	var cursor *CiliumEBPF.MapBatchCursor
	position, visited := 0, 0
	lookup := func(next *CiliumEBPF.MapBatchCursor, keys, values []uint32) (int, error) {
		if cursor != nil && cursor != next {
			t.Fatal("batch cursor was not retained")
		}
		cursor = next
		count := min(len(keys), 11-position)
		for index := range count {
			keys[index] = uint32(position + index)
			values[index] = keys[index]
		}
		position += count
		if position == 11 {
			return count, CiliumEBPF.ErrKeyNotExist
		}
		return count, nil
	}
	for pass := 0; pass < 3; pass++ {
		result, err := scratch.scanBatch(20, 4, lookup, func(key, value uint32) {
			if key != uint32(visited) || value != key {
				t.Fatal("revisited/skipped entry")
			}
			visited++
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Scanned > 4 || result.Complete != (pass == 2) {
			t.Fatalf("pass %d: %+v", pass, result)
		}
		if result.Complete && result.Entries != 11 {
			t.Fatalf("lost traversal occupancy: %+v", result)
		}
	}
	if visited != 11 || scratch.batchEntries != 0 {
		t.Fatal("incomplete traversal/reset")
	}
}
