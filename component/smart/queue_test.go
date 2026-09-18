package smart

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func queueOp(group, target, node string, data string) StoreOperation {
	return StoreOperation{
		Type: OpSaveStats, KeyType: KeyTypeStats,
		Group: group, Config: "config", Target: target, Node: node,
		Data: []byte(data),
	}
}

// The queue deduplicates so that its flush threshold counts distinct keys
// rather than raw appends. Losing that would flush more often, and every flush
// is a bbolt commit with an fsync.
func TestQueueKeepsOnlyTheLatestWritePerKey(t *testing.T) {
	var q operationQueue
	q.add([]StoreOperation{queueOp("g", "t", "n", "first")})
	q.add([]StoreOperation{queueOp("g", "t", "n", "second")})

	pending := q.snapshot()
	require.Len(t, pending, 1, "the same key was queued twice, so the threshold counts writes instead of keys")
	require.Equal(t, "second", string(pending[0].Data))
}

// Order is what makes GetSubBytesByPath's in-order scan answer a read with the
// caller's own pending write.
func TestQueueKeepsInsertionOrder(t *testing.T) {
	var q operationQueue
	for _, node := range []string{"a", "b", "c"} {
		q.add([]StoreOperation{queueOp("g", "t", node, node)})
	}
	// Replacing an existing key must not move it to the end.
	q.add([]StoreOperation{queueOp("g", "t", "a", "a2")})

	pending := q.snapshot()
	require.Len(t, pending, 3)
	require.Equal(t, []string{"a2", "b", "c"},
		[]string{string(pending[0].Data), string(pending[1].Data), string(pending[2].Data)})
}

// Reaching the threshold hands the whole batch to the caller and leaves the
// queue empty, so nothing is written twice.
func TestQueueFlushesAtTheThresholdAndEmptiesItself(t *testing.T) {
	var q operationQueue
	threshold := GetBatchSaveThreshold()
	var flushed []StoreOperation
	for i := range threshold {
		if batch := q.add([]StoreOperation{queueOp("g", "t", fmt.Sprintf("n%d", i), "x")}); batch != nil {
			require.Nil(t, flushed, "the queue flushed more than once")
			flushed = batch
		}
	}
	require.Len(t, flushed, threshold, "the queue did not flush on reaching the threshold")
	require.Empty(t, q.snapshot(), "a flushed batch was left in the queue as well")
}

// retain is how the flood suppressor and config teardown drop entries; the
// index has to follow or a later write to a dropped key would be lost.
func TestQueueRetainRebuildsTheIndex(t *testing.T) {
	var q operationQueue
	q.add([]StoreOperation{queueOp("keep", "t", "n", "1"), queueOp("drop", "t", "n", "2")})
	q.retain(func(op StoreOperation) bool { return op.Group == "keep" })
	require.Len(t, q.snapshot(), 1)

	// The dropped key must be insertable again, and the surviving one must
	// still deduplicate rather than being appended a second time.
	q.add([]StoreOperation{queueOp("drop", "t", "n", "3"), queueOp("keep", "t", "n", "4")})
	pending := q.snapshot()
	require.Len(t, pending, 2, "retain left a stale index, so a key was queued twice")
	require.Equal(t, "4", string(pending[0].Data))
	require.Equal(t, "3", string(pending[1].Data))
}

func TestQueueConcurrentAppendsKeepEveryKey(t *testing.T) {
	var q operationQueue
	const writers, each = 8, 50
	var wg sync.WaitGroup
	var flushedMu sync.Mutex
	flushed := 0
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				batch := q.add([]StoreOperation{queueOp("g", "t", fmt.Sprintf("n%d-%d", w, i), "x")})
				flushedMu.Lock()
				flushed += len(batch)
				flushedMu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, writers*each, flushed+len(q.snapshot()),
		"operations were lost between the flushed batches and what is still pending")
}

// The record is encoded with hs.mu released, from a copy taken under it. If the
// copy shared any map with the live record, a concurrent update could mutate it
// mid-encode -- and worse, the encoded form would not be the one that was
// agreed under the lock.
func TestHostStatusSaveCopySharesNothingWithTheLiveRecord(t *testing.T) {
	live := &HostStatus{
		LastCheck: 7,
		Blocked:   true,
		Codes: map[BlockCode]*CodeNodeSet{
			BlockNoResponse: {
				Nodes:      map[string]int64{"node-a": 100},
				FailCounts: map[string]int{"node-a": 2},
				NodeHosts:  map[string]string{"node-a": "probe.example.com"},
			},
			BlockManual: nil,
		},
	}

	live.mu.Lock()
	saved := live.cloneForSaveLocked()
	live.mu.Unlock()

	require.Equal(t, int64(7), saved.LastCheck)
	require.True(t, saved.Blocked)
	require.NotContains(t, saved.Codes, BlockManual, "a nil code set was copied as an empty one")

	live.Codes[BlockNoResponse].Nodes["node-a"] = 999
	live.Codes[BlockNoResponse].FailCounts["node-a"] = 99
	live.Codes[BlockNoResponse].NodeHosts["node-a"] = "elsewhere"
	require.Equal(t, int64(100), saved.Codes[BlockNoResponse].Nodes["node-a"],
		"the copy shares its Nodes map with the live record")
	require.Equal(t, 2, saved.Codes[BlockNoResponse].FailCounts["node-a"],
		"the copy shares its FailCounts map with the live record")
	require.Equal(t, "probe.example.com", saved.Codes[BlockNoResponse].NodeHosts["node-a"],
		"the copy shares its NodeHosts map with the live record")
}

// What the copy encodes to must be what the live record would have encoded to.
// The maps a code does not use stay out either way -- omitempty drops an empty
// map as readily as a nil one -- so this pins the whole encoded form rather
// than the nil-ness of any one field.
func TestHostStatusSaveCopyEncodesTheSameForm(t *testing.T) {
	live := &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockLowWeight: {Nodes: map[string]int64{"node-a": 1}},
	}}
	live.mu.Lock()
	saved := live.cloneForSaveLocked()
	live.mu.Unlock()

	encoded, err := json.Marshal(saved)
	require.NoError(t, err)
	require.JSONEq(t, `{"codes":{"5":{"nodes":{"node-a":1}}}}`, string(encoded))
}
