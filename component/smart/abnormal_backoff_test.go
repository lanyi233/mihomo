package smart

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func hostStatusFor(t *testing.T, cachePath string) *HostStatus {
	t.Helper()
	hs, ok := hostStatusCache.Get(cachePath)
	require.True(t, ok)
	return hs
}

// A repeat abnormal answer lengthens the next block, but only once the one in
// force has lapsed: blockNode never pushes a live deadline out, which is what
// keeps a host that fails every recovery probe from staying blocked for good.
func TestAbnormalStatusBackOffLengthensOnlyTheNextBlock(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "backoff.example.com"
		node           = "node"
	)
	cachePath := seedHostStatus(t, group, config, wildcardTarget, &HostStatus{})
	store := &Store{}
	metadata := &C.Metadata{Host: wildcardTarget}
	record := func() int64 {
		store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1_000, true, true, BlockAbnormalStatus, 5*time.Minute)
		return hostStatusFor(t, cachePath).Codes[BlockAbnormalStatus].Nodes[node]
	}

	first := record()
	require.InDelta(t, time.Now().Add(5*time.Minute).Unix(), first, 2)

	// Again while it is in force: counted, but the deadline stays.
	require.Equal(t, first, record())
	require.Equal(t, 2, hostStatusFor(t, cachePath).Codes[BlockAbnormalStatus].FailCounts[node])

	// Once it has lapsed, the next one escalates.
	hs := hostStatusFor(t, cachePath)
	hs.mu.Lock()
	hs.Codes[BlockAbnormalStatus].Nodes[node] = time.Now().Add(-time.Second).Unix()
	hs.mu.Unlock()
	third := record()
	require.InDelta(t, time.Now().Add(time.Hour).Unix(), third, 2)
}

// A code 2 FailCounts entry is back-off memory that outlives its block. Taken
// for the node's current verdict it would outrank every later one, so a dial
// failure or a dead relay on that node could not be recorded at all.
func TestAbnormalStatusBackOffDoesNotHideLaterVerdicts(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "later.example.com"
		node           = "node"
	)
	// A recent failure on the host keeps the back-off memory from being
	// dropped as stale before the verdict is weighed.
	cachePath := seedHostStatus(t, group, config, wildcardTarget, &HostStatus{
		LastFailure: time.Now().Add(-time.Minute).Unix(),
		Codes: map[BlockCode]*CodeNodeSet{
			BlockAbnormalStatus: {Nodes: map[string]int64{}, FailCounts: map[string]int{node: 2}},
		},
	})
	store := &Store{}

	store.UpdateHostStatus(group, config, wildcardTarget, &C.Metadata{Host: wildcardTarget}, node, 3, 1_000, true, true, BlockNoResponse, 0)

	codeSet := hostStatusFor(t, cachePath).Codes[BlockNoResponse]
	require.NotNil(t, codeSet, "the no-response verdict was discarded")
	require.Contains(t, codeSet.Nodes, node)
}

// A site's short-lived answers do not count toward hostFailLimit: a site that
// rate limits would otherwise flip its whole target in and out of Blocked.
func TestAbnormalStatusDoesNotMarkTheTargetBlocked(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "limited.example.com"
	)
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{})
	store := &Store{}
	metadata := &C.Metadata{Host: wildcardTarget}
	for _, node := range []string{"a", "b", "c"} {
		store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1, true, true, BlockAbnormalStatus, 5*time.Minute)
	}
	failNodes, _, _, blocked := store.GetHostStatus(group, config, wildcardTarget, 1)
	require.Len(t, failNodes, 3, "each node is still avoided for the host")
	require.False(t, blocked)

	for _, node := range []string{"a", "b"} {
		store.UpdateHostStatus(group, config, wildcardTarget, metadata, node+"-dead", 3, 1, true, true, BlockNoResponse, 0)
	}
	_, _, _, blocked = store.GetHostStatus(group, config, wildcardTarget, 1)
	require.True(t, blocked, "verdicts about the nodes themselves still count")
}

// A quiet host drops its back-off memory, but not for a node whose back-off
// block is still in force: CheckHostStatus tells that block from a legacy
// day-long one by the count, and would purge it early without it.
func TestQuietHostKeepsTheCountOfALiveBackOffBlock(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "quiet.example.com"
	)
	day := time.Now().Add(24 * time.Hour).Unix()
	cachePath := seedHostStatus(t, group, config, wildcardTarget, &HostStatus{
		LastFailure: time.Now().Add(-5 * time.Hour).Unix(),
		Codes: map[BlockCode]*CodeNodeSet{
			BlockAbnormalStatus: {
				Nodes:      map[string]int64{"backed-off": day},
				NodeHosts:  map[string]string{"backed-off": wildcardTarget},
				FailCounts: map[string]int{"backed-off": 5, "lapsed": 3},
			},
		},
	})
	store := &Store{}

	// Any update runs the expiry pass; a clean close on another node will do.
	store.UpdateHostStatus(group, config, wildcardTarget, &C.Metadata{Host: wildcardTarget}, "other", 3, 1_000, false, true, BlockNone, 0)
	_, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	codeSet := hostStatusFor(t, cachePath).Codes[BlockAbnormalStatus]
	require.NotNil(t, codeSet)
	require.Contains(t, codeSet.Nodes, "backed-off", "the live back-off block was purged")
	require.NotContains(t, codeSet.FailCounts, "lapsed")
}
