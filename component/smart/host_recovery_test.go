package smart

import (
	"encoding/json"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// seedHostStatus installs a HostStatus straight into both caches, the way
// TestCheckHostStatusConcurrentUpdate does: the global write queue runs
// asynchronous flushes and is not a stable fixture.
func seedHostStatus(t *testing.T, group, config, wildcardTarget string, hs *HostStatus) string {
	t.Helper()
	InitCache()
	InitQueue()
	db = nil
	hostStatusCache.Clear()
	dbResultCache.Clear()

	data, err := json.Marshal(hs)
	require.NoError(t, err)
	cachePath := FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget)
	hs.initOnce.Do(func() {})
	hostStatusCache.Set(cachePath, hs)
	dbResultCache.Set(FormatDBKey(KeyTypeHostFailures, config, group), map[string][]byte{
		cachePath: data,
	})
	return cachePath
}

func blockedNode(node, host string, expiresIn time.Duration) *CodeNodeSet {
	return &CodeNodeSet{
		Nodes:     map[string]int64{node: time.Now().Add(expiresIn).Unix()},
		NodeHosts: map[string]string{node: host},
	}
}

// A blocked node is dropped outright at dial time, so a recovery probe is the
// only thing that can return it to service before the 24-hour TTL. The sweep
// used to be built from BlockAbnormalStatus alone -- the one code a probe can
// itself raise -- which left dial failures, no-response, low weight and packet
// loss excluded for a full day with no way back.
func TestCheckHostStatusProbesEveryRecoverableCode(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
	)
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockAbnormalStatus: blockedNode("node-abnormal", "a.example.com", probeMaxBlockTTL/2),
		BlockDialFailure:    blockedNode("node-dial", "b.example.com", time.Hour),
		BlockNoResponse:     blockedNode("node-zero-traffic", "c.example.com", time.Hour),
		BlockLowWeight:      blockedNode("node-low-weight", "d.example.com", time.Hour),
		BlockPacketLoss:     blockedNode("node-loss", "e.example.com", time.Hour),
	}})

	store := &Store{}
	result, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	probes := result[wildcardTarget]
	for node, host := range map[string]string{
		"node-abnormal":     "a.example.com",
		"node-dial":         "b.example.com",
		"node-zero-traffic": "c.example.com",
		"node-low-weight":   "d.example.com",
		"node-loss":         "e.example.com",
	} {
		require.Equalf(t, host, probes[node], "%s is blocked with no way back before the TTL", node)
	}
}

// BlockManual is the dashboard's block. It must never be probed back into
// service behind the user's back.
//
// The entry here is given a real deadline rather than the TTL 0 production
// uses, precisely so the Recoverable guard is what the test exercises: with
// TTL 0 the independent "permanent entries are not probed" gate excludes it
// and the guard goes unpinned. Production also never records a NodeHosts
// entry for a manual block, which is a third independent reason -- so this is
// defence in depth, and each layer deserves its own test.
func TestCheckHostStatusNeverProbesAManualBlock(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "manual.example.com"
	)
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockManual: blockedNode("node-manual", "manual.example.com", time.Hour),
	}})

	store := &Store{}
	result, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)
	require.Empty(t, result[wildcardTarget], "a manual block was queued for a recovery probe")
}

// And the same for the shape production actually writes: TTL 0.
func TestCheckHostStatusNeverProbesAPermanentEntry(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "permanent.example.com"
	)
	permanent := blockedNode("node-permanent", "permanent.example.com", time.Hour)
	permanent.Nodes["node-permanent"] = 0 // TTL 0 means permanent
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockNoResponse: permanent,
	}})

	store := &Store{}
	result, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)
	require.Empty(t, result[wildcardTarget], "a permanent block was queued for a recovery probe")
}

// A probe needs somewhere to aim. Recording the host only for the
// status-test code meant that even once the others were swept there would be
// nothing to test.
func TestUpdateHostStatusRecordsTheHostForEveryBlockingCode(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	for _, blockCode := range []BlockCode{BlockAbnormalStatus, BlockNoResponse, BlockLowWeight, BlockPacketLoss} {
		seedHostStatus(t, group, config, wildcardTarget, &HostStatus{})

		store := &Store{}
		metadata := &C.Metadata{Host: "probe.example.com"}
		store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1_000, true, true, blockCode, 0)

		cached, ok := hostStatusCache.Get(FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget))
		require.True(t, ok)
		codeSet := cached.Codes[blockCode]
		require.NotNilf(t, codeSet, "code %d recorded no block at all", blockCode)
		require.Equalf(t, "probe.example.com", codeSet.NodeHosts[node],
			"code %d blocked a node without recording where to probe it", blockCode)
	}
}

// BlockDialFailure only blocks once the failures pile up; until then it is a
// counter, and a counter is not something to probe.
func TestUpdateHostStatusRecordsTheHostWhenCode3Blocks(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
		maxFailedTimes = 2
	)
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{})

	store := &Store{}
	cachePath := FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget)
	metadata := &C.Metadata{Host: "probe.example.com"}

	store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, maxFailedTimes, 1_000, true, true, BlockDialFailure, 0)
	cached, ok := hostStatusCache.Get(cachePath)
	require.True(t, ok)
	require.Empty(t, cached.Codes[BlockDialFailure].Nodes, "a single failure blocked the node outright")

	store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, maxFailedTimes, 1_000, true, true, BlockDialFailure, 0)
	cached, ok = hostStatusCache.Get(cachePath)
	require.True(t, ok)
	require.NotEmpty(t, cached.Codes[BlockDialFailure].Nodes, "the node never blocked despite reaching the failure limit")
	require.Equal(t, "probe.example.com", cached.Codes[BlockDialFailure].NodeHosts[node],
		"a dial-failure block recorded no probe target")
}

// The store-side contract the caller-side fix depends on: told a connection
// succeeded, UpdateHostStatus drops the node from every code set except the
// manual one. This branch predates that fix -- it is characterised here, not
// introduced -- and the fix is only worth anything if it holds.
func TestUpdateHostStatusClearsEveryRecoverableBlockOnSuccess(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	codes := map[BlockCode]*CodeNodeSet{}
	for _, code := range []BlockCode{BlockManual, BlockAbnormalStatus, BlockDialFailure, BlockNoResponse, BlockLowWeight, BlockPacketLoss} {
		codes[code] = blockedNode(node, "probe.example.com", time.Hour)
	}
	codes[BlockManual].Nodes[node] = 0
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: codes})

	store := &Store{}
	metadata := &C.Metadata{Host: "probe.example.com"}
	store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1_000, false, true, BlockNone, 0)

	cached, ok := hostStatusCache.Get(FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget))
	require.True(t, ok)
	for _, code := range []BlockCode{BlockAbnormalStatus, BlockDialFailure, BlockNoResponse, BlockLowWeight, BlockPacketLoss} {
		if codeSet := cached.Codes[code]; codeSet != nil {
			require.NotContainsf(t, codeSet.Nodes, node, "a clean close left the code %d block in place", code)
		}
	}
	require.NotNil(t, cached.Codes[BlockManual], "a clean close lifted the user's manual block")
	require.Contains(t, cached.Codes[BlockManual].Nodes, node, "a clean close lifted the user's manual block")
}

// A recovery probe that fails re-blocks the node, and the probe is the only
// thing that ever re-blocks a node it has just tested. Minting a fresh TTL
// there turns a bounded exclusion into a permanent one: a host that answers a
// bare GET with a banned status fails every probe, so the pair would never be
// released at all.
func TestUpdateHostStatusReblockNeverExtendsTheDeadline(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	original := time.Now().Add(2 * time.Hour).Unix()
	codes := map[BlockCode]*CodeNodeSet{BlockNoResponse: {
		Nodes:     map[string]int64{node: original},
		NodeHosts: map[string]string{node: "probe.example.com"},
	}}
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: codes})

	store := &Store{}
	metadata := &C.Metadata{Host: "probe.example.com"}
	// What a failed recovery probe does: re-block as code 2.
	store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1_000, true, true, BlockAbnormalStatus, 0)

	cached, ok := hostStatusCache.Get(FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget))
	require.True(t, ok)
	require.NotNil(t, cached.Codes[BlockAbnormalStatus])
	require.Equalf(t, original, cached.Codes[BlockAbnormalStatus].Nodes[node],
		"the re-block moved the deadline to %d; the node is now excluded for another full TTL and the next failed probe will do it again",
		cached.Codes[BlockAbnormalStatus].Nodes[node])
}

// A first block still gets the full TTL -- the clamp only ever holds a
// deadline back, it never shortens a new one.
func TestUpdateHostStatusFirstBlockGetsTheFullTTL(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{})

	store := &Store{}
	metadata := &C.Metadata{Host: "probe.example.com"}
	before := time.Now().Add(HostFailureNodeTTL).Unix()
	store.UpdateHostStatus(group, config, wildcardTarget, metadata, node, 3, 1_000, true, true, BlockNoResponse, 0)

	cached, ok := hostStatusCache.Get(FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget))
	require.True(t, ok)
	require.GreaterOrEqual(t, cached.Codes[BlockNoResponse].Nodes[node], before,
		"a first block was clamped below the full TTL")
}

// An expired block is not a block: nothing is excluding the node, so probing it
// can only mint a new one for a node that is serving fine. Nothing sweeps
// expired entries for a target that went quiet, so they would otherwise sit
// there being probed forever.
func TestCheckHostStatusSkipsALapsedBlock(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
	)
	codes := map[BlockCode]*CodeNodeSet{
		BlockNoResponse: blockedNode("node-lapsed", "lapsed.example.com", -time.Hour),
		BlockLowWeight:  blockedNode("node-live", "live.example.com", time.Hour),
	}
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: codes})

	store := &Store{}
	result, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	probes := result[wildcardTarget]
	require.NotContains(t, probes, "node-lapsed", "a block that already expired was queued for a probe")
	require.Equal(t, "live.example.com", probes["node-live"], "the live block stopped being probed")
}

// A demotion empties the old code set for the node, probe target included, and
// the connection that caused it may carry no hostname of its own. Losing the
// target there leaves the node blocked for the rest of the TTL with nothing
// able to probe it -- the state that recording a target for every blocking
// code was meant to end.
func TestUpdateHostStatusKeepsTheProbeTargetThroughADemotion(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	blocked := time.Now().Add(20 * time.Hour).Unix()
	seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockNoResponse: {
			Nodes:     map[string]int64{node: blocked},
			NodeHosts: map[string]string{node: "api.example.com"},
		},
	}})

	store := &Store{}
	// A later failure on a bare-IP destination: no hostname of its own, and a
	// lower code, so the code-4 record is demoted away.
	bareIP := &C.Metadata{}
	for range 3 {
		store.UpdateHostStatus(group, config, wildcardTarget, bareIP, node, 1, 1_000, true, true, BlockDialFailure, 0)
	}

	cached, ok := hostStatusCache.Get(FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget))
	require.True(t, ok)
	codeSet := cached.Codes[BlockDialFailure]
	require.NotNil(t, codeSet)
	require.Contains(t, codeSet.Nodes, node, "the demotion lifted the block instead of moving it")
	require.Equal(t, "api.example.com", codeSet.NodeHosts[node],
		"the demoted block has no probe target, so nothing can return this node to service before the TTL")
}

// The codes are the keys of a persisted map, so giving them a named type must
// not change what lands on disk. A defined integer type marshals exactly as the
// underlying int does; this pins that, because a silent change here would make
// every existing cache file unreadable.
func TestBlockCodeKeysKeepTheirOnDiskForm(t *testing.T) {
	encoded, err := json.Marshal(&HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockManual:     {Nodes: map[string]int64{"node-a": 0}},
		BlockNoResponse: {Nodes: map[string]int64{"node-b": 12345}},
	}})
	require.NoError(t, err)
	require.JSONEq(t,
		`{"codes":{"1":{"nodes":{"node-a":0}},"4":{"nodes":{"node-b":12345}}}}`,
		string(encoded))

	var decoded HostStatus
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, int64(12345), decoded.Codes[BlockNoResponse].Nodes["node-b"])
}
