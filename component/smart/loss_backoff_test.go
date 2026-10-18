package smart

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestPacketLossNeedsTwoWindowsAndPreservesDeadline(t *testing.T) {
	const group, config, target, node = "loss-group", "config", "example.com", "node"
	hs := &HostStatus{}
	seedHostStatus(t, group, config, target, hs)
	store := &Store{}
	metadata := &C.Metadata{Host: target}
	strike := func() bool {
		return store.UpdateHostStatus(group, config, target, metadata, node, 3, 100, true, true, BlockPacketLoss, 0)
	}
	for i, ttl := range []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, HostFailureNodeTTL} {
		require.False(t, strike(), "first window must not block")
		blocked, _, _, _ := store.GetHostStatus(group, config, target, 100)
		require.NotContains(t, blocked, node)
		before := time.Now().Unix()
		require.True(t, strike(), "second window must confirm loss")
		code := hs.Codes[BlockPacketLoss]
		deadline := code.Nodes[node]
		require.InDelta(t, before+int64(ttl.Seconds()), deadline, 2)
		require.Equal(t, i+1, code.Confirmations[node])
		strike()
		require.Equal(t, deadline, code.Nodes[node], "a live block must not be prolonged")
		require.Equal(t, i+1, code.Confirmations[node], "a live block must not advance the ladder")
		// Simulate expiry without sleeping; the next two windows should advance the ladder.
		hs.mu.Lock()
		code.Nodes[node] = time.Now().Add(-time.Second).Unix()
		hs.mu.Unlock()
	}
	store.UpdateHostStatus(group, config, target, metadata, node, 3, 100, false, true, BlockNone, 0)
	require.Empty(t, hs.Codes, "a successful answer must clear pending strikes and backoff memory")
}
