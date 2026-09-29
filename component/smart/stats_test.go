package smart

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckHostStatusConcurrentUpdate(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
	)
	now := time.Now().Unix()
	initial := HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockAbnormalStatus: {
			Nodes:     map[string]int64{"node-0": now + int64((probeMaxBlockTTL / 2).Seconds())},
			NodeHosts: map[string]string{"node-0": "example.com"},
		},
	}}
	cachePath := seedHostStatus(t, group, config, wildcardTarget, &initial)

	store := &Store{}
	_, err := store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	cached, ok := hostStatusCache.Get(cachePath)
	require.True(t, ok)
	require.NotNil(t, cached.Codes[BlockAbnormalStatus])

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2_000; i++ {
			name := fmt.Sprintf("node-%d", i%64)
			cached.mu.Lock()
			codeSet := cached.Codes[BlockAbnormalStatus]
			codeSet.Nodes[name] = now + int64((probeMaxBlockTTL / 2).Seconds())
			codeSet.NodeHosts[name] = fmt.Sprintf("host-%d.example", i)
			if i >= 64 {
				oldName := fmt.Sprintf("node-%d", (i+1)%64)
				delete(codeSet.Nodes, oldName)
				delete(codeSet.NodeHosts, oldName)
			}
			cached.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2_000; i++ {
			_, checkErr := store.CheckHostStatus(group, config, 1_000)
			if checkErr != nil {
				select {
				case errCh <- checkErr:
				default:
				}
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for checkErr := range errCh {
		require.NoError(t, checkErr)
	}
}

// CheckHostStatus drops the day-long code 2 blocks an older version wrote, but
// a repeat block the back-off lengthened past probeMaxBlockTTL carries the
// FailCounts entry it was counted with and has to stay.
func TestCheckHostStatusDropsOnlyLegacyLongAbnormalBlocks(t *testing.T) {
	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "legacy.example.com"
	)
	now := time.Now().Unix()
	day := now + int64((24 * time.Hour).Seconds())
	cachePath := seedHostStatus(t, group, config, wildcardTarget, &HostStatus{Codes: map[BlockCode]*CodeNodeSet{
		BlockAbnormalStatus: {
			Nodes:      map[string]int64{"legacy": day, "backed-off": day},
			NodeHosts:  map[string]string{"legacy": wildcardTarget, "backed-off": wildcardTarget},
			FailCounts: map[string]int{"backed-off": 5},
		},
	}})

	_, err := (&Store{}).CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	cached, ok := hostStatusCache.Get(cachePath)
	require.True(t, ok)
	codeSet := cached.Codes[BlockAbnormalStatus]
	require.NotNil(t, codeSet)
	require.NotContains(t, codeSet.Nodes, "legacy")
	require.Contains(t, codeSet.Nodes, "backed-off")
}

// The evidence behind network claims is cached between rebuilds, so a flush has
// to drop that cache too, or the flushed counts keep backing claims.
func TestFlushDropsCachedASNEvidence(t *testing.T) {
	InitCache()
	InitQueue()
	store := &Store{}
	const (
		group    = "flush-evidence-group"
		config   = "config"
		ruleName = "RuleSet [example-video]"
	)
	t.Cleanup(func() { invalidateASNEvidence("group", config, group) })

	require.Empty(t, store.TargetASNEvidence(group, config))
	store.RecordASNEvidence(group, config, ruleName, "64512")
	require.Equal(t, 1, store.TargetASNEvidence(group, config)[ruleName]["64512"],
		"fixture did not record the evidence")

	require.NoError(t, store.FlushByGroup(group, config))
	require.Empty(t, store.TargetASNEvidence(group, config), "flushed evidence still backs claims")
}
