package smart

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAdjustCacheParametersConcurrentRecordCreation(t *testing.T) {
	InitCache()
	InitQueue()
	db = nil
	recordCache.Clear()

	originalTargetCache := targetCache
	originalUnwrapCache := unwrapCache
	originalRecordCache := recordCache
	originalDBResultCache := dbResultCache
	originalBlockedNodesCache := blockedNodesCache
	originalHostStatusCache := hostStatusCache

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			key := fmt.Sprintf("record-%d", i)
			_ = (&Store{}).GetOrCreateAtomicRecord(key, "group", "config", "target", key)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			globalCacheParams.mutex.Lock()
			globalCacheParams.LastMemoryUsage = 0
			globalCacheParams.mutex.Unlock()
			(&Store{}).AdjustCacheParameters()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		// Only a hang guard: the assertions below are what this test is about.
		// Keep the budget far above any plausible runtime so a slow CI runner
		// never turns this into a flake.
		t.Fatal("cache adjustment did not finish alongside record creation")
	}

	require.Same(t, originalTargetCache, targetCache)
	require.Same(t, originalUnwrapCache, unwrapCache)
	require.Same(t, originalRecordCache, recordCache)
	require.Same(t, originalDBResultCache, dbResultCache)
	require.Same(t, originalBlockedNodesCache, blockedNodesCache)
	require.Same(t, originalHostStatusCache, hostStatusCache)
}
