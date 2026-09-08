package smart

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckHostStatusConcurrentUpdate(t *testing.T) {
	InitCache()
	InitQueue()
	db = nil
	hostStatusCache.Clear()
	dbResultCache.Clear()

	const (
		group          = "group"
		config         = "config"
		wildcardTarget = "example.com"
	)
	now := time.Now().Unix()
	initial := HostStatus{Codes: map[int]*CodeNodeSet{
		2: {
			Nodes:     map[string]int64{"node-0": now + int64(time.Hour.Seconds())},
			NodeHosts: map[string]string{"node-0": "example.com"},
		},
	}}
	data, err := json.Marshal(&initial)
	require.NoError(t, err)

	store := &Store{}
	store.AppendToGlobalQueue(StoreOperation{
		Type:   OpSaveHostFailures,
		Group:  group,
		Config: config,
		Target: wildcardTarget,
		Data:   data,
	})
	_, err = store.CheckHostStatus(group, config, 1_000)
	require.NoError(t, err)

	cachePath := FormatDBKey(KeyTypeHostFailures, config, group, wildcardTarget)
	cached, ok := hostStatusCache.Get(cachePath)
	require.True(t, ok)

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2_000; i++ {
			name := fmt.Sprintf("node-%d", i%64)
			cached.mu.Lock()
			codeSet := cached.Codes[2]
			codeSet.Nodes[name] = now + int64(time.Hour.Seconds())
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
