package smart

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type lifecycleExitProxy struct {
	C.Proxy
	probe func(context.Context) (*ExitProbeResult, error)
}

func (p lifecycleExitProxy) Name() string { return "exit-node" }

func (p lifecycleExitProxy) ExitProbe(ctx context.Context, _ bool) (*ExitProbeResult, error) {
	return p.probe(ctx)
}

func TestExitProbeParticipatesInOwnerShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	finished := make(chan struct{})
	watcher := NewExitWatcher(ExitWatcherOptions{
		BeginProbe: func() (func(), bool) {
			return func() { close(finished) }, true
		},
	})
	watcher.MaybeProbe(ctx, lifecycleExitProxy{probe: func(ctx context.Context) (*ExitProbeResult, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("exit probe did not start")
	}
	select {
	case <-finished:
		t.Fatal("shutdown barrier released while probe was running")
	default:
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled probe did not release shutdown barrier")
	}
	require.True(t, watcher.Due("exit-node", exitRegionTTL, exitProbeRetryGap, time.Now()), "owner cancellation must not mark the node failed")
}

func TestClosingOwnerRejectsExitProbe(t *testing.T) {
	watcher := NewExitWatcher(ExitWatcherOptions{
		BeginProbe: func() (func(), bool) { return nil, false },
	})
	watcher.MaybeProbe(context.Background(), lifecycleExitProxy{probe: func(context.Context) (*ExitProbeResult, error) {
		panic("closing owner started an exit probe")
	}})
	_, inflight := watcher.inflight.Load("exit-node")
	require.False(t, inflight, "rejected work must release its node slot")
}

func TestQueuedNodeStatePreservesHealthAndExitUpdates(t *testing.T) {
	openScanTestDB(t, 0)
	InitQueue()
	t.Cleanup(InitQueue)
	store := &Store{}
	watcher := NewExitWatcher(ExitWatcherOptions{Name: "group", Config: "config", Store: store})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 20 {
			store.UpdateNodeState("group", "config", "node", func(state *NodeState) {
				state.BlockedUntil = int64(i + 1)
				state.ThresholdGrade = 3
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := range 20 {
			watcher.storeExitState("node", ExitInfo{Region: "SG", ASN: "123", Key: "exit-key", Updated: int64(i + 1)})
		}
	}()
	wg.Wait()
	check := func() {
		raw, ok := store.NodeStateBytes("group", "config", "node")
		require.True(t, ok)
		var state NodeState
		require.NoError(t, json.Unmarshal(raw, &state))
		require.Equal(t, NodeState{Name: "node", BlockedUntil: 20, ThresholdGrade: 3, ExitRegion: "SG", ExitASN: "123", ExitKey: "exit-key", ExitUpdated: 20}, state)
	}
	check()
	store.FlushQueue(true)
	check()
}
