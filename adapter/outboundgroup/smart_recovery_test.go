package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func recoveryCandidates(count int) map[string]map[string]string {
	nodes := make(map[string]string, count)
	for i := 0; i < count; i++ {
		nodes[fmt.Sprintf("node-%03d", i)] = fmt.Sprintf("host-%03d.example", i)
	}
	return map[string]map[string]string{"*.example": nodes}
}

func TestHostRecoverySelectionIsBoundedAndFair(t *testing.T) {
	now := time.Now()
	s := &Smart{recoveryBackoff: make(map[string]hostRecoveryState)}
	s.lastTrafficActivity.Store(now.UnixNano())

	candidates := recoveryCandidates(20)
	first := s.selectHostRecoveryItems(candidates, nil, now)
	second := s.selectHostRecoveryItems(candidates, nil, now)
	if len(first) != hostRecoveryProbeBudget || len(second) != hostRecoveryProbeBudget {
		t.Fatalf("probe batches = %d and %d, want %d", len(first), len(second), hostRecoveryProbeBudget)
	}
	seen := make(map[string]struct{}, len(first))
	for _, item := range first {
		seen[item.key] = struct{}{}
	}
	for _, item := range second {
		if _, duplicate := seen[item.key]; duplicate {
			t.Fatalf("round-robin budget immediately repeated %q", item.key)
		}
	}
}

func TestHostRecoverySuppressesIdleAndBacksOffFailures(t *testing.T) {
	now := time.Now()
	s := &Smart{recoveryBackoff: make(map[string]hostRecoveryState)}
	candidates := recoveryCandidates(1)

	s.lastTrafficActivity.Store(now.Add(-hostRecoveryActiveWindow - time.Second).UnixNano())
	if got := s.selectHostRecoveryItems(candidates, nil, now); len(got) != 0 {
		t.Fatalf("idle group scheduled %d recovery probes", len(got))
	}

	s.lastTrafficActivity.Store(now.UnixNano())
	first := s.selectHostRecoveryItems(candidates, nil, now)
	if len(first) != 1 {
		t.Fatalf("active group scheduled %d probes, want 1", len(first))
	}
	s.recordHostRecoveryResult(first[0].key, false, now)

	nextCycle := now.Add(hostStatusCheckInterval + time.Second)
	s.lastTrafficActivity.Store(nextCycle.UnixNano())
	if got := s.selectHostRecoveryItems(candidates, nil, nextCycle); len(got) != 0 {
		t.Fatal("failed probe was retried on the next 30-minute maintenance cycle")
	}

	afterBackoff := now.Add(hostRecoveryBackoffBase + time.Second)
	s.lastTrafficActivity.Store(afterBackoff.UnixNano())
	if got := s.selectHostRecoveryItems(candidates, nil, afterBackoff); len(got) != 1 {
		t.Fatalf("probe did not become eligible after backoff: %d", len(got))
	}
}

func TestHostRecoveryStaleNodesDoNotConsumeBudget(t *testing.T) {
	now := time.Now()
	s := &Smart{recoveryBackoff: make(map[string]hostRecoveryState)}
	s.lastTrafficActivity.Store(now.UnixNano())

	nodes := make(map[string]string, 2*hostRecoveryProbeBudget)
	available := make(map[string]C.Proxy, hostRecoveryProbeBudget)
	for i := 0; i < hostRecoveryProbeBudget; i++ {
		nodes[fmt.Sprintf("stale-%03d", i)] = fmt.Sprintf("stale-%03d.example", i)
		name := fmt.Sprintf("live-%03d", i)
		nodes[name] = fmt.Sprintf("live-%03d.example", i)
		available[name] = nil
	}

	selected := s.selectHostRecoveryItems(map[string]map[string]string{"*.example": nodes}, available, now)
	if len(selected) != hostRecoveryProbeBudget {
		t.Fatalf("stale nodes consumed recovery budget: selected=%d, want %d", len(selected), hostRecoveryProbeBudget)
	}
	for _, item := range selected {
		if _, exists := available[item.nodeName]; !exists {
			t.Fatalf("stale node %q consumed recovery budget", item.nodeName)
		}
	}
}

type cancelAwareStatusProxy struct {
	strategyTestProxy
	started chan struct{}
}

func (p cancelAwareStatusProxy) StatusTest(ctx context.Context, _ string) (uint16, bool, error) {
	close(p.started)
	<-ctx.Done()
	return 0, false, ctx.Err()
}

func TestSmartStatusTestInheritsGroupCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Smart{ctx: ctx}
	proxy := cancelAwareStatusProxy{
		strategyTestProxy: strategyTestProxy{name: "probe"},
		started:           make(chan struct{}),
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := s.StatusTest(proxy, "example.com")
		result <- err
	}()

	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("status probe did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("status probe error=%v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("status probe outlived the smart group")
	}
}
