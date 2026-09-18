//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"
)

// A fake-ip range change is driven by the DNS config, which will not change
// again just because one backend refused the write. Without a retry the planes
// disagree permanently: a plane still forcing interception on the old range
// lets the new fake addresses fall through to the bypass policy, and a fake
// address that is bypassed has no routable meaning at all.
//
// Rolling back instead -- what the bypass policy does -- would be wrong here.
// It moves away from the goal: every plane would agree on ranges the DNS pool
// has already left, so no fake address is force-intercepted anywhere. The
// bypass policy had no driver that would ever ask again; this one does.
func TestFakeIPRangeFailureSchedulesARetryAndClearsOnSuccess(t *testing.T) {
	i := &Inbound{}

	// Nothing pending: the scheduler hook costs a lock and a boolean.
	if got := i.retryFakeIPRangesIfNeeded(); got != tcSharedRewriteSettled {
		t.Fatalf("outcome with nothing pending = %v, want settled", got)
	}

	i.noteFakeIPRangeOutcome(false)
	i.policyAccess.RLock()
	pending := i.fakeIPRangeNeedsRetry
	i.policyAccess.RUnlock()
	if !pending {
		t.Fatal("a backend refused the ranges and nothing was scheduled to try again")
	}

	// With no live backend left, applying trivially succeeds and the flag clears.
	if got := i.retryFakeIPRangesIfNeeded(); got != tcSharedRewriteSettled {
		t.Fatalf("retry outcome = %v, want settled", got)
	}
	i.policyAccess.RLock()
	pending = i.fakeIPRangeNeedsRetry
	i.policyAccess.RUnlock()
	if pending {
		t.Fatal("a successful retry left the inbound asking for another one forever")
	}
}

// Every backend is attempted even after one fails: they hold independent
// copies, so two of three is strictly better than one, and the retry picks up
// whatever is left.
func TestApplyFakeIPRangesReportsCompletionWithNoBackends(t *testing.T) {
	i := &Inbound{}
	if !i.applyFakeIPRanges(i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix) {
		t.Fatal("an inbound with no live backend reported an incomplete apply")
	}
}
