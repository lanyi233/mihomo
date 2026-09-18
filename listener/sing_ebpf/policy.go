//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"slices"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

type toIpCidr interface {
	ToIpCidr() *netipx.IPSet
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	if i.providerTunnel == nil {
		return E.New("tunnel does not expose rule providers")
	}
	i.bypassRuleSetCallback = i.providerTunnel.RuleUpdateCallback().Register(i.updateBypassRuleSet)
	i.bypassRuleSetStarted = true
	err := i.refreshBypassCIDRsLocked()
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	if i.bypassRuleSetCallback != nil {
		_ = i.bypassRuleSetCallback.Close()
		i.bypassRuleSetCallback = nil
	}
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(ruleProvider P.RuleProvider) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	// The callback is registered on the tunnel, so it fires for every rule
	// provider in the config -- not only the ones this listener bypasses. A
	// config with forty providers recompiled the whole policy forty times to
	// reach the same answer thirty-eight of them: every tag's prefixes
	// re-collected (tens of thousands for a CN list), two IPSets rebuilt, the
	// coexistence union recomputed for every publisher, all under this lock.
	// Worst at startup, where every provider's first fetch lands at once and
	// each callback queues here. sing_tun's equivalent filters by name the same
	// way. A nil provider is not something Emit produces, but refreshing is the
	// safe answer if it ever did.
	if ruleProvider != nil && !slices.Contains(i.bypassRuleSetTags, ruleProvider.Name()) {
		return
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		// Logged regardless of which data planes are running: a cgroup-only or
		// shared-only inbound used to fail here in complete silence.
		log.Errorln("[EBPF] refresh eBPF bypass_rule_set; keeping previous policy: %s", err.Error())
		// A rule-provider update is the only thing that would otherwise ever
		// ask for this refresh again: nothing about this rule set is
		// guaranteed to change a second time, so a transient failure here
		// sticks until a restart. Hand it to the interface-update scheduler,
		// which owns the backoff, and wake it now -- setting the flag alone
		// would leave the first retry waiting on a netlink event or the drift
		// check (tcDriftCheckInterval, ten minutes) instead of the seconds
		// every other TC failure gets.
		i.bypassRuleSetNeedsRetry = true
		i.notifyTCInterfaceUpdate()
		return
	}
	i.bypassRuleSetNeedsRetry = false
}

// retryBypassRuleSetIfNeeded is updateTCInterfaces' hook into the
// bypass_rule_set half of this file: it does nothing, and reports settled,
// unless a previous refresh actually failed, so a healthy bypass_rule_set
// costs a round nothing beyond the lock and a boolean check.
func (i *Inbound) retryBypassRuleSetIfNeeded() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return tcSharedRewriteSettled
	}
	if i.bypassRuleSetBackendRequiresRebuildLocked() {
		i.bypassRuleSetNeedsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !i.bypassRuleSetNeedsRetry {
		return tcSharedRewriteSettled
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		i.interfaceWarnings.bypassRuleSet.warn(i.logWarn, "retry TC eBPF bypass_rule_set refresh: ", err)
		if i.bypassRuleSetBackendRequiresRebuildLocked() {
			i.bypassRuleSetNeedsRetry = false
			return tcSharedRewriteUnrecoverable
		}
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

// bypassRuleSetBackendRequiresRebuildLocked reports whether any backend a
// refresh would have to write the compiled policy into has already been
// invalidated by a failed rollback of its own. Every write to such a backend is
// refused from then on, so repeating the refresh cannot succeed.
func (i *Inbound) bypassRuleSetBackendRequiresRebuildLocked() bool {
	if i.tcBackend().RequiresRebuild() {
		return true
	}
	if i.cgroupBackendInstance().RequiresRebuild() {
		return true
	}
	if i.sharedRewrite != nil && i.sharedRewrite.sharedBackendInstance().RequiresRebuild() {
		return true
	}
	return false
}

// sharedRewriteBackend is the shared packet-rewrite backend, or nil when that
// data plane is not running.
func (i *Inbound) sharedRewriteBackend() *ECommon.SharedNetworkBackend {
	if i.sharedRewrite == nil {
		return nil
	}
	return i.sharedRewrite.sharedBackendInstance()
}

// bypassRuleSetPrefixesLocked resolves the configured tags against the
// tunnel's registry as it stands right now, and collects the CIDRs they carry.
//
// A tag that no longer resolves is dropped rather than failing the refresh: a
// user can remove a rule-provider without touching this listener's own config,
// and the honest kernel policy for a rule set that is gone is one without it.
// Failing instead would pin the kernel to the policy it already had and hand
// the retry scheduler a failure that retrying can never clear.
func (i *Inbound) bypassRuleSetPrefixesLocked() []netip.Prefix {
	if len(i.bypassRuleSetTags) == 0 {
		return nil
	}
	var providers map[string]P.RuleProvider
	if i.providerTunnel != nil {
		providers = i.providerTunnel.RuleProviders()
	}
	var prefixes []netip.Prefix
	var missing []string
	for _, ruleSetTag := range i.bypassRuleSetTags {
		ruleSet, loaded := providers[ruleSetTag]
		if !loaded {
			missing = append(missing, ruleSetTag)
			continue
		}
		strategy := ruleSet.Strategy()
		ipCidrStrategy, ok := strategy.(toIpCidr)
		if !ok {
			continue
		}
		ipSet := ipCidrStrategy.ToIpCidr()
		if ipSet == nil {
			continue
		}
		prefixes = append(prefixes, ipSet.Prefixes()...)
	}
	if len(missing) > 0 {
		i.bypassRuleSetMissing.warn(i.logWarn,
			"[EBPF] bypass_rule_set is not a registered rule-set and is no longer bypassed:",
			joinStringList(missing))
	}
	return prefixes
}

func (i *Inbound) refreshBypassCIDRsLocked() error {
	prefixes := i.bypassRuleSetPrefixesLocked()
	if conflicts := i.fakeIPBypassConflictCount(prefixes); conflicts > 0 {
		log.Warnln("[EBPF] FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=%d", conflicts)
	}
	policy, err := ECommon.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return err
	}
	// One policy has to reach every data plane or none of them. Applying in
	// sequence and returning on the first error leaves the planes disagreeing
	// about what to bypass -- TC proxying a CIDR cgroup lets past, or the
	// reverse -- silently and permanently, since nothing revisits a rule set
	// that did not change again. So each write records how to undo itself, and
	// a failure puts the previous policy back before reporting.
	previousPolicy := i.bypassRuleSetPolicy
	var steps []reversibleStep
	if backend := i.tcBackend(); backend != nil {
		steps = append(steps, reversibleStep{
			name:   "TC bypass policy",
			apply:  func() error { _, applyErr := backend.UpdateCompiledBypassCIDR(policy); return applyErr },
			revert: func() error { _, undoErr := backend.UpdateCompiledBypassCIDR(previousPolicy); return undoErr },
		})
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		previousIPv4, previousIPv6 := backend.BypassCIDRCount()
		steps = append(steps, reversibleStep{
			name:   "cgroup bypass policy",
			apply:  func() error { _, applyErr := backend.UpdateCompiledBypassCIDR(policy); return applyErr },
			revert: func() error { _, undoErr := backend.UpdateCompiledBypassCIDR(previousPolicy); return undoErr },
		})
		if shared := i.sharedRewriteBackend(); shared != nil {
			steps = append(steps, reversibleStep{
				name: "shared packet-rewrite bypass policy",
				// The shared plane mirrors the cgroup's counts rather than
				// compiling its own copy, so this reads them after the cgroup
				// step has installed the new policy.
				apply: func() error {
					ipv4Count, ipv6Count := backend.BypassCIDRCount()
					return shared.SetBypassCIDRState(ipv4Count, ipv6Count)
				},
				revert: func() error { return shared.SetBypassCIDRState(previousIPv4, previousIPv6) },
			})
		}
	} else if shared := i.sharedRewriteBackend(); shared != nil {
		steps = append(steps, reversibleStep{
			name:   "shared packet-rewrite bypass policy",
			apply:  func() error { _, applyErr := shared.UpdateCompiledBypassCIDR(policy); return applyErr },
			revert: func() error { _, undoErr := shared.UpdateCompiledBypassCIDR(previousPolicy); return undoErr },
		})
	}

	// Committed only once every plane has it. No step reads these fields -- the
	// revert closures captured previousPolicy above -- and every reader holds
	// the lock this function is called with, so there is nothing to restore on
	// failure if nothing was published in the first place.
	if err = applyReversibleSteps(steps); err != nil {
		return err
	}
	i.bypassRuleSetPolicy = policy
	i.bypassCIDR = policy.Prefixes()
	// Recompute the set the DNS fake-ip middleware consults, so domains whose
	// real addresses fall inside it keep their real IP and the kernel eBPF
	// bypass can engage. Only bypass_rule_set feeds it; publishing the private
	// ranges here would make every A/AAAA query resolve for real before
	// fake-ip could answer it. The registry unions it with the other inbounds'
	// sets and drops this inbound's share when it closes.
	i.dnsBypassSet = nil
	if len(i.bypassRuleSetTags) > 0 {
		var builder netipx.IPSetBuilder
		for _, prefix := range i.bypassCIDR {
			builder.AddPrefix(prefix)
		}
		if bypassSet, buildErr := builder.IPSet(); buildErr == nil {
			i.dnsBypassSet = bypassSet
		}
	}
	i.publishBypassPolicyLocked()
	return nil
}
