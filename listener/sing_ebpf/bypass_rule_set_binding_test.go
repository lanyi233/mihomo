//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"go4.org/netipx"
)

// fakeRuleProviderTunnel is the tunnel's rule-provider registry and nothing
// else. A config reload replaces the whole map, which is exactly what these
// tests reproduce by assigning a new one.
type fakeRuleProviderTunnel struct {
	providers map[string]P.RuleProvider
	callback  utils.Callback[P.RuleProvider]
}

func (t *fakeRuleProviderTunnel) Providers() map[string]P.ProxyProvider { return nil }

func (t *fakeRuleProviderTunnel) RuleProviders() map[string]P.RuleProvider { return t.providers }

func (t *fakeRuleProviderTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return &t.callback
}

// fakeIPCIDRStrategy is the only part of a rule set the bypass policy reads.
type fakeIPCIDRStrategy struct {
	set *netipx.IPSet
}

func (s fakeIPCIDRStrategy) ToIpCidr() *netipx.IPSet { return s.set }

type fakeIPCIDRRuleProvider struct {
	name     string
	strategy fakeIPCIDRStrategy
}

func newFakeIPCIDRRuleProvider(t *testing.T, name string, prefixes ...netip.Prefix) *fakeIPCIDRRuleProvider {
	t.Helper()
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build %s rule set: %v", name, err)
	}
	return &fakeIPCIDRRuleProvider{name: name, strategy: fakeIPCIDRStrategy{set: set}}
}

func (p *fakeIPCIDRRuleProvider) Name() string               { return p.name }
func (p *fakeIPCIDRRuleProvider) VehicleType() P.VehicleType { return P.Compatible }
func (p *fakeIPCIDRRuleProvider) Type() P.ProviderType       { return P.Rule }
func (p *fakeIPCIDRRuleProvider) Initial() error             { return nil }
func (p *fakeIPCIDRRuleProvider) Update() error              { return nil }
func (p *fakeIPCIDRRuleProvider) Behavior() P.RuleBehavior   { return P.IPCIDR }
func (p *fakeIPCIDRRuleProvider) Count() int                 { return 0 }
func (p *fakeIPCIDRRuleProvider) Strategy() any              { return p.strategy }

func (p *fakeIPCIDRRuleProvider) Match(*C.Metadata, C.RuleMatchHelper) bool { return false }

var _ P.RuleProvider = (*fakeIPCIDRRuleProvider)(nil)

func bypassInboundForTest(providerTunnel *fakeRuleProviderTunnel, tags ...string) *Inbound {
	return &Inbound{providerTunnel: providerTunnel, bypassRuleSetTags: tags}
}

func refreshBypassForTest(t *testing.T, i *Inbound) []netip.Prefix {
	t.Helper()
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		t.Fatalf("refresh bypass CIDRs: %v", err)
	}
	return slices.Clone(i.bypassCIDR)
}

// A config reload builds a whole new set of rule-provider objects and swaps the
// registry out from under everyone; the old objects are dropped and nothing
// refreshes them again. An inbound that resolved its tags once at startup would
// go on compiling the kernel bypass policy from those orphans, so the eBPF
// bypass silently stops tracking the rule set after the first reload. Resolving
// by name on every refresh is what keeps the two in step.
func TestBypassRuleSetFollowsAReloadedRuleProvider(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	replaced := netip.MustParsePrefix("192.168.0.0/16")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", china),
	}}
	i := bypassInboundForTest(providerTunnel, "ChinaIP")

	if got := refreshBypassForTest(t, i); !slices.Contains(got, china) {
		t.Fatalf("first refresh = %v, want it to contain %v", got, china)
	}

	// The reload: same tag, brand new provider object, different content.
	providerTunnel.providers = map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", replaced),
	}
	got := refreshBypassForTest(t, i)
	if !slices.Contains(got, replaced) {
		t.Fatalf("refresh after reload = %v, want it to contain %v", got, replaced)
	}
	if slices.Contains(got, china) {
		t.Fatalf("refresh after reload = %v, still carries the dropped provider's %v", got, china)
	}
}

// A tag can stop resolving without this listener's own config changing: the
// user removes the rule-provider and leaves bypass-rule-set alone. Failing the
// refresh would pin the kernel to the policy it already had and hand the
// retry scheduler a failure it can never clear, so the vanished tag is dropped
// and the rest of the policy is still installed.
func TestBypassRuleSetSkipsATagThatNoLongerResolves(t *testing.T) {
	kept := netip.MustParsePrefix("10.0.0.0/8")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", kept),
	}}
	i := bypassInboundForTest(providerTunnel, "ChinaIP", "Removed")

	got := refreshBypassForTest(t, i)
	if !slices.Contains(got, kept) {
		t.Fatalf("refresh = %v, want the surviving rule set's %v", got, kept)
	}
}

// Every tag vanishing is not an error either -- it is a policy of nothing --
// but it must actually compile to nothing rather than leaving the previous
// prefixes in place.
func TestBypassRuleSetClearsWhenEveryTagVanishes(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", china),
	}}
	i := bypassInboundForTest(providerTunnel, "ChinaIP")
	if got := refreshBypassForTest(t, i); !slices.Contains(got, china) {
		t.Fatalf("first refresh = %v, want it to contain %v", got, china)
	}

	providerTunnel.providers = map[string]P.RuleProvider{}
	if got := refreshBypassForTest(t, i); len(got) != 0 {
		t.Fatalf("refresh with no resolvable tag = %v, want empty", got)
	}
	if i.dnsBypassSet != nil && len(i.dnsBypassSet.Prefixes()) != 0 {
		t.Fatalf("DNS bypass set kept %v after every tag vanished", i.dnsBypassSet.Prefixes())
	}
}

// The rule-update callback is registered on the tunnel, so every rule provider
// in the config reaches it. Recompiling for providers this listener does not
// bypass is pure waste -- and not a little of it, since each recompile
// re-collects every tag's prefixes, rebuilds two IPSets and recomputes the
// coexistence union across all publishers, under the policy lock.
func TestBypassRuleSetRefreshesOnlyForItsOwnRuleSets(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	replaced := netip.MustParsePrefix("192.168.0.0/16")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", china),
	}}
	i := bypassInboundForTest(providerTunnel, "ChinaIP")
	i.bypassRuleSetStarted = true
	if got := refreshBypassForTest(t, i); !slices.Contains(got, china) {
		t.Fatalf("first refresh = %v, want %v", got, china)
	}

	// Content moves, so any recompile is observable.
	providerTunnel.providers["ChinaIP"] = newFakeIPCIDRRuleProvider(t, "ChinaIP", replaced)

	i.updateBypassRuleSet(newFakeIPCIDRRuleProvider(t, "SomeOtherRuleSet"))
	if slices.Contains(i.bypassCIDR, replaced) {
		t.Fatal("a rule set this listener does not bypass triggered a full policy recompile")
	}

	i.updateBypassRuleSet(providerTunnel.providers["ChinaIP"])
	if !slices.Contains(i.bypassCIDR, replaced) {
		t.Fatalf("bypass policy = %v, want the updated rule set's %v", i.bypassCIDR, replaced)
	}
}
