//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
)

func updatableInboundForTest(t *testing.T, providerTunnel *fakeRuleProviderTunnel, tags ...string) *Inbound {
	t.Helper()
	i := &Inbound{providerTunnel: providerTunnel, bypassRuleSetTags: tags}
	i.udpTimeout.Store(int64(300 * time.Second))
	i.bypassTUNDirect = true
	i.bypassPublisher = resolver.NewEBPFBypassPublisher()
	t.Cleanup(i.bypassPublisher.Close)
	i.bypassRuleSetAccess.Lock()
	err := i.refreshBypassCIDRsLocked()
	i.bypassRuleSetAccess.Unlock()
	if err != nil {
		t.Fatalf("seed bypass policy: %v", err)
	}
	return i
}

func updateOptions(tags []string, udpTimeout int64) LC.EBPF {
	return LC.EBPF{UDPTimeout: udpTimeout, BypassRuleSet: tags}
}

// The whole point of the in-place path: a changed udp-timeout reaches the
// running inbound instead of taking every kernel map with it on a rebuild.
func TestUpdateAppliesUDPTimeoutToTheSweeper(t *testing.T) {
	i := updatableInboundForTest(t, &fakeRuleProviderTunnel{})

	if err := i.Update(updateOptions(nil, 600)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := i.udpTimeoutValue(); got != 600*time.Second {
		t.Fatalf("udp timeout = %v, want 10m", got)
	}
	// The janitor paces itself at half the timeout, bounded at 30s, and reads
	// it each round -- a sweep still pacing off the value the process started
	// with would keep the old cadence for the rest of its life.
	if got := i.udpJanitorInterval(); got != 30*time.Second {
		t.Fatalf("janitor interval = %v, want 30s", got)
	}

	if err := i.Update(updateOptions(nil, 10)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := i.udpJanitorInterval(); got != 5*time.Second {
		t.Fatalf("janitor interval = %v, want 5s after lowering the timeout", got)
	}
}

func TestUpdateSwapsBypassRuleSetTagsAndRecompiles(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	added := netip.MustParsePrefix("192.168.0.0/16")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", china),
		"MetaCN":  newFakeIPCIDRRuleProvider(t, "MetaCN", added),
	}}
	i := updatableInboundForTest(t, providerTunnel, "ChinaIP")

	if err := i.Update(updateOptions([]string{"ChinaIP", "MetaCN"}, 300)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !slices.Equal(i.bypassRuleSetTags, []string{"ChinaIP", "MetaCN"}) {
		t.Fatalf("tags = %v after update", i.bypassRuleSetTags)
	}
	if !slices.Contains(i.bypassCIDR, added) {
		t.Fatalf("bypass policy = %v, want it to carry the added rule set's %v", i.bypassCIDR, added)
	}
	if !slices.Contains(i.bypassCIDR, china) {
		t.Fatalf("bypass policy = %v, want it to keep %v", i.bypassCIDR, china)
	}
}

// A tag the user just typed into this listener's own config is a typo, and
// starting with it silently missing is the failure New refuses outright. It is
// refused before anything is applied, so the inbound keeps running the config
// it had.
func TestUpdateRefusesAnUnknownRuleSetTagWithoutApplyingAnything(t *testing.T) {
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", netip.MustParsePrefix("10.0.0.0/8")),
	}}
	i := updatableInboundForTest(t, providerTunnel, "ChinaIP")

	err := i.Update(updateOptions([]string{"ChinaIP", "Typo"}, 600))
	if err == nil {
		t.Fatal("an unknown rule-set tag was accepted, so the listener silently bypasses less than configured")
	}
	if !slices.Equal(i.bypassRuleSetTags, []string{"ChinaIP"}) {
		t.Fatalf("tags = %v after a refused update", i.bypassRuleSetTags)
	}
	if got := i.udpTimeoutValue(); got != 300*time.Second {
		t.Fatalf("udp timeout = %v after a refused update, want the original 5m", got)
	}
}

// bypass-tun-direct decides whether a destination this inbound bypasses is
// connected directly when a TUN listener's auto-route claims it anyway, so the
// observable effect is what the resolver answers for such an address.
func TestUpdateRepublishesBypassTUNDirect(t *testing.T) {
	bypassed := netip.MustParseAddr("10.1.2.3")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", netip.MustParsePrefix("10.0.0.0/8")),
	}}
	i := updatableInboundForTest(t, providerTunnel, "ChinaIP")
	if !resolver.EBPFBypassedDirect(bypassed) {
		t.Fatal("fixture did not publish a bypassed destination as direct")
	}

	disabled := false
	options := updateOptions([]string{"ChinaIP"}, 300)
	options.BypassTUNDirect = &disabled
	if err := i.Update(options); err != nil {
		t.Fatalf("update: %v", err)
	}
	if resolver.EBPFBypassedDirect(bypassed) {
		t.Fatal("bypass-tun-direct was turned off but the resolver still reports the destination as direct")
	}

	enabled := true
	options.BypassTUNDirect = &enabled
	if err := i.Update(options); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !resolver.EBPFBypassedDirect(bypassed) {
		t.Fatal("bypass-tun-direct was turned back on but the resolver did not follow")
	}
}

// An option that did not move produces no steps at all, so a reload that
// touches one field does not silently rewrite the others.
func TestUpdateWithNothingChangedTouchesNothing(t *testing.T) {
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", netip.MustParsePrefix("10.0.0.0/8")),
	}}
	i := updatableInboundForTest(t, providerTunnel, "ChinaIP")
	before := slices.Clone(i.bypassCIDR)

	if err := i.Update(updateOptions([]string{"ChinaIP"}, 300)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := i.udpTimeoutValue(); got != 300*time.Second {
		t.Fatalf("udp timeout = %v, want it left alone", got)
	}
	if !slices.Equal(i.bypassCIDR, before) {
		t.Fatalf("bypass policy = %v, want %v", i.bypassCIDR, before)
	}
}

// Only the shared packet-rewrite plane sizes its bypass flow cache to the
// presence of a policy, and only at map creation. An inbound running it has to
// be rebuilt when the rule-set list crosses between empty and non-empty; one
// that is not running it has no such constraint and used to be rebuilt anyway,
// losing every kernel map for a limit it does not have.
func TestUpdateOnlyDemandsARebuildForThePlaneThatNeedsOne(t *testing.T) {
	china := netip.MustParsePrefix("10.0.0.0/8")
	providerTunnel := &fakeRuleProviderTunnel{providers: map[string]P.RuleProvider{
		"ChinaIP": newFakeIPCIDRRuleProvider(t, "ChinaIP", china),
	}}

	withoutShared := updatableInboundForTest(t, providerTunnel, "ChinaIP")
	if err := withoutShared.Update(updateOptions(nil, 300)); err != nil {
		t.Fatalf("an inbound with no shared packet-rewrite plane refused to empty its rule set: %v", err)
	}
	if len(withoutShared.bypassRuleSetTags) != 0 {
		t.Fatalf("tags = %v, want empty", withoutShared.bypassRuleSetTags)
	}

	withShared := updatableInboundForTest(t, providerTunnel, "ChinaIP")
	withShared.sharedRewrite = &sharedRewrite{}
	err := withShared.Update(updateOptions(nil, 300))
	if !errors.Is(err, ErrRebuildRequired) {
		t.Fatalf("update = %v, want a rebuild request", err)
	}
	if len(withShared.bypassRuleSetTags) != 1 {
		t.Fatalf("a refused update changed the tags to %v", withShared.bypassRuleSetTags)
	}
}
