//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
)

var (
	fakeIPSafetyIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
	}
	fakeIPSafetyIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::ff00:0:0/104"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// normalizeFakeIPPrefixPair masks both ranges and rejects one that lands in
// the address space the programs bypass unconditionally: a fake address there
// could never be intercepted, so the pool would be silently useless.
func normalizeFakeIPPrefixPair(ipv4 netip.Prefix, ipv6 netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	ipv4, err := normalizeFakeIPPrefix("IPv4", ipv4, true, fakeIPSafetyIPv4Prefixes)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	ipv6, err = normalizeFakeIPPrefix("IPv6", ipv6, false, fakeIPSafetyIPv6Prefixes)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	return ipv4, ipv6, nil
}

func normalizeFakeIPPrefix(name string, prefix netip.Prefix, ipv4 bool, safety []netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, nil
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() != ipv4 || prefix.Addr().Is4In6() {
		return netip.Prefix{}, E.New("invalid ", name, " FakeIP range for eBPF inbound: ", prefix)
	}
	for _, safetyPrefix := range safety {
		if prefixesOverlap(prefix, safetyPrefix) {
			return netip.Prefix{}, E.New(
				name, " FakeIP range ", prefix,
				" overlaps mandatory eBPF safety bypass ", safetyPrefix,
			)
		}
	}
	return prefix, nil
}

func (i *Inbound) normalizeFakeIPPrefixes() error {
	ipv4, ipv6, err := normalizeFakeIPPrefixPair(i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix)
	if err != nil {
		return err
	}
	i.fakeIPIPv4Prefix = ipv4
	i.fakeIPIPv6Prefix = ipv6
	return nil
}

// fakeIPPrefixes returns the active ranges. The runtime update below rewrites
// them under policyAccess, so readers outside New take the read lock.
func (i *Inbound) fakeIPPrefixes() []netip.Prefix {
	i.policyAccess.RLock()
	defer i.policyAccess.RUnlock()
	return i.fakeIPPrefixesLocked()
}

func (i *Inbound) fakeIPPrefixesLocked() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.fakeIPIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.fakeIPIPv4Prefix)
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		prefixes = append(prefixes, i.fakeIPIPv6Prefix)
	}
	return prefixes
}

func (i *Inbound) fakeIPBypassConflictCount(prefixes []netip.Prefix) int {
	var conflicts int
	for _, fakeIPPrefix := range i.fakeIPPrefixes() {
		for _, bypassPrefix := range prefixes {
			if prefixesOverlap(fakeIPPrefix, bypassPrefix) {
				conflicts++
			}
		}
	}
	return conflicts
}

func prefixesOverlap(left netip.Prefix, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	left = left.Masked()
	right = right.Masked()
	if left.Addr().Is4() != right.Addr().Is4() {
		return false
	}
	if left.Bits() <= right.Bits() {
		return left.Contains(right.Addr())
	}
	return right.Contains(left.Addr())
}

// The fake-ip ranges have to reach the kernel policy, not just the tunnel: a
// fake address carries no routable meaning, so it must be intercepted even when
// the destination would otherwise be bypassed. mihomo maps it back to its
// domain only once the flow reaches the tunnel, so a bypassed fake address is a
// dead end.
//
// The ranges are compiled into the policy when the inbound starts, but they
// come from the DNS section, which a config reload can change while the
// listener itself stays untouched. The observer below keeps a running inbound
// in step: it recompiles the policy snapshot, so a backend created later (a
// hotspot interface that appears after the reload, say) is built with the new
// ranges, and pushes the ranges into every backend that is already live.
func (i *Inbound) startFakeIPTracking() {
	i.fakeIPRangeRemove = resolver.RegisterFakeIPRangeObserver(i.updateFakeIPRanges)
	// Register first, then read: a change published between the two is applied
	// twice rather than lost.
	i.updateFakeIPRanges(resolver.FakeIPRanges())
}

func (i *Inbound) stopFakeIPTracking() {
	if i.fakeIPRangeRemove == nil {
		return
	}
	i.fakeIPRangeRemove()
	i.fakeIPRangeRemove = nil
}

func (i *Inbound) updateFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) {
	ipv4, ipv6, err := normalizeFakeIPPrefixPair(ipv4, ipv6)
	if err != nil {
		log.Warnln("[EBPF] fake-ip range update ignored, the inbound keeps its current ranges: %s", err.Error())
		return
	}
	// The redirect prefixes were chosen to stay clear of the fake-ip ranges
	// that existed at start. A range moved on top of one would make the
	// program force-intercept its own redirect addresses.
	for _, redirect := range []netip.Prefix{i.redirectIPv4Prefix, i.redirectIPv6Prefix} {
		for _, fakeIP := range []netip.Prefix{ipv4, ipv6} {
			if prefixesOverlap(redirect, fakeIP) {
				log.Warnln("[EBPF] fake-ip range %s overlaps the eBPF redirect address %s; restart the inbound to apply it", fakeIP, redirect)
				return
			}
		}
	}
	i.policyAccess.Lock()
	if ipv4 == i.fakeIPIPv4Prefix && ipv6 == i.fakeIPIPv6Prefix {
		i.policyAccess.Unlock()
		return
	}
	previousIPv4, previousIPv6 := i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix
	i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix = ipv4, ipv6
	if err = i.compilePolicyLocked(); err != nil {
		i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix = previousIPv4, previousIPv6
		i.policyAccess.Unlock()
		log.Warnln("[EBPF] recompile policy for fake-ip ranges ipv4=%s, ipv6=%s: %s",
			fakeIPRangeText(ipv4), fakeIPRangeText(ipv6), err.Error())
		return
	}
	i.policyAccess.Unlock()
	i.applyFakeIPRanges(ipv4, ipv6)
}

// applyFakeIPRanges pushes the ranges into every backend that is live. A
// backend that does not exist yet picks them up from the recompiled policy.
func (i *Inbound) applyFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) {
	if backend := i.cgroupBackendInstance(); backend != nil {
		changed, err := backend.SetFakeIPRanges(ipv4, ipv6)
		logFakeIPRangeUpdate("local cgroup", ipv4, ipv6, changed, err)
	}
	if backend := i.tcBackend(); backend != nil {
		changed, err := backend.SetFakeIPRanges(ipv4, ipv6)
		logFakeIPRangeUpdate("TC", ipv4, ipv6, changed, err)
	}
	if shared := i.sharedRewrite; shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil && !backend.IsClosed() {
			changed, err := backend.SetFakeIPRanges(ipv4, ipv6)
			logFakeIPRangeUpdate("shared packet-rewrite", ipv4, ipv6, changed, err)
		}
	}
}

func logFakeIPRangeUpdate(scope string, ipv4 netip.Prefix, ipv6 netip.Prefix, changed bool, err error) {
	switch {
	case err != nil:
		log.Warnln("[EBPF] update %s fake-ip ranges: %s", scope, err.Error())
	case changed:
		log.Infoln("[EBPF] %s fake-ip ranges: ipv4=%s, ipv6=%s", scope, fakeIPRangeText(ipv4), fakeIPRangeText(ipv6))
	}
}

func fakeIPRangeText(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return "off"
	}
	return prefix.String()
}
