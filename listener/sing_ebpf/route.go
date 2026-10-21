//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

var (
	redirectIPv4Candidates = []netip.Prefix{
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("127.64.0.0/10"),
	}
	redirectIPv6Candidates = []netip.Prefix{
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		netip.MustParsePrefix("fd53:696e:672d:6270::/64"),
	}
)

func (i *Inbound) requiresIPv6Redirect() bool {
	return (i.localCgroupEnabled() || i.sharedRewriteEnabled()) &&
		(i.cgroupIPv6Enabled() || i.sharedRewriteIPv6Enabled())
}

func (i *Inbound) selectRedirectPrefixes() error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return E.Cause(err, "find loopback interface")
	}
	i.redirectIPv4Prefix, err = selectRedirectPrefix(
		loopback.Attrs().Index,
		unix.AF_INET,
		redirectIPv4Candidates,
		i.fakeIPPrefixes(),
	)
	if err != nil {
		return E.Cause(err, "select internal IPv4 redirect prefix")
	}
	if i.requiresIPv6Redirect() {
		i.redirectIPv6Prefix, err = selectRedirectPrefix(
			loopback.Attrs().Index,
			unix.AF_INET6,
			redirectIPv6Candidates,
			i.fakeIPPrefixes(),
		)
		if err != nil {
			return E.Cause(err, "select internal IPv6 redirect prefix")
		}
	} else {
		i.redirectIPv6Prefix = netip.Prefix{}
	}
	return nil
}

func selectRedirectPrefix(
	loopbackIndex int,
	family int,
	candidates []netip.Prefix,
	excluded []netip.Prefix,
) (netip.Prefix, error) {
	var conflictErr error
	for _, candidate := range candidates {
		var excludedConflict netip.Prefix
		for _, prefix := range excluded {
			if prefixesOverlap(candidate, prefix) {
				excludedConflict = prefix
				break
			}
		}
		if excludedConflict.IsValid() {
			conflictErr = E.Errors(conflictErr, E.New(
				"eBPF redirect address ", candidate,
				" conflicts with FakeIP range ", excludedConflict,
			))
			continue
		}
		if err := checkRedirectRouteConflict(loopbackIndex, family, candidate); err != nil {
			conflictErr = E.Errors(conflictErr, err)
			continue
		}
		return candidate, nil
	}
	return netip.Prefix{}, conflictErr
}

func (i *Inbound) setupLocalRoutes() error {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.redirectIPv4Prefix)
	}
	if i.cgroupIPv6Enabled() || i.sharedRewriteIPv6Enabled() {
		if i.redirectIPv6Prefix.IsValid() {
			prefixes = append(prefixes, i.redirectIPv6Prefix)
		}
	}
	routes, err := newLocalRouteSet(prefixes)
	if err != nil {
		return err
	}
	i.localRoutes = routes
	_, err = routes.ReconcileInterfaceRoutes()
	return err
}

func (i *Inbound) removeLocalRoutes() error {
	err := i.localRoutes.Close()
	if i.localRoutes.IsClosed() {
		i.localRoutes = nil
	}
	return err
}

func candidateOverlapsInterface(candidate netip.Prefix) bool {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return false
	}
	family := unix.AF_INET
	if candidate.Addr().Is6() {
		family = unix.AF_INET6
	}
	return checkRedirectRouteConflict(loopback.Attrs().Index, family, candidate) != nil
}

func localRedirectCandidates() (netip.Prefix, error) {
	return netip.Prefix{}, nil
}
