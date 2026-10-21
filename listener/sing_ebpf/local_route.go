//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"

	"golang.org/x/sys/unix"
)

// localRouteSet owns the local-table routes created for redirect token
// prefixes. Existing unmarked routes are preserved; marked interface routes
// left by a previous instance may be adopted by reconciliation.
type localRouteSet struct {
	access   sync.Mutex
	prefixes []netip.Prefix
	routes   []netlink.Route
	// interfaceRoutes are the per-interface routes ReconcileInterfaceRoutes
	// installed, keyed by prefix and interface.
	interfaceRoutes map[localInterfaceRouteKey]localInterfaceRoute
	closing         bool
}

type localInterfaceRouteKey struct {
	prefix    netip.Prefix
	linkIndex int
}

// The kernel replaces routes by prefix and priority, even across output
// interfaces. Remember foreign slots so reconciliation cannot take them over.
type localInterfaceRouteSlot struct {
	prefix   netip.Prefix
	priority uint32
}

// localRouteProtocol marks the routes ReconcileInterfaceRoutes installs
// (rtm_protocol 83, unassigned in iproute2's rt_protos), so prefix selection
// and later reconciliation can tell them apart from anyone else's routes.
const localRouteProtocol netlink.RouteProtocol = 83

// localRouteInterfacePriorityBase orders a prefix's interface routes after its
// loopback route, so a lookup without a required output interface keeps using
// the loopback route. Each interface route takes the base plus its interface
// index: a unique priority keeps every interface's route a separate entry
// rather than one replacing another.
const localRouteInterfacePriorityBase = 0x53000000

// newLocalRouteSet installs local-table routes for prefixes and returns their
// owner. On failure it removes every route installed by this call.
func newLocalRouteSet(prefixes []netip.Prefix) (*localRouteSet, error) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback interface")
	}
	set := &localRouteSet{routes: make([]netlink.Route, 0, len(prefixes))}
	for _, prefix := range prefixes {
		set.prefixes = append(set.prefixes, prefix.Masked())
		route, owned, routeErr := addLocalRoute(loopback.Attrs().Index, prefix)
		if routeErr != nil {
			return nil, E.Errors(routeErr, set.Close())
		}
		if owned {
			set.routes = append(set.routes, route)
		}
	}
	return set, nil
}

// ReconcileInterfaceRoutes installs each prefix as a local route on every
// interface that is up and carries an address of the prefix's family, and
// removes the routes it installed for interfaces that no longer qualify. It
// reports whether any route changed.
//
// A socket bound to an interface (SO_BINDTODEVICE, IP_UNICAST_IF or
// IPV6_UNICAST_IF, as systemd-resolved binds the sockets for its DNS servers)
// routes with that interface as the required output device, and the kernel
// skips every route whose next hop is another device, the prefix's loopback
// route included. A connection a cgroup program redirected into the prefix
// would follow the default route out of the interface instead of reaching the
// listener. The interface route keeps the lookup local, and its source address,
// one of the interface's own, brings the listener's replies back on the
// interface the socket is bound to, so the socket accepts them.
//
// An IPv4 prefix is otherwise covered only by the kernel's 127.0.0.0/8 loopback
// route, which the more specific interface routes would take over; the set
// therefore also installs the prefix on the loopback interface, ahead of them,
// so sockets without a bound interface keep 127.0.0.1 as their source.
//
// The kernel deletes a route together with its source address, so this must
// run again whenever interfaces or addresses change.
func (s *localRouteSet) ReconcileInterfaceRoutes() (bool, error) {
	if s == nil {
		return false, nil
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closing || len(s.prefixes) == 0 {
		return false, nil
	}
	desired, err := desiredLocalInterfaceRoutes(s.prefixes)
	if err != nil {
		return false, err
	}
	current, foreign, err := listLocalInterfaceRouteState(s.prefixes)
	if err != nil {
		return false, err
	}
	if s.interfaceRoutes == nil {
		s.interfaceRoutes = make(map[localInterfaceRouteKey]localInterfaceRoute)
	}
	changed := false
	var routeErr error
	for key, route := range s.interfaceRoutes {
		if _, wanted := desired[key]; wanted {
			continue
		}
		if err = deleteLocalInterfaceRoute(route); err != nil {
			routeErr = E.Errors(routeErr, E.Cause(err, "remove local route for ", key.prefix, " from interface ", key.linkIndex))
			continue
		}
		delete(s.interfaceRoutes, key)
		changed = true
	}
	for key, route := range desired {
		if existing, present := foreign[localInterfaceRouteSlot{route.prefix, route.priority}]; present {
			if route.priority == 0 && existing.Type == unix.RTN_LOCAL && existing.LinkIndex == route.linkIndex {
				// Preserve an exact loopback route supplied by the operator.
				// It already keeps unbound sockets ahead of the interface routes.
				delete(s.interfaceRoutes, key)
				continue
			}
			routeErr = E.Errors(routeErr, E.New("eBPF redirect route for ", key.prefix,
				" conflicts with an existing route at priority ", route.priority))
			continue
		}
		installed, present := current[key]
		if present && installed == route {
			// A matching route left by an instance that did not shut down is
			// adopted, so Close removes it.
			s.interfaceRoutes[key] = route
			continue
		}
		if err = writeLocalInterfaceRoute(route, present && installed.priority == route.priority); err != nil {
			routeErr = E.Errors(routeErr, E.Cause(err, "add local route for ", key.prefix, " on interface ", key.linkIndex))
			continue
		}
		s.interfaceRoutes[key] = route
		changed = true
	}
	return changed, routeErr
}

// localInterfaceRoute is a local-table route of a redirect prefix through one
// interface, with that interface's address as the preferred source.
type localInterfaceRoute struct {
	prefix    netip.Prefix
	linkIndex int
	source    netip.Addr
	priority  uint32
}

// desiredLocalInterfaceRoutes returns the interface routes prefixes need on
// the interfaces present now, with each interface's preferred address of the
// prefix's family as the source. An interface without one has no use for the
// route: a socket bound to it cannot send that family anyway.
func desiredLocalInterfaceRoutes(prefixes []netip.Prefix) (map[localInterfaceRouteKey]localInterfaceRoute, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for eBPF redirect routes")
	}
	loopbackIndex := 0
	upLinks := make(map[int]bool, len(links))
	for _, link := range links {
		attributes := link.Attrs()
		if attributes.Flags&net.FlagLoopback != 0 {
			loopbackIndex = attributes.Index
			continue
		}
		if attributes.Flags&net.FlagUp != 0 {
			upLinks[attributes.Index] = true
		}
	}
	if loopbackIndex == 0 {
		return nil, E.New("find loopback interface for eBPF redirect routes")
	}
	sources := make(map[int]map[int]netip.Addr, 2)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		addresses, listErr := netlink.AddrList(nil, family)
		if listErr != nil {
			return nil, E.Cause(listErr, "list interface addresses for eBPF redirect routes")
		}
		preferred := make(map[int]netlink.Addr)
		for _, address := range addresses {
			if !upLinks[address.LinkIndex] {
				continue
			}
			if _, usable := localInterfaceRouteSource(address); !usable {
				continue
			}
			if existing, loaded := preferred[address.LinkIndex]; loaded &&
				!localInterfaceRouteSourcePreferred(address, existing) {
				continue
			}
			preferred[address.LinkIndex] = address
		}
		familySources := make(map[int]netip.Addr, len(preferred))
		for linkIndex, address := range preferred {
			familySources[linkIndex], _ = localInterfaceRouteSource(address)
		}
		sources[family] = familySources
	}
	desired := make(map[localInterfaceRouteKey]localInterfaceRoute)
	for _, prefix := range prefixes {
		family := candidateFamily(prefix)
		if family == unix.AF_UNSPEC {
			continue
		}
		if family == unix.AF_INET {
			desired[localInterfaceRouteKey{prefix: prefix, linkIndex: loopbackIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: loopbackIndex,
				source:    netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			}
		}
		for linkIndex, source := range sources[family] {
			desired[localInterfaceRouteKey{prefix: prefix, linkIndex: linkIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: linkIndex,
				source:    source,
				priority:  localRouteInterfacePriorityBase + uint32(linkIndex),
			}
		}
	}
	return desired, nil
}

// localInterfaceRouteSource returns address as an interface route's source if
// it can be one: an IPv4 interface's primary address, or an IPv6 address of
// global scope (which includes unique local addresses) that finished duplicate
// address detection. A link-local IPv6 address cannot address a reply without
// a zone.
func localInterfaceRouteSource(address netlink.Addr) (netip.Addr, bool) {
	if address.IPNet == nil {
		return netip.Addr{}, false
	}
	ip, loaded := netip.AddrFromSlice(address.IP)
	if !loaded {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	if ip.Is4() {
		return ip, address.Flags&unix.IFA_F_SECONDARY == 0
	}
	if address.Scope != unix.RT_SCOPE_UNIVERSE || ip.IsLinkLocalUnicast() ||
		address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
		return netip.Addr{}, false
	}
	return ip, true
}

// localInterfaceRouteSourcePreferred reports whether candidate is a better
// source than current: an address still preferred for new connections beats a
// deprecated one, and otherwise the address the kernel lists first is kept.
func localInterfaceRouteSourcePreferred(candidate netlink.Addr, current netlink.Addr) bool {
	return current.Flags&unix.IFA_F_DEPRECATED != 0 && candidate.Flags&unix.IFA_F_DEPRECATED == 0
}

// listLocalInterfaceRoutes returns the local-table routes for prefixes that
// carry localRouteProtocol, whoever installed them.
func listLocalInterfaceRoutes(prefixes []netip.Prefix) (map[localInterfaceRouteKey]localInterfaceRoute, error) {
	current, _, err := listLocalInterfaceRouteState(prefixes)
	return current, err
}

func listLocalInterfaceRouteState(prefixes []netip.Prefix) (map[localInterfaceRouteKey]localInterfaceRoute, map[localInterfaceRouteSlot]netlink.Route, error) {
	current := make(map[localInterfaceRouteKey]localInterfaceRoute)
	foreign := make(map[localInterfaceRouteSlot]netlink.Route)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: unix.RT_TABLE_LOCAL},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return nil, nil, E.Cause(err, "list eBPF redirect interface routes")
		}
		for _, route := range routes {
			prefix, loaded := prefixFromIPNet(route.Dst)
			if !loaded || !slices.Contains(prefixes, prefix) {
				continue
			}
			if route.Protocol != localRouteProtocol || route.Type != unix.RTN_LOCAL {
				foreign[localInterfaceRouteSlot{prefix, uint32(route.Priority)}] = route
				continue
			}
			var source netip.Addr
			if route.Src != nil {
				source, _ = netip.AddrFromSlice(route.Src)
				source = source.Unmap()
			}
			current[localInterfaceRouteKey{prefix: prefix, linkIndex: route.LinkIndex}] = localInterfaceRoute{
				prefix:    prefix,
				linkIndex: route.LinkIndex,
				source:    source,
				priority:  uint32(route.Priority),
			}
		}
	}
	return current, foreign, nil
}

// replaceLocalInterfaceRoute installs route in place of any route of the same
// prefix and priority. The request is built here because the netlink package
// also sets the source prefix length from a route's source address, which
// would make an IPv6 route source-specific; only RTA_PREFSRC is wanted.
func replaceLocalInterfaceRoute(route localInterfaceRoute) error {
	return writeLocalInterfaceRoute(route, true)
}

func writeLocalInterfaceRoute(route localInterfaceRoute, replace bool) error {
	family := candidateFamily(route.prefix)
	if family == unix.AF_UNSPEC || !route.source.IsValid() || route.source.Is4() != route.prefix.Addr().Is4() {
		return E.New("invalid eBPF redirect interface route for ", route.prefix, " from ", route.source)
	}
	flags := unix.NLM_F_CREATE | unix.NLM_F_ACK | unix.NLM_F_EXCL
	if replace {
		flags = unix.NLM_F_CREATE | unix.NLM_F_ACK | unix.NLM_F_REPLACE
	}
	request := nl.NewNetlinkRequest(unix.RTM_NEWROUTE, flags)
	message := nl.NewRtMsg()
	message.Family = uint8(family)
	message.Dst_len = uint8(route.prefix.Bits())
	message.Table = unix.RT_TABLE_LOCAL
	message.Protocol = uint8(localRouteProtocol)
	message.Scope = unix.RT_SCOPE_HOST
	message.Type = unix.RTN_LOCAL
	request.AddData(message)
	request.AddData(nl.NewRtAttr(unix.RTA_DST, route.prefix.Masked().Addr().AsSlice()))
	request.AddData(nl.NewRtAttr(unix.RTA_PREFSRC, route.source.AsSlice()))
	request.AddData(nl.NewRtAttr(unix.RTA_OIF, nl.Uint32Attr(uint32(route.linkIndex))))
	request.AddData(nl.NewRtAttr(unix.RTA_PRIORITY, nl.Uint32Attr(route.priority)))
	_, err := request.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func deleteLocalInterfaceRoute(route localInterfaceRoute) error {
	return deleteLocalRoute(netlink.Route{
		LinkIndex: route.linkIndex,
		Family:    candidateFamily(route.prefix),
		Dst:       prefixIPNet(route.prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Protocol:  localRouteProtocol,
		Priority:  int(route.priority),
	})
}

func deleteLocalRoute(route netlink.Route) error {
	err := netlink.RouteDel(&route)
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// Close removes only routes owned by the set. Failed removals remain owned so
// a later Close call can retry them.
func (s *localRouteSet) Close() error {
	if s == nil {
		return nil
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.closing = true
	var routeErr error
	for key, route := range s.interfaceRoutes {
		if err := deleteLocalInterfaceRoute(route); err != nil {
			routeErr = E.Errors(routeErr, err)
			continue
		}
		delete(s.interfaceRoutes, key)
	}
	if len(s.routes) == 0 {
		return routeErr
	}
	remaining := make([]netlink.Route, 0, len(s.routes))
	for index := len(s.routes) - 1; index >= 0; index-- {
		route := s.routes[index]
		err := netlink.RouteDel(&route)
		if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			routeErr = E.Errors(routeErr, err)
			remaining = append(remaining, route)
		}
	}
	slices.Reverse(remaining)
	s.routes = remaining
	return routeErr
}

// IsClosed reports whether the set has released all routes it owns.
func (s *localRouteSet) IsClosed() bool {
	if s == nil {
		return true
	}
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.routes) == 0 && len(s.interfaceRoutes) == 0
}

func addLocalRoute(loopbackIndex int, prefix netip.Prefix) (netlink.Route, bool, error) {
	family := candidateFamily(prefix)
	if family == unix.AF_UNSPEC {
		return netlink.Route{}, false, E.New("invalid eBPF redirect prefix: ", prefix)
	}
	route := netlink.Route{
		LinkIndex: loopbackIndex,
		Family:    family,
		Dst:       prefixIPNet(prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
	}
	if err := checkRedirectRouteConflict(loopbackIndex, family, prefix); err != nil {
		return netlink.Route{}, false, err
	}
	exists, err := localRouteExists(family, prefix)
	if err != nil {
		return netlink.Route{}, false, err
	}
	if exists {
		return route, false, nil
	}
	if err = netlink.RouteAdd(&route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			exists, listErr := localRouteExists(family, prefix)
			if listErr == nil && exists {
				return route, false, nil
			}
		}
		return netlink.Route{}, false, E.Cause(err, "add local route for ", prefix)
	}
	return route, true, nil
}

func checkRedirectRouteConflict(loopbackIndex int, family int, prefix netip.Prefix) error {
	addresses, err := netlink.AddrList(nil, family)
	if err != nil {
		return E.Cause(err, "list interface addresses for eBPF redirect route")
	}
	for _, address := range addresses {
		if address.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		addressPrefix, loaded := prefixFromIPNet(address.IPNet)
		if loaded && prefixesOverlap(prefix, addressPrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with interface address ", addressPrefix)
		}
	}
	// This has to see every table, not just the main one. RT_FILTER_TABLE with
	// RT_TABLE_UNSPEC requests all tables and avoids RouteList's implicit output
	// interface filter.
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return E.Cause(err, "list routes for eBPF redirect address")
	}
	minimumRouteBits := 8
	if prefix.Addr().Is6() {
		minimumRouteBits = 7
	}
	for _, route := range routes {
		if route.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		routePrefix, loaded := prefixFromIPNet(route.Dst)
		if !loaded || routePrefix.Bits() < minimumRouteBits {
			continue
		}
		if route.LinkIndex == loopbackIndex && route.Type == unix.RTN_LOCAL && routePrefix == prefix {
			continue
		}
		// Interface routes of this prefix, left by an instance sharing it or
		// one that did not shut down, are adopted by the next reconciliation.
		if route.Protocol == localRouteProtocol && route.Type == unix.RTN_LOCAL && routePrefix == prefix {
			continue
		}
		if prefixesOverlap(prefix, routePrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with route ", routePrefix)
		}
	}
	return nil
}

func localRouteExists(family int, prefix netip.Prefix) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: unix.RT_TABLE_LOCAL},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, E.Cause(err, "list local routes")
	}
	for _, route := range routes {
		// Interface routes only serve sockets bound to their interface.
		if route.Protocol == localRouteProtocol {
			continue
		}
		if route.Type == unix.RTN_LOCAL && routePrefixContains(route.Dst, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func candidateFamily(prefix netip.Prefix) int {
	if !prefix.IsValid() {
		return unix.AF_UNSPEC
	}
	if prefix.Addr().Is4() {
		return unix.AF_INET
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return unix.AF_INET6
	}
	return unix.AF_UNSPEC
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func routePrefixContains(destination *net.IPNet, prefix netip.Prefix) bool {
	destinationPrefix, loaded := prefixFromIPNet(destination)
	if !loaded {
		return false
	}
	prefix = prefix.Masked()
	if destinationPrefix.Addr().BitLen() != prefix.Addr().BitLen() || destinationPrefix.Bits() > prefix.Bits() {
		return false
	}
	return destinationPrefix.Contains(prefix.Addr())
}

func prefixFromIPNet(network *net.IPNet) (netip.Prefix, bool) {
	if network == nil {
		return netip.Prefix{}, false
	}
	bits, addressBits := network.Mask.Size()
	address, loaded := netip.AddrFromSlice(network.IP)
	if !loaded || bits < 0 {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	if address.BitLen() != addressBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, bits).Masked(), true
}
