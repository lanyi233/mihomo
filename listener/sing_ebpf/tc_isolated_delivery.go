//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strings"

	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

const tcReturnFilterHandle = 0x5349

// The veth can carry a full original packet; the route metric constrains only
// replies. The private IP stack performs TCP segmentation/UDP fragmentation
// before the TC return hook, which otherwise bypasses host IP output.
func (d *tcDataPlane) isolatedReplyMTU(local string, shared []string) (int, error) {
	mtu := 65535
	for _, name := range append([]string{local}, shared...) {
		if name == "" {
			continue
		}
		link, err := netlink.LinkByName(name)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if link.Attrs().MTU > 0 {
			mtu = min(mtu, link.Attrs().MTU)
		}
	}
	if mtu == 65535 {
		mtu = 1500
	}
	return mtu, nil
}

func (d *tcDataPlane) inNamespace(block func() error) error {
	if d.namespace == nil {
		return block()
	}
	return d.namespace.with(block)
}

func (d *tcDataPlane) createIsolatedTCDeliveryLink() (*tcDeliveryLink, error) {
	hostName, peerName, err := nextTCVethNames()
	if err != nil {
		return nil, err
	}
	hostAddress, err := newTCDeliveryHardwareAddress()
	if err != nil {
		return nil, E.Cause(err, "generate TC eBPF redirect link address")
	}
	peerAddress, err := newTCDeliveryHardwareAddress()
	if err != nil {
		return nil, E.Cause(err, "generate TC eBPF delivery link address")
	}
	n := d.namespace
	n.access.RLock()
	if !n.open {
		n.access.RUnlock()
		return nil, os.ErrClosed
	}
	veth := &netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: hostName, MTU: 65535, HardwareAddr: hostAddress},
		PeerName:         peerName,
		PeerHardwareAddr: peerAddress,
		PeerNamespace:    netlink.NsFd(n.handle),
	}
	err = netlink.LinkAdd(veth)
	n.access.RUnlock()
	if err != nil {
		return nil, E.Cause(err, "create isolated TC veth (CONFIG_VETH and CAP_NET_ADMIN required)")
	}
	owner := &tcDeliveryLink{namespace: n, redirectName: hostName, deliveryName: peerName, redirect: veth, enableIPv6: d.enableIPv6, replyMTU: d.replyMTU}
	cleanup := func(cause error) (*tcDeliveryLink, error) {
		err := E.Errors(cause, owner.Close())
		if owner.redirect == nil && owner.delivery == nil {
			return nil, err
		}
		return owner, err
	}
	owner.redirect, err = netlink.LinkByName(hostName)
	if err != nil {
		owner.redirect = veth
		return cleanup(E.Cause(err, "find TC eBPF redirect link"))
	}
	if err = netlink.LinkSetUp(owner.redirect); err != nil {
		return cleanup(err)
	}
	if err = ensureTCClsact(owner.redirect); err != nil {
		return cleanup(err)
	}
	owner.returnFilter, err = attachTCFilter(owner.redirect, netlink.HANDLE_MIN_INGRESS,
		d.backend.IsolatedReturnProgramFD(), "sb_tc_return", tcReturnFilterHandle, d.priority)
	if err != nil {
		return cleanup(err)
	}
	err = n.with(func() error {
		var err error
		owner.delivery, err = netlink.LinkByName(peerName)
		if err != nil {
			return err
		}
		if _, err = owner.configureIsolatedPeer(true); err != nil {
			return err
		}
		if err = ensureTCClsact(owner.delivery); err != nil {
			return err
		}
		owner.filter, err = attachTCFilter(owner.delivery, netlink.HANDLE_MIN_INGRESS,
			d.backend.DeliveryIngressProgramFD(), "sb_tc_deliver", tcDeliveryFilterHandle, d.priority)
		return err
	})
	if err != nil {
		return cleanup(E.Cause(err, "configure TC namespace"))
	}
	mac, valid := tcDeliveryMACAddress(owner.delivery)
	if !valid {
		return cleanup(E.New("invalid TC namespace peer MAC"))
	}
	if err = d.backend.SetDeliveryInterface(uint32(owner.redirect.Attrs().Index), mac); err != nil {
		return cleanup(err)
	}
	owner.deliveryMAC = mac
	return owner, nil
}

// Called inside the private namespace only. No host routes, addresses, rules
// or global sysctls are altered. Missing state is repaired without a full reset.
func (d *tcDeliveryLink) configureIsolatedPeer(repair bool) (bool, error) {
	healthy := true
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return false, err
	}
	for _, link := range []netlink.Link{loopback, d.delivery} {
		if link.Attrs().Flags&net.FlagUp != 0 {
			continue
		}
		healthy = false
		if repair {
			if err = netlink.LinkSetUp(link); err != nil {
				return false, err
			}
		}
	}
	for _, setting := range []struct{ device, name, value string }{
		{"all", "rp_filter", "0"}, {"default", "rp_filter", "0"},
		{d.deliveryName, "rp_filter", "0"}, {d.deliveryName, "accept_local", "1"},
		{d.deliveryName, "route_localnet", "1"},
	} {
		path := tcInterfaceSysctlPath(setting.device, setting.name)
		value, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(string(value)) == setting.value {
			continue
		}
		healthy = false
		if repair {
			if _, _, err = setTCSysctl(path, setting.value); err != nil {
				return false, err
			}
		}
	}
	families := []int{unix.AF_INET}
	if d.enableIPv6 {
		families = append(families, unix.AF_INET6)
	}
	for _, family := range families {
		address, gateway := "169.254.0.2/32", net.ParseIP("169.254.0.1").To4()
		if family == unix.AF_INET6 {
			address, gateway = "fe80::2/128", net.ParseIP("fe80::1")
		}
		wantAddress, err := netlink.ParseAddr(address)
		if err != nil {
			return false, err
		}
		wantAddress.Flags = unix.IFA_F_NODAD
		addresses, err := netlink.AddrList(d.delivery, family)
		if err != nil {
			return false, err
		}
		found := false
		for _, current := range addresses {
			if current.Equal(*wantAddress) {
				found = true
				break
			}
		}
		if !found {
			healthy = false
			if repair {
				if err = netlink.AddrAdd(d.delivery, wantAddress); err != nil {
					return false, err
				}
			}
		}
		wantNeighbor := netlink.Neigh{LinkIndex: d.delivery.Attrs().Index, Family: family,
			State: netlink.NUD_PERMANENT, IP: gateway, HardwareAddr: d.redirect.Attrs().HardwareAddr}
		neighbors, err := netlink.NeighList(wantNeighbor.LinkIndex, family)
		if err != nil {
			return false, err
		}
		found = false
		for _, current := range neighbors {
			if current.IP.Equal(gateway) && current.State == netlink.NUD_PERMANENT && bytes.Equal(current.HardwareAddr, wantNeighbor.HardwareAddr) {
				found = true
				break
			}
		}
		if !found {
			healthy = false
			if repair {
				if err = netlink.NeighSet(&wantNeighbor); err != nil {
					return false, err
				}
			}
		}
		wantRoute := netlink.Route{LinkIndex: d.delivery.Attrs().Index, Family: family, Gw: gateway,
			Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Scope: netlink.SCOPE_UNIVERSE,
			Protocol: unix.RTPROT_STATIC, Flags: int(unix.RTNH_F_ONLINK), MTU: d.replyMTU}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return false, err
		}
		found = false
		for _, current := range routes {
			if current.LinkIndex == wantRoute.LinkIndex && current.Gw.Equal(gateway) &&
				(current.Dst == nil || routeDestination(current.Dst).Bits() == 0) && current.Type == unix.RTN_UNICAST && current.MTU == wantRoute.MTU {
				found = true
				break
			}
		}
		if !found {
			healthy = false
			if repair {
				if err = netlink.RouteReplace(&wantRoute); err != nil {
					return false, err
				}
			}
		}
	}
	return healthy, nil
}

func (d *tcDeliveryLink) inspectIsolatedLinks() (bool, error) {
	if d.redirect == nil || d.delivery == nil {
		return false, nil
	}
	host, err := netlink.LinkByName(d.redirectName)
	if tcLinkNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if host.Attrs().Index != d.redirect.Attrs().Index {
		return false, nil
	}
	var peer netlink.Link
	err = d.namespace.with(func() error { var err error; peer, err = netlink.LinkByName(d.deliveryName); return err })
	if tcLinkNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if peer.Attrs().Index != d.delivery.Attrs().Index {
		return false, nil
	}
	d.redirect, d.delivery = host, peer
	return true, nil
}

func (d *tcDeliveryLink) healthyIsolated(priority uint16) (bool, error) {
	live, err := d.inspectIsolatedLinks()
	if err != nil || !live {
		return false, err
	}
	if d.redirect.Attrs().Flags&net.FlagUp == 0 {
		return false, nil
	}
	if mac, valid := tcDeliveryMACAddress(d.delivery); !valid || mac != d.deliveryMAC {
		return false, nil
	}
	live, err = tcFilterAttached(d.redirect, netlink.HANDLE_MIN_INGRESS, "sb_tc_return", tcReturnFilterHandle, priority)
	if err != nil || !live {
		return false, err
	}
	err = d.namespace.with(func() error {
		var err error
		live, err = d.configureIsolatedPeer(false)
		if err != nil || !live {
			return err
		}
		live, err = tcFilterAttached(d.delivery, netlink.HANDLE_MIN_INGRESS, "sb_tc_deliver", tcDeliveryFilterHandle, priority)
		return err
	})
	return live, err
}

func (d *tcDeliveryLink) repairIsolated(backend *commonEBPF.TCBackend, priority uint16) (bool, bool, error) {
	live, err := d.inspectIsolatedLinks()
	if err != nil || !live {
		return false, !live, err
	}
	changed := false
	// Anything that changes the private end's address after creation leaves
	// the backend addressing frames to a MAC the interface no longer accepts.
	mac, valid := tcDeliveryMACAddress(d.delivery)
	if !valid {
		return false, true, nil
	}
	if mac != d.deliveryMAC {
		if err = backend.SetDeliveryInterface(uint32(d.redirect.Attrs().Index), mac); err != nil {
			return false, false, E.Cause(err, "update TC eBPF delivery address")
		}
		d.deliveryMAC = mac
		changed = true
	}
	if d.redirect.Attrs().Flags&net.FlagUp == 0 {
		if err = netlink.LinkSetUp(d.redirect); err != nil {
			return false, false, err
		}
		changed = true
	}
	repairFilter := func(link netlink.Link, name string, handle uint16, fd int, target **netlink.BpfFilter) error {
		attached, err := tcFilterAttached(link, netlink.HANDLE_MIN_INGRESS, name, handle, priority)
		if err != nil || attached {
			return err
		}
		if err = ensureTCClsact(link); err != nil {
			return err
		}
		*target, err = attachTCFilter(link, netlink.HANDLE_MIN_INGRESS, fd, name, handle, priority)
		if err == nil {
			changed = true
		}
		return err
	}
	if err = repairFilter(d.redirect, "sb_tc_return", tcReturnFilterHandle, backend.IsolatedReturnProgramFD(), &d.returnFilter); err != nil {
		return changed, false, err
	}
	err = d.namespace.with(func() error {
		healthy, err := d.configureIsolatedPeer(true)
		changed = changed || !healthy
		if err != nil {
			return err
		}
		return repairFilter(d.delivery, "sb_tc_deliver", tcDeliveryFilterHandle, backend.DeliveryIngressProgramFD(), &d.filter)
	})
	return changed, false, err
}

func (d *tcDeliveryLink) closeIsolated() error {
	if err := detachTCFilterOwned(&d.returnFilter, detachTCFilter); err != nil {
		return err
	}
	if d.filter != nil {
		if err := d.namespace.with(func() error { return detachTCFilterOwned(&d.filter, detachTCFilter) }); err != nil {
			return err
		}
	}
	if d.redirect != nil {
		// A replaced interface with the same name/index is never ours to delete.
		current, err := netlink.LinkByName(d.redirectName)
		if err != nil && !tcLinkNotFound(err) {
			return err
		}
		if err == nil && (d.redirect.Attrs().Index == 0 || current.Attrs().Index == d.redirect.Attrs().Index) {
			if err = netlink.LinkDel(current); err != nil && !errors.Is(err, unix.ENODEV) {
				return err
			}
		}
	}
	d.redirect, d.delivery = nil, nil
	return nil
}

func newTCDeliveryHardwareAddress() (net.HardwareAddr, error) {
	address := make(net.HardwareAddr, 6)
	if _, err := rand.Read(address); err != nil {
		return nil, err
	}
	address[0] = address[0]&^1 | 2
	return address, nil
}
func tcDeliveryMACAddress(link netlink.Link) (commonEBPF.MACAddress, bool) {
	var address commonEBPF.MACAddress
	if link == nil || len(link.Attrs().HardwareAddr) != len(address) {
		return address, false
	}
	copy(address[:], link.Attrs().HardwareAddr)
	return address, true
}
