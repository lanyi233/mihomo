//go:build with_ebpf && linux && ebpf_integration

package sing_ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	goRuntime "runtime"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

var (
	routeTestIPv4Prefix      = netip.MustParsePrefix("127.128.0.0/9")
	routeTestIPv6Prefix      = netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	routeTestIPv4Destination = netip.MustParseAddrPort("127.145.1.1:24680")
	routeTestIPv6Destination = netip.MustParseAddrPort("[fd53:696e:672d:626f::7]:24680")
)

// TestLocalRouteSetReachesListenerFromBoundSockets drives real sockets bound
// to an interface into the redirect prefixes, the way a cgroup program rewrites
// their destination. Without interface routes the kernel skips the prefix's
// loopback route for them and sends the packets out of the interface instead.
func TestLocalRouteSetReachesListenerFromBoundSockets(t *testing.T) {
	requireEBPFIntegration(t, "exercise redirect routes in a network namespace")
	enterRouteTestNetworkNamespace(t)
	uplink := createRouteTestUplink(t)
	routes, err := newLocalRouteSet([]netip.Prefix{routeTestIPv4Prefix, routeTestIPv6Prefix})
	if err != nil {
		t.Fatalf("install the redirect routes: %v", err)
	}
	t.Cleanup(func() { _ = routes.Close() })
	for _, destination := range []netip.AddrPort{routeTestIPv4Destination, routeTestIPv6Destination} {
		startRouteTestUDPEcho(t, destination)
		startRouteTestTCPGreeter(t, destination)
	}

	// The loopback route alone is what the kernel used before.
	for _, destination := range []netip.AddrPort{routeTestIPv4Destination, routeTestIPv6Destination} {
		if reply, replyErr := routeTestUDPExchange(destination, routeTestBindToDevice, uplink, 300*time.Millisecond); replyErr == nil {
			t.Fatalf("a socket bound with SO_BINDTODEVICE reached %s through the loopback route alone: %q", destination, reply)
		}
	}
	// Older kernels, such as 5.10, ignore IP_UNICAST_IF and IPV6_UNICAST_IF on
	// a connected UDP socket, which then routes like an unbound one.
	unicastInterfaceHonored := make(map[bool]bool)
	for _, destination := range []netip.AddrPort{routeTestIPv4Destination, routeTestIPv6Destination} {
		reply, replyErr := routeTestUDPExchange(destination, routeTestUnicastInterface, uplink, 300*time.Millisecond)
		unicastInterfaceHonored[destination.Addr().Is6()] = replyErr != nil
		if replyErr == nil {
			t.Logf("this kernel ignores the unicast interface of a connected UDP socket to %s; it arrived from %s", destination, reply)
		}
	}

	changed, err := routes.ReconcileInterfaceRoutes()
	if err != nil || !changed {
		t.Fatalf("ReconcileInterfaceRoutes = %v, %v; want the interface routes installed", changed, err)
	}
	requireRouteTestBoundSocketsReach(t, uplink, "10.252.0.1", "fd00:5b::1", unicastInterfaceHonored)
	if changed, err = routes.ReconcileInterfaceRoutes(); err != nil || changed {
		t.Fatalf("a second ReconcileInterfaceRoutes = %v, %v; want nothing left to change", changed, err)
	}
	for _, route := range listRouteTestInterfaceRoutes(t) {
		if err = deleteLocalInterfaceRoute(route); err != nil {
			t.Fatal(err)
		}
	}
	if changed, err = routes.ReconcileInterfaceRoutes(); err != nil || !changed {
		t.Fatalf("ReconcileInterfaceRoutes after route loss = %v, %v; want repaired routes", changed, err)
	}
	requireRouteTestBoundSocketsReach(t, uplink, "10.252.0.1", "fd00:5b::1", unicastInterfaceHonored)

	// Sockets without a bound interface keep the loopback source.
	if peer := routeTestTCPPeer(t, routeTestIPv4Destination, routeTestUnbound, uplink); peer != "127.0.0.1" {
		t.Fatalf("an unbound socket reached the listener from %s, want 127.0.0.1", peer)
	}

	// The kernel deletes a route together with its source address. The new
	// IPv4 address is in another subnet: one added to the old address's subnet
	// is a secondary, and unless promote_secondaries is set, which systemd
	// does but a kernel default does not, removing the primary removes it too.
	replaceRouteTestAddress(t, uplink, "10.252.0.1/24", "10.252.1.9/24")
	replaceRouteTestAddress(t, uplink, "fd00:5b::1/64", "fd00:5b::9/64")
	if changed, err = routes.ReconcileInterfaceRoutes(); err != nil || !changed {
		t.Fatalf("ReconcileInterfaceRoutes after an address change = %v, %v; want the routes restored", changed, err)
	}
	requireRouteTestBoundSocketsReach(t, uplink, "10.252.1.9", "fd00:5b::9", unicastInterfaceHonored)

	if err = netlink.LinkSetDown(uplink); err != nil {
		t.Fatalf("take the uplink down: %v", err)
	}
	if changed, err = routes.ReconcileInterfaceRoutes(); err != nil || !changed {
		t.Fatalf("ReconcileInterfaceRoutes after the uplink went down = %v, %v; want its routes removed", changed, err)
	}
	if current := listRouteTestInterfaceRoutes(t); len(current) != 1 || current[0].linkIndex == uplink.Attrs().Index {
		t.Fatalf("interface routes with the uplink down = %+v, want only the IPv4 loopback route", current)
	}

	if err = routes.Close(); err != nil || !routes.IsClosed() {
		t.Fatalf("Close = %v, IsClosed = %v", err, routes.IsClosed())
	}
	if current := listRouteTestInterfaceRoutes(t); len(current) != 0 {
		t.Fatalf("interface routes left after Close: %+v", current)
	}
	if changed, err = routes.ReconcileInterfaceRoutes(); err != nil || changed {
		t.Fatalf("ReconcileInterfaceRoutes after Close = %v, %v; want nothing installed", changed, err)
	}
}

// TestLocalRouteSetAdoptsInterfaceRoutesLeftBehind covers interface routes an
// earlier instance did not remove. They must neither make the prefix look
// taken nor stand in for the IPv6 prefix's loopback route.
func TestLocalRouteSetAdoptsInterfaceRoutesLeftBehind(t *testing.T) {
	requireEBPFIntegration(t, "exercise redirect routes in a network namespace")
	enterRouteTestNetworkNamespace(t)
	uplink := createRouteTestUplink(t)
	leftBehind := localInterfaceRoute{
		prefix:    routeTestIPv6Prefix,
		linkIndex: uplink.Attrs().Index,
		source:    netip.MustParseAddr("fd00:5b::1"),
		priority:  localRouteInterfacePriorityBase + uint32(uplink.Attrs().Index),
	}
	if err := replaceLocalInterfaceRoute(leftBehind); err != nil {
		t.Fatalf("install a left-behind interface route: %v", err)
	}

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectRedirectPrefix(loopback.Attrs().Index, unix.AF_INET6, []netip.Prefix{routeTestIPv6Prefix}, nil)
	if err != nil || selected != routeTestIPv6Prefix {
		t.Fatalf("SelectRedirectPrefix = %v, %v; want the prefix its own interface route belongs to", selected, err)
	}
	routes, err := newLocalRouteSet([]netip.Prefix{routeTestIPv6Prefix})
	if err != nil {
		t.Fatalf("install the redirect routes: %v", err)
	}
	t.Cleanup(func() { _ = routes.Close() })
	if len(routes.routes) != 1 {
		t.Fatalf("owned loopback routes = %+v, want the IPv6 prefix's own", routes.routes)
	}
	if _, err = routes.ReconcileInterfaceRoutes(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	startRouteTestUDPEcho(t, routeTestIPv6Destination)
	if _, err = routeTestUDPExchange(routeTestIPv6Destination, routeTestBindToDevice, uplink, 2*time.Second); err != nil {
		t.Fatalf("a bound socket did not reach the listener: %v", err)
	}
	if err = routes.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if current := listRouteTestInterfaceRoutes(t); len(current) != 0 {
		t.Fatalf("the adopted interface route outlived Close: %+v", current)
	}
}

func TestLocalRouteSetPreservesExistingLoopbackRoute(t *testing.T) {
	requireEBPFIntegration(t, "preserve an operator's redirect route")
	enterRouteTestNetworkNamespace(t)
	uplink := createRouteTestUplink(t)
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	foreign := netlink.Route{
		LinkIndex: loopback.Attrs().Index,
		Family:    unix.AF_INET,
		Dst:       prefixIPNet(routeTestIPv4Prefix),
		Src:       net.IPv4(127, 0, 0, 1),
		Scope:     netlink.SCOPE_HOST,
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Protocol:  unix.RTPROT_STATIC,
	}
	if err = netlink.RouteAdd(&foreign); err != nil {
		t.Fatal(err)
	}
	routes, err := newLocalRouteSet([]netip.Prefix{routeTestIPv4Prefix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routes.Close() })
	if _, err = routes.ReconcileInterfaceRoutes(); err != nil {
		t.Fatal(err)
	}
	startRouteTestUDPEcho(t, routeTestIPv4Destination)
	for _, binding := range []routeTestBinding{routeTestUnbound, routeTestBindToDevice} {
		if _, err = routeTestUDPExchange(routeTestIPv4Destination, binding, uplink, time.Second); err != nil {
			t.Fatalf("UDP %s with an existing loopback route: %v", binding, err)
		}
	}
	if err = routes.Close(); err != nil {
		t.Fatal(err)
	}
	requireRouteTestForeignRoute(t, foreign)
}

func TestLocalRouteSetRejectsForeignReplacement(t *testing.T) {
	requireEBPFIntegration(t, "preserve a foreign replacement of a redirect route")
	enterRouteTestNetworkNamespace(t)
	uplink := createRouteTestUplink(t)
	routes, err := newLocalRouteSet([]netip.Prefix{routeTestIPv4Prefix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routes.Close() })
	if _, err = routes.ReconcileInterfaceRoutes(); err != nil {
		t.Fatal(err)
	}
	foreign := netlink.Route{
		LinkIndex: uplink.Attrs().Index,
		Family:    unix.AF_INET,
		Dst:       prefixIPNet(routeTestIPv4Prefix),
		Src:       net.IPv4(10, 252, 0, 1),
		Scope:     netlink.SCOPE_HOST,
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Protocol:  unix.RTPROT_STATIC,
		Priority:  localRouteInterfacePriorityBase + uplink.Attrs().Index,
	}
	if err = netlink.RouteReplace(&foreign); err != nil {
		t.Fatal(err)
	}
	if _, err = routes.ReconcileInterfaceRoutes(); err == nil {
		t.Fatal("reconciliation accepted an occupied route priority")
	}
	if err = routes.Close(); err != nil {
		t.Fatal(err)
	}
	requireRouteTestForeignRoute(t, foreign)
}

func requireRouteTestForeignRoute(t *testing.T, expected netlink.Route) {
	t.Helper()
	routes, err := netlink.RouteListFiltered(expected.Family, &expected,
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_PRIORITY)
	if err != nil || len(routes) != 1 || routes[0].LinkIndex != expected.LinkIndex || !routes[0].Src.Equal(expected.Src) {
		t.Fatalf("foreign route was changed or removed: routes=%v error=%v", routes, err)
	}
}

type routeTestBinding int

const (
	routeTestUnbound routeTestBinding = iota
	routeTestUnicastInterface
	routeTestBindToDevice
)

func (b routeTestBinding) String() string {
	switch b {
	case routeTestUnicastInterface:
		return "unicast_if"
	case routeTestBindToDevice:
		return "bindtodevice"
	default:
		return "unbound"
	}
}

// unicastInterfaceHonored reports, keyed by IPv6, whether the kernel routes a
// connected UDP socket by its unicast interface; where it does not, that socket
// only has to reach the listener.
func requireRouteTestBoundSocketsReach(t *testing.T, uplink netlink.Link, ipv4Source, ipv6Source string, unicastInterfaceHonored map[bool]bool) {
	t.Helper()
	for _, destination := range []netip.AddrPort{routeTestIPv4Destination, routeTestIPv6Destination} {
		wantSource := ipv4Source
		if destination.Addr().Is6() {
			wantSource = ipv6Source
		}
		for _, binding := range []routeTestBinding{routeTestUnbound, routeTestUnicastInterface, routeTestBindToDevice} {
			reply, err := routeTestUDPExchange(destination, binding, uplink, 2*time.Second)
			if err != nil {
				t.Fatalf("UDP %s to %s: %v", binding, destination, err)
			}
			if binding == routeTestUnicastInterface && !unicastInterfaceHonored[destination.Addr().Is6()] {
				continue
			}
			if binding != routeTestUnbound && reply != wantSource {
				t.Fatalf("UDP %s to %s arrived from %s, want the interface address %s", binding, destination, reply, wantSource)
			}
		}
		// TCP ignores IP_UNICAST_IF; SO_BINDTODEVICE is what binds it.
		if peer := routeTestTCPPeer(t, destination, routeTestBindToDevice, uplink); peer != wantSource {
			t.Fatalf("TCP bindtodevice to %s arrived from %s, want the interface address %s", destination, peer, wantSource)
		}
	}
}

func enterRouteTestNetworkNamespace(t *testing.T) {
	t.Helper()
	goRuntime.LockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		goRuntime.UnlockOSThread()
		t.Fatalf("hold the thread's network namespace open: %v", err)
	}
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = original.Close()
		goRuntime.UnlockOSThread()
		t.Fatalf("create a private network namespace: %v", err)
	}
	t.Cleanup(func() {
		defer original.Close()
		if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore the thread's network namespace, leaving the thread locked so the runtime discards it: %v", err)
			return
		}
		goRuntime.UnlockOSThread()
	})
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find the loopback interface: %v", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring up the loopback interface: %v", err)
	}
}

// createRouteTestUplink creates an interface carrying the default routes, so a
// packet a bound socket sends anywhere but to a local route leaves through it.
func createRouteTestUplink(t *testing.T) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "sbroute0"}}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("the kernel has no dummy interface driver: %v", err)
		}
		t.Fatalf("create the uplink: %v", err)
	}
	uplink, err := netlink.LinkByName("sbroute0")
	if err != nil {
		t.Fatalf("find the uplink: %v", err)
	}
	if err = netlink.LinkSetUp(uplink); err != nil {
		t.Fatalf("bring up the uplink: %v", err)
	}
	addRouteTestAddress(t, uplink, "10.252.0.1/24")
	addRouteTestAddress(t, uplink, "fd00:5b::1/64")
	for _, destination := range []string{"0.0.0.0/0", "::/0"} {
		_, network, _ := net.ParseCIDR(destination)
		if err = netlink.RouteAdd(&netlink.Route{LinkIndex: uplink.Attrs().Index, Dst: network}); err != nil {
			t.Fatalf("route %s through the uplink: %v", destination, err)
		}
	}
	return uplink
}

func addRouteTestAddress(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	address, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	address.Flags = unix.IFA_F_NODAD
	if err = netlink.AddrAdd(link, address); err != nil {
		t.Fatalf("add %s: %v", cidr, err)
	}
}

func replaceRouteTestAddress(t *testing.T, link netlink.Link, previous, next string) {
	t.Helper()
	addRouteTestAddress(t, link, next)
	address, err := netlink.ParseAddr(previous)
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrDel(link, address); err != nil {
		t.Fatalf("remove %s: %v", previous, err)
	}
}

func listRouteTestInterfaceRoutes(t *testing.T) []localInterfaceRoute {
	t.Helper()
	current, err := listLocalInterfaceRoutes([]netip.Prefix{routeTestIPv4Prefix, routeTestIPv6Prefix})
	if err != nil {
		t.Fatal(err)
	}
	routes := make([]localInterfaceRoute, 0, len(current))
	for _, route := range current {
		routes = append(routes, route)
	}
	return routes
}

func routeTestNetwork(destination netip.AddrPort, network string) string {
	if destination.Addr().Is4() {
		return network + "4"
	}
	return network + "6"
}

// routeTestListenControl lets a listener bind to a redirect address the way the
// consumer's transparent listeners receive them: IPv4 redirect addresses are
// local through 127.0.0.0/8, IPv6 ones are assigned to no interface.
func routeTestListenControl(_, _ string, rawConn syscall.RawConn) error {
	var optionErr error
	err := rawConn.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
		if errors.Is(optionErr, unix.ENOPROTOOPT) || errors.Is(optionErr, unix.EOPNOTSUPP) {
			optionErr = nil
		}
	})
	if err != nil {
		return err
	}
	return optionErr
}

func routeTestListenConfig(destination netip.AddrPort) *net.ListenConfig {
	if destination.Addr().Is4() {
		return &net.ListenConfig{}
	}
	return &net.ListenConfig{Control: routeTestListenControl}
}

// startRouteTestUDPEcho answers every datagram with the address it came from.
func startRouteTestUDPEcho(t *testing.T, destination netip.AddrPort) {
	t.Helper()
	conn, err := routeTestListenConfig(destination).ListenPacket(context.Background(), routeTestNetwork(destination, "udp"), destination.String())
	if err != nil {
		t.Fatalf("listen on %s: %v", destination, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			_, peer, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteTo([]byte(peer.(*net.UDPAddr).AddrPort().Addr().Unmap().String()), peer)
		}
	}()
}

// startRouteTestTCPGreeter sends every accepted connection the address it came
// from.
func startRouteTestTCPGreeter(t *testing.T, destination netip.AddrPort) {
	t.Helper()
	listener, err := routeTestListenConfig(destination).Listen(context.Background(), routeTestNetwork(destination, "tcp"), destination.String())
	if err != nil {
		t.Fatalf("listen on %s: %v", destination, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_, _ = conn.Write([]byte(conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap().String()))
			_ = conn.Close()
		}
	}()
}

func routeTestDialer(destination netip.AddrPort, binding routeTestBinding, uplink netlink.Link, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			var optionErr error
			err := rawConn.Control(func(fd uintptr) {
				index := uplink.Attrs().Index
				switch binding {
				case routeTestUnicastInterface:
					// Both options take the index in network byte order.
					var indexBytes [4]byte
					binary.BigEndian.PutUint32(indexBytes[:], uint32(index))
					value := int(binary.NativeEndian.Uint32(indexBytes[:]))
					if destination.Addr().Is4() {
						optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_UNICAST_IF, value)
					} else {
						optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_IF, value)
					}
				case routeTestBindToDevice:
					optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, uplink.Attrs().Name)
				}
			})
			if err != nil {
				return err
			}
			return optionErr
		},
	}
}

// routeTestUDPExchange sends a datagram from a socket with binding and returns
// the source address the listener saw.
func routeTestUDPExchange(destination netip.AddrPort, binding routeTestBinding, uplink netlink.Link, timeout time.Duration) (string, error) {
	conn, err := routeTestDialer(destination, binding, uplink, timeout).Dial(routeTestNetwork(destination, "udp"), destination.String())
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		return "", err
	}
	buffer := make([]byte, 128)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

// routeTestTCPPeer connects from a socket with binding and returns the source
// address the listener saw.
func routeTestTCPPeer(t *testing.T, destination netip.AddrPort, binding routeTestBinding, uplink netlink.Link) string {
	t.Helper()
	conn, err := routeTestDialer(destination, binding, uplink, 2*time.Second).Dial(routeTestNetwork(destination, "tcp"), destination.String())
	if err != nil {
		t.Fatalf("TCP %s to %s: %v", binding, destination, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 128)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("TCP %s to %s: %v", binding, destination, err)
	}
	return string(buffer[:n])
}

func requireEBPFIntegration(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("SING_BOX_EBPF_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_INTEGRATION=1 to " + reason)
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to " + reason)
	}
}
