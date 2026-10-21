//go:build with_ebpf && linux && ebpf_integration

package sing_ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func isolatedTestListenConfig(ipv6 bool) net.ListenConfig {
	return net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var setErr error
		err := raw.Control(func(fd uintptr) {
			level, option := unix.SOL_IP, unix.IP_TRANSPARENT
			if ipv6 {
				level, option = unix.SOL_IPV6, unix.IPV6_TRANSPARENT
			}
			setErr = unix.SetsockoptInt(int(fd), level, option, 1)
		})
		if err != nil {
			return err
		}
		return setErr
	}}
}

func TestTCIsolatedRoundTripIntegration(t *testing.T) {
	for _, rawIP := range []bool{false, true} {
		for _, shared := range []bool{false, true} {
			if rawIP && shared {
				continue
			}
			for _, ipv6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw_ip=%v/shared=%v/ipv6=%v", rawIP, shared, ipv6), func(t *testing.T) {
					testTCIsolatedRoundTrip(t, rawIP, shared, ipv6, false, false)
				})
			}
		}
	}
}

func TestTCIsolatedExistingSNATIntegration(t *testing.T) {
	testTCIsolatedRoundTrip(t, false, true, false, true, false)
}

func TestTCIsolatedListenerPortCollisionIntegration(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprint(ipv6), func(t *testing.T) {
			testTCIsolatedRoundTrip(t, false, true, ipv6, false, true)
		})
	}
}

func testTCIsolatedRoundTrip(t *testing.T, rawIP, shared, ipv6, seeded, listenerPortCollision bool) {
	enterRouteTestNetworkNamespace(t)
	var host, peer netlink.Link
	if rawIP {
		tun := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "sbiso0"}, Mode: netlink.TUNTAP_MODE_TUN, Flags: netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI, NonPersist: true, Queues: 1}
		if err := netlink.LinkAdd(tun); err != nil {
			t.Fatal(err)
		}
		for _, fd := range tun.Fds {
			defer fd.Close()
		}
		var err error
		host, err = netlink.LinkByName("sbiso0")
		if err != nil {
			t.Fatal(err)
		}
		if err = netlink.LinkSetUp(host); err != nil {
			t.Fatal(err)
		}
		peer = host
	} else {
		host, peer = createTestVethPair(t, "sbiso0", "sbiso1")
	}
	clientDo := func(block func() error) error { return block() }
	clientLink, gatewayMAC := host, peer.Attrs().HardwareAddr
	if shared {
		clientNS, err := NewTCNamespace()
		if err != nil {
			t.Fatal(err)
		}
		defer clientNS.Close()
		if err = netlink.LinkSetNsFd(peer, int(clientNS.handle)); err != nil {
			t.Fatal(err)
		}
		clientDo = clientNS.with
		if err = clientDo(func() error {
			var err error
			clientLink, err = netlink.LinkByName("sbiso1")
			if err != nil {
				return err
			}
			return netlink.LinkSetUp(clientLink)
		}); err != nil {
			t.Fatal(err)
		}
		gatewayMAC = host.Attrs().HardwareAddr
	}
	family, network, source, remote := unix.AF_INET, "4", "192.0.2.2/24", "203.0.113.10"
	if ipv6 {
		family, network, source, remote = unix.AF_INET6, "6", "fd00:1::2/64", "2001:db8:2::10"
	}
	address, _ := netlink.ParseAddr(source)
	address.Flags = unix.IFA_F_NODAD
	if err := clientDo(func() error { return netlink.AddrAdd(clientLink, address) }); err != nil {
		t.Fatal(err)
	}
	remoteIP := net.ParseIP(remote)
	bits := 128
	if !ipv6 {
		remoteIP = remoteIP.To4()
		bits = 32
	}
	route := netlink.Route{LinkIndex: clientLink.Attrs().Index, Family: family, Dst: &net.IPNet{IP: remoteIP, Mask: net.CIDRMask(bits, bits)}, Scope: netlink.SCOPE_LINK}
	if err := clientDo(func() error { return netlink.RouteAdd(&route) }); err != nil {
		t.Fatal(err)
	}
	if err := clientDo(func() error {
		if rawIP {
			return nil
		}
		return netlink.NeighSet(&netlink.Neigh{LinkIndex: clientLink.Attrs().Index, Family: family, IP: remoteIP, HardwareAddr: gatewayMAC, State: netlink.NUD_PERMANENT})
	}); err != nil {
		t.Fatal(err)
	}
	n, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	config := isolatedTestListenConfig(ipv6)
	var tcp net.Listener
	var udp net.PacketConn
	var port int
	err = n.with(func() error {
		var err error
		tcp, err = config.Listen(context.Background(), "tcp"+network, ":0")
		if err != nil {
			return err
		}
		port = tcp.Addr().(*net.TCPAddr).Port
		loopback := "127.0.0.1"
		if ipv6 {
			loopback = "::1"
		}
		udp, err = config.ListenPacket(context.Background(), "udp"+network, net.JoinHostPort(loopback, fmt.Sprint(port)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true, EnableUDP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{Isolated: true, ListenerPort: uint16(port), EnableLocal: !shared, EnableShared: shared, EnableIPv4: true, EnableLocalIPv6: ipv6 && !shared, EnableSharedIPv6: ipv6 && shared, EnableTCP: true, EnableUDP: true, Policy: policy, AssignmentCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	raw, _ := tcp.(*net.TCPListener).SyscallConn()
	var registerErr error
	var listenerProtocol int
	if err = raw.Control(func(fd uintptr) {
		listenerProtocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
		registerErr = backend.RegisterTCPListener(ipv6, int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("TCP listener protocol=%d lookup=%s", listenerProtocol, backend.TCPListenerLookupMode())
	if registerErr != nil {
		t.Fatal(registerErr)
	}
	localInterface := host.Attrs().Name
	var sharedInterfaces []string
	if shared {
		localInterface = ""
		sharedInterfaces = []string{host.Attrs().Name}
	}
	d, err := startTCDataPlane(backend, !shared, ipv6, localInterface, sharedInterfaces, nil, false, 2, n)
	if d != nil {
		defer d.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	endpoint := net.JoinHostPort(remote, "9681")
	if listenerPortCollision {
		endpoint = net.JoinHostPort(remote, fmt.Sprint(port))
	}
	// Occupy the same remote port in the host namespace. Only isolation
	// allows a transparent response socket to bind without SO_REUSEPORT.
	occupied, err := net.ListenPacket("udp"+network, ":9681")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	var client net.Conn
	err = clientDo(func() error {
		var err error
		client, err = net.DialTimeout("udp"+network, endpoint, 2*time.Second)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if seeded {
		if err = backend.Disable(); err != nil {
			t.Fatal(err)
		}
		seedIsolatedTestSNAT(t, host, client, remoteIP)
		if err = backend.Enable(); err != nil {
			t.Fatal(err)
		}
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	udp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write([]byte("udp request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	count, clientAddress, err := udp.ReadFrom(buffer)
	if err != nil {
		stats, _ := backend.TCStats()
		t.Fatalf("UDP receive: %v; stats=%+v", err, stats)
	}
	if string(buffer[:count]) != "udp request" || clientAddress.String() != client.LocalAddr().String() {
		t.Fatalf("tuple/payload changed: %v %q", clientAddress, buffer[:count])
	}
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolUDP, netip.MustParseAddrPort(clientAddress.String()), netip.MustParseAddrPort(endpoint), 0, false)
	if err != nil || assignment.InterfaceIndex != uint32(host.Attrs().Index) {
		t.Fatalf("assignment=%+v err=%v", assignment, err)
	}
	var reply net.PacketConn
	err = n.with(func() error {
		var err error
		reply, err = config.ListenPacket(context.Background(), "udp"+network, endpoint)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	if _, err = reply.WriteTo([]byte("udp reply"), clientAddress); err != nil {
		t.Fatal(err)
	}
	count, err = client.Read(buffer)
	if err != nil || string(buffer[:count]) != "udp reply" {
		t.Fatalf("UDP reply: %q %v", buffer[:count], err)
	}
	// The reply route must fragment in the private IP stack, not emit an
	// oversized Ethernet frame at the host's TC redirect. Includes IPv6 tails.
	largeReply := bytes.Repeat([]byte("large-udp-reply"), 600)
	rawReply, err := reply.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fragmentErr error
	if err = rawReply.Control(func(fd uintptr) {
		level, option := unix.SOL_IP, unix.IP_MTU_DISCOVER
		if ipv6 {
			level, option = unix.SOL_IPV6, unix.IPV6_MTU_DISCOVER
		}
		fragmentErr = unix.SetsockoptInt(int(fd), level, option, unix.IP_PMTUDISC_DONT)
	}); err != nil || fragmentErr != nil {
		t.Fatalf("enable reply fragmentation: %v %v", err, fragmentErr)
	}
	if _, err = reply.WriteTo(largeReply, clientAddress); err != nil {
		t.Fatal(err)
	}
	largeBuffer := make([]byte, len(largeReply)+1)
	if count, err = client.Read(largeBuffer); err != nil || !bytes.Equal(largeReply, largeBuffer[:count]) {
		stats, _ := backend.TCStats()
		t.Fatalf("large UDP reply: bytes=%d err=%v stats=%+v", count, err, stats)
	}
	// TCP's assignment is consumed on accept; its return record must survive.
	var tcpClient net.Conn
	err = clientDo(func() error {
		var err error
		tcpClient, err = net.DialTimeout("tcp"+network, endpoint, 3*time.Second)
		return err
	})
	if err != nil {
		stats, _ := backend.TCStats()
		t.Fatalf("TCP dial: %v; stats=%+v", err, stats)
	}
	defer tcpClient.Close()
	tcp.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	accepted, err := tcp.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.LocalAddr().String() != endpoint || accepted.RemoteAddr().String() != tcpClient.LocalAddr().String() {
		t.Fatalf("TCP tuple changed: %v -> %v", accepted.RemoteAddr(), accepted.LocalAddr())
	}
	if _, err = backend.LookupAssignment(commonEBPF.ProtocolTCP, netip.MustParseAddrPort(accepted.RemoteAddr().String()), netip.MustParseAddrPort(endpoint), 0, true); err != nil {
		t.Fatal(err)
	}
	accepted.SetDeadline(time.Now().Add(3 * time.Second))
	tcpClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = accepted.Write([]byte("tcp reply")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(tcpClient, buffer[:9]); err != nil || string(buffer[:9]) != "tcp reply" {
		t.Fatalf("TCP reply %q: %v", buffer[:9], err)
	}
	// Only connection setup records a TCP assignment, so the established
	// segments that follow its consumption must not recreate it.
	if _, err = tcpClient.Write([]byte("tcp request")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(accepted, buffer[:11]); err != nil || string(buffer[:11]) != "tcp request" {
		t.Fatalf("TCP request %q: %v", buffer[:11], err)
	}
	if assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, netip.MustParseAddrPort(accepted.RemoteAddr().String()), netip.MustParseAddrPort(endpoint), 0, false); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("established TCP segments recreated the consumed assignment: %+v err=%v", assignment, err)
	}
	for _, fault := range []string{"mtu", "return_filter", "delivery_filter", "delivery_mac", "veth"} {
		switch fault {
		case "mtu":
			err = netlink.LinkSetMTU(host, 1280)
		case "return_filter":
			err = netlink.FilterDel(d.delivery.returnFilter)
		case "delivery_filter":
			err = n.with(func() error { return netlink.FilterDel(d.delivery.filter) })
		case "delivery_mac":
			// The backend must follow a changed private-end address, or every
			// redirected frame is dropped as PACKET_OTHERHOST.
			err = n.with(func() error {
				return netlink.LinkSetHardwareAddr(d.delivery.delivery, net.HardwareAddr{0x02, 0x5b, 0x00, 0x00, 0x00, 0x01})
			})
		case "veth":
			err = netlink.LinkDel(d.delivery.redirect)
		}
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := d.repairInfrastructure(); err != nil || !changed {
			t.Fatalf("%s not repaired: changed=%v err=%v", fault, changed, err)
		}
		client.SetDeadline(time.Now().Add(3 * time.Second))
		udp.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = client.Write([]byte(fault)); err != nil {
			t.Fatal(err)
		}
		count, clientAddress, err = udp.ReadFrom(buffer)
		if err != nil || string(buffer[:count]) != fault {
			t.Fatalf("%s receive: %q %v", fault, buffer[:count], err)
		}
		if _, err = reply.WriteTo(buffer[:count], clientAddress); err != nil {
			t.Fatal(err)
		}
		count, err = client.Read(buffer)
		if err != nil || string(buffer[:count]) != fault {
			t.Fatalf("%s return: %q %v", fault, buffer[:count], err)
		}
		if _, err = reply.WriteTo(largeReply, clientAddress); err != nil {
			t.Fatal(err)
		}
		if count, err = client.Read(largeBuffer); err != nil || !bytes.Equal(largeReply, largeBuffer[:count]) {
			t.Fatalf("%s large UDP return: bytes=%d err=%v", fault, count, err)
		}
	}
	if stats, err := backend.TCStats(); err != nil || stats.ReturnLookupFailed != 0 || stats.ReturnUpdateFailed != 0 || stats.ReturnConflict != 0 {
		t.Fatalf("return stats=%+v err=%v", stats, err)
	}
	if err = d.Close(); err != nil || d.backend != nil {
		t.Fatalf("runtime cleanup: closed=%v err=%v", d.backend == nil, err)
	}
	if left := deliveryPairLeftBehind(t); len(left) != 0 {
		t.Fatalf("leaked host links: %v", left)
	}
}

// Only invoked after enterTestNetworkNamespace. The old conntrack entry and
// SNAT rule remain installed throughout the round-trip and recovery tests.
func seedIsolatedTestSNAT(t *testing.T, host netlink.Link, client net.Conn, remote net.IP) {
	t.Helper()
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		t.Skip("SNAT integration needs iptables")
	}
	address, _ := netlink.ParseAddr("192.0.2.1/24")
	if err = netlink.AddrAdd(host, address); err != nil {
		t.Fatal(err)
	}
	wan := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "sbnatwan"}}
	if err = netlink.LinkAdd(wan); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(wan); err != nil {
		t.Fatal(err)
	}
	address, _ = netlink.ParseAddr("198.51.100.1/24")
	if err = netlink.AddrAdd(wan, address); err != nil {
		t.Fatal(err)
	}
	if err = netlink.RouteAdd(&netlink.Route{LinkIndex: wan.Attrs().Index, Dst: &net.IPNet{IP: remote, Mask: net.CIDRMask(32, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"all", host.Attrs().Name, wan.Attrs().Name} {
		if _, _, err = setTCSysctl(tcInterfaceSysctlPath(name, "rp_filter"), "0"); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command(iptables, "-t", "nat", "-A", "POSTROUTING", "-o", "sbnatwan", "-p", "udp", "-j", "SNAT", "--to-source", "198.51.100.1:18094").CombinedOutput(); err != nil {
		t.Fatalf("SNAT setup: %v: %s", err, output)
	}
	if _, err = client.Write([]byte("seed NAT before interception")); err != nil {
		t.Fatal(err)
	}
	local := client.LocalAddr().(*net.UDPAddr)
	for attempt := 0; attempt < 100; attempt++ {
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET))
		if err != nil {
			t.Fatal(err)
		}
		for _, flow := range flows {
			if flow.Forward.SrcIP.Equal(local.IP) && int(flow.Forward.SrcPort) == local.Port && flow.Forward.DstPort == 9681 {
				if flow.Reverse.DstIP.String() != "198.51.100.1" || flow.Reverse.DstPort != 18094 {
					t.Fatalf("not SNAT: %s", flow)
				}
				t.Logf("existing SNAT kept: %s", flow)
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SNAT state was not established")
}

func createTestVethPair(t *testing.T, selfName, peerName string) (netlink.Link, netlink.Link) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: selfName}, PeerName: peerName}); err != nil {
		t.Fatal(err)
	}
	self, err := netlink.LinkByName(selfName)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(device); err != nil {
			t.Fatal(err)
		}
	}
	return self, peer
}
func deliveryPairLeftBehind(t *testing.T) []string {
	devices, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, device := range devices {
		name := device.Attrs().Name
		if strings.HasPrefix(name, "sbt") || strings.HasPrefix(name, "sbd") {
			left = append(left, name)
		}
	}
	return left
}
