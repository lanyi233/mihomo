//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// A zero UDP checksum can be disabled or a CHECKSUM_PARTIAL seed. Test actual
// delivery through a veth, including rejection of a falsely disabled checksum.
// Adapted from sing-ebpf's shared_rewrite_checksum_netns_test.go (3bef0db).
func TestSharedRewriteUDPChecksumDeliveryIntegration(t *testing.T) {
	requireEBPFIntegration(t, "deliver rewritten UDP with checksum offload metadata")
	for _, partial := range []bool{false, true} {
		name := "disabled"
		if partial {
			name = "partial_zero_seed"
		}
		t.Run(name, func(t *testing.T) {
			runtime.LockOSThread()
			previous, err := os.Open("/proc/self/ns/net")
			if err != nil {
				runtime.UnlockOSThread()
				t.Fatal(err)
			}
			if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
				previous.Close()
				runtime.UnlockOSThread()
				t.Fatal(err)
			}
			defer func() {
				if err := unix.Setns(int(previous.Fd()), unix.CLONE_NEWNET); err != nil {
					previous.Close()
					t.Fatalf("restore network namespace: %v", err)
				}
				previous.Close()
				runtime.UnlockOSThread()
			}()
			veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sbcsum0"}, PeerName: "sbcsum1"}
			if err = netlink.LinkAdd(veth); err != nil {
				t.Fatal(err)
			}
			self, err := netlink.LinkByName("sbcsum0")
			if err != nil {
				t.Fatal(err)
			}
			peer, err := netlink.LinkByName("sbcsum1")
			if err != nil {
				t.Fatal(err)
			}
			for _, device := range []string{"lo", "sbcsum0", "sbcsum1"} {
				l, err := netlink.LinkByName(device)
				if err != nil {
					t.Fatal(err)
				}
				if err = netlink.LinkSetUp(l); err != nil {
					t.Fatal(err)
				}
			}
			for _, setting := range []struct{ path, value string }{
				{"all/rp_filter", "0"}, {"sbcsum0/rp_filter", "0"}, {"sbcsum0/route_localnet", "1"},
			} {
				if err = os.WriteFile("/proc/sys/net/ipv4/conf/"+setting.path, []byte(setting.value), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if partial {
				filter := []unix.SockFilter{
					{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 6},
					{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jf: 1},
					{Code: unix.BPF_RET | unix.BPF_K, K: 0},
					{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},
				}
				if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
					t.Fatal(err)
				}
			}
			if err = unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
				t.Fatal(err)
			}
			bound, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			timeout := unix.NsecToTimeval(time.Second.Nanoseconds())
			if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
				t.Fatal(err)
			}
			policy, err := CompilePolicy(PolicyConfig{EnableUDP: true})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
				ListenerPort: uint16(bound.(*unix.SockaddrInet4).Port), EnableUDP: true,
				RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), Policy: policy,
				MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 64}, UDPTimeout: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			if err = netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: self.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
			}, QdiscType: "clsact"}); err != nil {
				t.Fatal(err)
			}
			if err = netlink.FilterAdd(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
				LinkIndex: self.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Priority: 1, Protocol: unix.ETH_P_ALL,
			}, Fd: backend.IngressProgramFD(), Name: "sb_checksum", DirectAction: true}); err != nil {
				t.Fatal(err)
			}
			if err = backend.Enable(); err != nil {
				t.Fatal(err)
			}
			payload := []byte("udp-payload")
			packet := sharedRewriteTestPacket(ProtocolUDP, netip.MustParseAddrPort("10.250.0.2:53000"), netip.MustParseAddrPort("203.0.41.223:9681"), payload, true)
			copy(packet[:6], self.Attrs().HardwareAddr)
			copy(packet[6:12], peer.Attrs().HardwareAddr)
			pseudo := make([]byte, 12)
			copy(pseudo[:8], packet[26:34])
			pseudo[9] = unix.IPPROTO_UDP
			binary.BigEndian.PutUint16(pseudo[10:], uint16(len(packet)-34))
			if sharedRewriteTestChecksum(pseudo) != 0 {
				t.Fatal("fixture does not have a zero-equivalent partial seed")
			}
			protocol := int(binary.NativeEndian.Uint16([]byte{0x08, 0x00}))
			sender, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(sender)
			if err = unix.Bind(sender, &unix.SockaddrLinklayer{Ifindex: peer.Attrs().Index, Protocol: uint16(protocol)}); err != nil {
				t.Fatal(err)
			}
			if partial {
				if err = unix.SetsockoptInt(sender, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 10)
				header[0] = 1 // VIRTIO_NET_HDR_F_NEEDS_CSUM
				binary.NativeEndian.PutUint16(header[6:8], 34)
				binary.NativeEndian.PutUint16(header[8:10], 6)
				packet = append(header, packet...)
			}
			if _, err = unix.Write(sender, packet); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 1500)
			n, _, err := unix.Recvfrom(fd, data, 0)
			if err != nil {
				t.Fatal(err)
			}
			if string(data[:n]) != string(payload) {
				t.Fatalf("unexpected payload: %q", data[:n])
			}
		})
	}
}
