//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestCgroupUDPFlowCacheRevalidatesRedirect covers a cached proxy decision
// whose redirect entry is gone, as after an LRU eviction, or now records
// another flow, as when that flow claimed the freed token. The cache must not
// send the datagram to a token userspace cannot map back to this destination.
func TestCgroupUDPFlowCacheRevalidatesRedirectIntegration(t *testing.T) {
	const listenerPort = 41010
	backend := startCgroupUDPIntegrationBackend(t, 101, listenerPort)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	cookie, err := udpSocketCookie(sender)
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddrPort("198.51.100.7:9")
	flowKey := udpFlowKey{SocketCookie: cookie, Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: destination.Port()}
	destination4 := destination.Addr().As4()
	copy(flowKey.Addr[:4], destination4[:])
	flows := backend.runtime.maps["cgroup_udp_flow"]
	redirects := backend.runtime.maps["cgroup_udp_redirect"]

	// send returns the token the flow cache holds after one datagram, and
	// requires the redirect entry for it to record this socket's destination.
	send := func(payload string) listenerLookupKey {
		t.Helper()
		if _, err := sender.WriteToUDPAddrPort([]byte(payload), destination); err != nil {
			t.Fatal(err)
		}
		assertUDPReceived(t, listener, payload)
		var flow udpFlowValue
		if err := flows.Lookup(&flowKey, &flow); err != nil {
			t.Fatalf("look up the UDP flow cache after %q: %v", payload, err)
		}
		if flow.Action != udpFlowActionProxy {
			t.Fatalf("UDP flow action after %q = %d, want proxy", payload, flow.Action)
		}
		var original originalDestinationValue
		if err := redirects.Lookup(&flow.Listener, &original); err != nil {
			t.Fatalf("after %q the UDP flow cache names token %v without a redirect entry: %v",
				payload, flow.Listener.TokenAddr[:4], err)
		}
		if original.SocketCookie != cookie || original.Port != destination.Port() ||
			[4]byte(original.Addr[:4]) != destination4 {
			t.Fatalf("after %q the UDP flow cache names a token recording %+v, want this socket's destination",
				payload, original)
		}
		return flow.Listener
	}

	token := send("first")
	if err = redirects.Delete(&token); err != nil {
		t.Fatal(err)
	}
	token = send("after eviction")

	claimed := originalDestinationValue{
		Family:       addressFamilyIPv4,
		Protocol:     ProtocolUDP,
		Port:         53,
		SocketCookie: cookie + 1,
	}
	copy(claimed.Addr[:4], netip.MustParseAddr("192.0.2.53").AsSlice())
	if err = redirects.Update(&token, &claimed, CiliumEBPF.UpdateExist); err != nil {
		t.Fatal(err)
	}
	if replacement := send("after reuse"); replacement == token {
		t.Fatal("the UDP flow cache kept a token another flow claimed")
	}
	var current originalDestinationValue
	if err = redirects.Lookup(&token, &current); err != nil || current != claimed {
		t.Fatalf("the other flow's redirect entry = %+v, %v; want it left alone", current, err)
	}
}

// startCgroupUDPIntegrationBackend attaches an IPv4 UDP backend that
// intercepts every destination to a dedicated cgroup and moves this process
// into it.
func startCgroupUDPIntegrationBackend(t *testing.T, index int, listenerPort uint16) *CgroupBackend {
	t.Helper()
	requireEBPFIntegration(t, "attach cgroup UDP interception")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, cgroupRoot, index)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	backend, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(listenerPort); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program loading is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program attach is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	moveCurrentProcessToCgroup(t, path, cgroupRoot)
	return backend
}

func moveCurrentProcessToCgroup(t *testing.T, path, root string) {
	t.Helper()
	previous, err := DetectProcessCgroup2Path()
	if err != nil {
		t.Fatal(err)
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), pid, 0o644); err != nil {
		t.Skipf("cannot move integration process into cgroup: %v", err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(previous, "cgroup.procs"), pid, 0o644); err != nil {
			t.Errorf("restore test process cgroup: %v", err)
		}
	})
}

func udpSocketCookie(conn *net.UDPConn) (uint64, error) {
	var cookie uint64
	var controlErr error
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = rawConn.Control(func(fd uintptr) {
		cookie, controlErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	if err != nil {
		return 0, err
	}
	return cookie, controlErr
}

func assertUDPReceived(t *testing.T, conn *net.UDPConn, want string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != want {
		t.Fatalf("received %q, want %q", buffer[:n], want)
	}
}
