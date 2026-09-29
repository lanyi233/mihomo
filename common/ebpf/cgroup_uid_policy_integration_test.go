//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
)

const (
	cgroupUIDHelperEnv = "SB_EBPF_CGROUP_UID_HELPER"
	cgroupUIDBypassed  = 65534
)

var (
	cgroupUIDPolicyTarget = netip.MustParseAddrPort("203.0.113.10:9")
	cgroupUIDPolicyFakeIP = netip.MustParseAddrPort("198.18.0.1:9")
)

// UID policy belongs to the task that sends, so a socket must not carry a proxy
// decision cached under one UID over to a UID the policy bypasses. A fake-ip
// destination resolves only through the proxy, so it is intercepted for a
// bypassed UID too. A helper process in the test cgroup sends from one UDP
// socket under both UIDs, and the listener port shows which datagrams the
// sendmsg program redirected. It runs against both cgroup objects, the
// coarse-clock one and the plain one.
func TestCgroupUIDPolicyPrecedesTheFlowCacheIntegration(t *testing.T) {
	requireEBPFIntegration(t, "send UDP through the cgroup programs under two UIDs")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	variants := []struct {
		name   string
		coarse bool
	}{
		{name: "coarse_time", coarse: true},
		{name: "plain"},
	}
	for index, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			path, dedicated := createIntegrationCgroup(t, root, 910+index)
			if !dedicated {
				t.Skip("no dedicated cgroup to run the helper in")
			}
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			listenerPort := uint16(listener.LocalAddr().(*net.UDPAddr).Port)

			policy, err := CompilePolicy(PolicyConfig{
				EnableUDP:  true,
				Local:      LocalPolicy{ExcludeUID: []UIDRange{{Start: cgroupUIDBypassed, End: cgroupUIDBypassed}}},
				FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
			})
			if err != nil {
				t.Fatal(err)
			}
			selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
				Type:       CiliumEBPF.LRUHash,
				KeySize:    8,
				ValueSize:  4,
				MaxEntries: 8,
			})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := PrepareCgroup(CgroupConfig{
				Path:          path,
				EnableUDP:     true,
				RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
				MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
				UDPTimeout:    time.Minute,
				Policy:        policy,
				SelfBypassMap: selfBypassMap,
			})
			_ = selfBypassMap.Close()
			if err != nil {
				if cgroupIntegrationUnavailable(err) {
					t.Skipf("cgroup eBPF is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			if variant.coarse && !backend.runtime.coarse_time_supported {
				t.Skip("kernel lacks the coarse clock helper")
			}
			if !variant.coarse {
				backend.runtime.coarse_time_supported = false
			}
			if err = backend.LoadPrograms(listenerPort); err != nil {
				t.Fatal(err)
			}
			if err = backend.Attach(); err != nil {
				t.Fatal(err)
			}

			received := runCgroupUIDHelper(t, path, listener)
			want := []string{"proxied-first", "bypassed-fakeip", "proxied-again"}
			if !slices.Equal(received, want) {
				t.Fatalf("redirected datagrams %q, want %q (a bypassed UID reused the cached proxy decision, or lost fake-ip interception)", received, want)
			}
		})
	}
}

// runCgroupUIDHelper runs the helper inside the cgroup at path and returns the
// payloads the listener received, in arrival order.
func runCgroupUIDHelper(t *testing.T, path string, listener *net.UDPConn) []string {
	t.Helper()
	cgroupDir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroupDir.Close()

	payloads := make(chan string, 8)
	go func() {
		buffer := make([]byte, 64)
		for {
			n, _, err := listener.ReadFromUDP(buffer)
			if err != nil {
				close(payloads)
				return
			}
			payloads <- string(buffer[:n])
		}
	}()

	command := exec.Command(os.Args[0], "-test.run=^TestCgroupUIDPolicyHelperProcess$")
	command.Env = append(os.Environ(), cgroupUIDHelperEnv+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroupDir.Fd())}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
	// Redirected datagrams arrive over loopback before the helper can exit, the
	// wait only has to outlast scheduling.
	_ = listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var received []string
	for payload := range payloads {
		received = append(received, payload)
	}
	return received
}

// TestCgroupUIDPolicyHelperProcess is the helper runCgroupUIDHelper starts. It
// sends from one socket first as root, which the policy intercepts, then as the
// bypassed UID to the same destination and to a fake-ip address, then as root
// again.
func TestCgroupUIDPolicyHelperProcess(t *testing.T) {
	if os.Getenv(cgroupUIDHelperEnv) != "1" {
		t.Skip("helper for TestCgroupUIDPolicyPrecedesTheFlowCacheIntegration")
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(payload string, destination netip.AddrPort) {
		if _, err := conn.WriteToUDPAddrPort([]byte(payload), destination); err != nil {
			t.Fatalf("send %s: %v", payload, err)
		}
	}
	send("proxied-first", cgroupUIDPolicyTarget)
	if err = syscall.Setresuid(cgroupUIDBypassed, cgroupUIDBypassed, 0); err != nil {
		t.Fatal(err)
	}
	send("bypassed-cached", cgroupUIDPolicyTarget)
	send("bypassed-fakeip", cgroupUIDPolicyFakeIP)
	if err = syscall.Setresuid(0, 0, 0); err != nil {
		t.Fatal(err)
	}
	send("proxied-again", cgroupUIDPolicyTarget)
}
