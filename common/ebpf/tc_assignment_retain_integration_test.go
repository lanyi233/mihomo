//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A failed sk_assign drops one packet and must leave the flow's assignment where
// it was. Recording first and deleting on failure took a live flow's entry on a
// single transient failure. BPF_PROG_TEST_RUN runs the program off the ingress
// path, where the kernel refuses every sk_assign, which is the failure needed.
func TestTCFailedSocketAssignKeepsTheAssignmentIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run TC socket assignment against a refused sk_assign")
	requireTCSocketAssignment(t)
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65530,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	if backend.TCPListenerLookupMode() != "sockmap" {
		t.Skip("kernel lacks the SOCKMAP listener lookup this test finds the socket through")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listenerFile, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer listenerFile.Close()
	if err = backend.RegisterTCPListener(false, int(listenerFile.Fd())); err != nil {
		t.Fatal(err)
	}

	source := netip.MustParseAddrPort("192.0.2.10:53100")
	destination := netip.MustParseAddrPort("203.0.113.10:443")
	key, err := makeTCAssignKey(unix.IPPROTO_TCP, source, destination, 0)
	if err != nil {
		t.Fatal(err)
	}
	live := TCAssignment{SocketCookie: 0x5ab1e, InterfaceIndex: 7, Path: 1}
	if err = updateMap(backend.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&live)); err != nil {
		t.Fatalf("seed the live assignment: %v", err)
	}

	packet := testIPv4TCPPacket(source.Addr(), destination.Addr(), source.Port(), destination.Port())
	action, _ := runTCProgram(t, backend.runtime.programs[tcProgramSharedIngressEthernet], packet)
	if action != testTCActShot {
		t.Fatalf("selected flow was not dropped on a refused sk_assign: action=%d", action)
	}
	stats, err := backend.TCStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SKAssignFailed != 1 || stats.ListenerSocketMissing != 0 {
		t.Fatalf("the packet did not reach a refused sk_assign: %+v", stats)
	}

	kept, err := backend.LookupAssignment(unix.IPPROTO_TCP, source, destination, 0, false)
	if err != nil {
		t.Fatalf("a refused sk_assign removed the flow's assignment: %v", err)
	}
	if kept != live {
		t.Fatalf("a refused sk_assign rewrote the flow's assignment: got %+v, want %+v", kept, live)
	}
}
