//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// attachMultiTestProgram reproduces a legacy BPF_PROG_ATTACH with
// BPF_F_ALLOW_MULTI. Like attachExclusiveTestProgram, the program stays
// attached after its descriptor is closed, as one left behind by an exited
// process does.
func attachMultiTestProgram(t *testing.T, cgroupFile *os.File, name string) {
	t.Helper()
	program := newHookOwnerTestProgram(t, name)
	defer program.Close()
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  CiliumEBPF.AttachCGroupInet4Connect,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	}); err != nil {
		t.Fatal(err)
	}
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	t.Cleanup(func() {
		if leftover, openErr := CiliumEBPF.NewProgramFromID(id); openErr == nil {
			_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInet4Connect)
			_ = leftover.Close()
		}
	})
}

func countNames(names []string, name string) int {
	count := 0
	for _, candidate := range names {
		if candidate == name {
			count++
		}
	}
	return count
}

// TestCgroupBackendsShareACgroupIntegration covers several interception
// backends on one cgroup. Each takes a slot of its own, and one that starts
// beside a live backend reclaims only the stale programs of its own slot; the
// first to start on a cgroup with no live backend reclaims every slot's.
func TestCgroupBackendsShareACgroupIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 300)
	slot0 := "sb_ebpf_conn4"
	slot1 := cgroupKernelProgramName("sb_ebpf_conn4", 1)
	slot2 := cgroupKernelProgramName("sb_ebpf_conn4", 2)

	first, err := attachTCPCgroupBackend(t, path, 41200)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup attach is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if first.InstanceSlot() != 0 {
		t.Fatalf("the first backend took slot %d, want 0", first.InstanceSlot())
	}
	// Leftovers of dead backends in slots 1 and 2.
	attachMultiTestProgram(t, cgroupFile, slot1)
	attachMultiTestProgram(t, cgroupFile, slot2)

	second, err := attachTCPCgroupBackend(t, path, 41201)
	if err != nil {
		t.Fatalf("a second backend could not share the cgroup: %v", err)
	}
	if second.InstanceSlot() != 1 {
		t.Fatalf("the second backend took slot %d, want 1", second.InstanceSlot())
	}
	names := connect4ProgramNames(t, cgroupFile)
	if countNames(names, slot0) != 1 || countNames(names, slot1) != 1 || countNames(names, slot2) != 1 {
		t.Fatalf("connect4 programs = %v; want the live slot-0 backend, the slot-1 backend replacing its "+
			"leftover, and the slot-2 leftover no live backend can vouch for", names)
	}

	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	names = connect4ProgramNames(t, cgroupFile)
	if countNames(names, slot0) != 0 || countNames(names, slot1) != 1 {
		t.Fatalf("connect4 programs after closing the first backend = %v", names)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := attachTCPCgroupBackend(t, path, 41202)
	if err != nil {
		t.Fatal(err)
	}
	if third.InstanceSlot() != 0 {
		t.Fatalf("the third backend took slot %d, want the released slot 0", third.InstanceSlot())
	}
	if names = connect4ProgramNames(t, cgroupFile); !slices.Equal(names, []string{slot0}) {
		t.Fatalf("connect4 programs = %v; the only backend alive should have reclaimed every leftover", names)
	}
}

func prepareIPv6CgroupBackend(t *testing.T, path string, redirectIPv6 netip.Prefix, port uint16) *CgroupBackend {
	t.Helper()
	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer selfBypassMap.Close()
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableTCP:     true,
		EnableIPv6:    true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:  redirectIPv6,
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(port); err != nil {
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		t.Fatal(err)
	}
	return backend
}

// tcpRedirects lists the redirect entries a backend's connect hooks recorded.
func tcpRedirects(t *testing.T, backend *CgroupBackend) map[listenerLookupKey]originalDestinationValue {
	t.Helper()
	entries := make(map[listenerLookupKey]originalDestinationValue)
	var key listenerLookupKey
	var value originalDestinationValue
	iterator := backend.runtime.maps["cgroup_tcp_redirect"].Iterate()
	for iterator.Next(&key, &value) {
		entries[key] = value
	}
	if err := iterator.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}

// connectIPv6 starts a TCP connection so the cgroup connect hooks run. The
// rewritten destination has no route in this test, so the attempt itself
// fails; only the hooks' bookkeeping is examined.
func connectIPv6(t *testing.T, destination netip.AddrPort) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrInet6{Port: int(destination.Port()), Addr: destination.Addr().As16()})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.ENETUNREACH) &&
		!errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("connect: %v", err)
	}
}

// TestCgroupBackendsDoNotRedirectEachOthersIPv6TokensIntegration covers two
// backends whose connect hooks a socket runs through one after the other.
// The later one sees the token the earlier one redirected to and must leave it
// alone; IPv4 tokens are loopback addresses and safe already, IPv6 tokens are
// recognized by their marker.
func TestCgroupBackendsDoNotRedirectEachOthersIPv6TokensIntegration(t *testing.T) {
	path, _ := dedicatedHookOwnerCgroup(t, 301)
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skip(err)
	}
	firstPrefix := netip.MustParsePrefix("fd53:696e:672d:1::/64")
	first := prepareIPv6CgroupBackend(t, path, firstPrefix, 41210)
	second := prepareIPv6CgroupBackend(t, path, netip.MustParsePrefix("fd53:696e:672d:2::/64"), 41211)
	moveCurrentProcessToCgroup(t, path, root)

	destination := netip.MustParseAddrPort("[2001:db8::1]:443")
	connectIPv6(t, destination)
	firstEntries := tcpRedirects(t, first)
	if len(firstEntries) != 1 {
		t.Fatalf("the first backend recorded %d redirects, want 1", len(firstEntries))
	}
	for key, original := range firstEntries {
		token := netip.AddrFrom16(key.TokenAddr)
		if !firstPrefix.Contains(token) || key.TokenAddr[8] != 0x5e || key.TokenAddr[9] != 0xb6 {
			t.Fatalf("token %s lacks the first backend's prefix or the token marker", token)
		}
		if netip.AddrFrom16(original.Addr) != destination.Addr() {
			t.Fatalf("the first backend recorded original %s, want %s", netip.AddrFrom16(original.Addr), destination.Addr())
		}
	}
	if entries := tcpRedirects(t, second); len(entries) != 0 {
		t.Fatalf("the second backend redirected the first backend's token again: %v", entries)
	}

	// Alone, the second backend intercepts the same destination, so the check
	// above is the token marker at work rather than its policy.
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	connectIPv6(t, destination)
	if entries := tcpRedirects(t, second); len(entries) != 1 {
		t.Fatalf("the second backend alone recorded %d redirects, want 1", len(entries))
	}
}
