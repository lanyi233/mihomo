//go:build with_ebpf && linux && ebpf_integration

package sing_ebpf

import (
	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	"github.com/sagernet/netlink"
	"os"
	"slices"
	"testing"
)

// newPassThroughTCProgram loads a classifier that hands every packet to the
// next program or filter.
func newPassThroughTCProgram(t *testing.T, name string) *CiliumEBPF.Program {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         name,
		Type:         CiliumEBPF.SchedCLS,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a classifier program in this environment: %v", err)
	}
	t.Cleanup(func() { _ = program.Close() })
	return program
}

func tcProgramID(t *testing.T, program *CiliumEBPF.Program) CiliumEBPF.ProgramID {
	t.Helper()
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return id
}

// TestTCXOrderedAttachFollowsPriority covers the order several runtimes share
// on one TCX hook: lower priorities run first, equal priorities keep their
// attach order, and a program without a priority marker is left where it is.
func TestTCXOrderedAttachFollowsPriority(t *testing.T) {
	enterRouteTestNetworkNamespace(t)
	self, _ := createTestVethPair(t, "sbtcxo0", "sbtcxo1")
	index := self.Attrs().Index
	attach := func(name string, priority uint16) CiliumEBPF.ProgramID {
		program := newPassThroughTCProgram(t, name)
		attached, err := commonEBPF.AttachTCXOrdered(index, CiliumEBPF.AttachTCXIngress, program, priority)
		if err != nil {
			if tcxUnsupportedError(err) {
				t.Skipf("TCX unavailable: %v", err)
			}
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = attached.Close() })
		return tcProgramID(t, program)
	}
	priority5 := attach("sb_test_p5", 5)
	foreignProgram := newPassThroughTCProgram(t, "foreign_tail")
	foreign, err := link.AttachTCX(link.TCXOptions{Interface: index, Program: foreignProgram, Attach: CiliumEBPF.AttachTCXIngress})
	if err != nil {
		t.Fatalf("attach a foreign program: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	priority1 := attach("sb_test_p1a", 1)
	priority3 := attach("sb_test_p3", 3)
	priority1Later := attach("sb_test_p1b", 1)

	result, err := link.QueryPrograms(link.QueryOptions{Target: index, Attach: CiliumEBPF.AttachTCXIngress})
	if err != nil {
		t.Fatal(err)
	}
	var order []CiliumEBPF.ProgramID
	for _, attached := range result.Programs {
		order = append(order, attached.ID)
	}
	want := []CiliumEBPF.ProgramID{priority1, priority1Later, priority3, priority5, tcProgramID(t, foreignProgram)}
	if !slices.Equal(order, want) {
		t.Fatalf("TCX order = %v, want %v (p1, p1 attached later, p3, p5, unmarked foreign program)", order, want)
	}
}

func TestTCInstancesKeepLiveFiltersDuringReclaimIntegration(t *testing.T) {
	enterRouteTestNetworkNamespace(t)
	old := tcxSupport.Swap(tcxSupportUnavailable)
	defer tcxSupport.Store(old)
	device, _ := createTestVethPair(t, "sbmulti0", "sbmulti1")
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{ListenerPort: 65530, EnableLocal: true, EnableShared: true, EnableIPv4: true, EnableTCP: true, Policy: policy, AssignmentCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	attach := func(priority uint16) *tcInterfaceAttachment {
		a, err := attachTCInterface(device, backend, tcInterfaceRole{local: true, shared: true}, false, priority)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		return a
	}
	first, second := attach(5), attach(1)
	if tcLockSlot(first.lock) == tcLockSlot(second.lock) {
		t.Fatal("instances share an interface slot")
	}
	check := func(a *tcInterfaceAttachment, priority uint16) {
		if ok, err := a.filtersAttached(priority, false); err != nil || !ok {
			t.Fatalf("live instance lost filters: %v %v", ok, err)
		}
	}
	check(first, 5)
	check(second, 1)
	stale, err := acquireTCInterfaceLock(device.Attrs().Name, device.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, backend.LocalEgressProgramFD(commonEBPF.TCLinkFramingEthernet), "sb_tc_local", tcLocalFilterHandle, 9, stale.Index())
	if err != nil {
		t.Fatal(err)
	}
	defer detachTCFilter(orphan)
	if err = stale.Close(); err != nil {
		t.Fatal(err)
	}
	purgeStaleTCFilters()
	check(first, 5)
	check(second, 1)
	if found, err := tcFilterAttached(device, orphan.Parent, orphan.Name, uint16(orphan.Handle), 9); err != nil || found {
		t.Fatalf("orphan not reclaimed: %v %v", found, err)
	}
	firstSlot := tcLockSlot(first.lock)
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	check(second, 1)
	third := attach(3)
	if tcLockSlot(third.lock) != firstSlot {
		t.Fatal("released interface slot was not reused")
	}
}

func TestSharedSysctlLeasesRestoreAfterLastInstanceIntegration(t *testing.T) {
	enterRouteTestNetworkNamespace(t)
	device, _ := createTestVethPair(t, "sblease0", "sblease1")
	name := device.Attrs().Name
	localnet := sharedRewriteLocalnetPath(name)
	arp := tcInterfaceSysctlPath(name, "arp_announce")
	if err := os.WriteFile(localnet, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arp, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	var first, second, firstARP, secondARP *commonEBPF.InstanceLease
	defer releaseSharedRewriteLocalnet(name, &first)
	defer releaseSharedRewriteLocalnet(name, &second)
	defer releaseSharedArpAnnounce(name, &firstARP)
	defer releaseSharedArpAnnounce(name, &secondARP)
	for _, lease := range []**commonEBPF.InstanceLease{&first, &second} {
		if err := claimSharedRewriteLocalnet(name, lease); err != nil {
			t.Fatal(err)
		}
	}
	for _, lease := range []**commonEBPF.InstanceLease{&firstARP, &secondARP} {
		if err := claimSharedArpAnnounce(name, lease); err != nil {
			t.Fatal(err)
		}
	}
	if err := releaseSharedRewriteLocalnet(name, &first); err != nil {
		t.Fatal(err)
	}
	if err := releaseSharedArpAnnounce(name, &firstARP); err != nil {
		t.Fatal(err)
	}
	if value, _ := readTCSysctl(localnet); value != "1" {
		t.Fatal("first instance restored a setting still leased")
	}
	if value, _ := readTCSysctl(arp); value != "2" {
		t.Fatal("first instance restored arp_announce still leased")
	}
	if err := releaseSharedRewriteLocalnet(name, &second); err != nil {
		t.Fatal(err)
	}
	if err := releaseSharedArpAnnounce(name, &secondARP); err != nil {
		t.Fatal(err)
	}
	if value, _ := readTCSysctl(localnet); value != "0" {
		t.Fatalf("last instance did not restore route_localnet: %s", value)
	}
	if value, _ := readTCSysctl(arp); value != "0" {
		t.Fatalf("last instance did not restore arp_announce: %s", value)
	}
}

func TestTCInterfaceRecreationKeepsPeerSlotIntegration(t *testing.T) {
	enterRouteTestNetworkNamespace(t)
	oldSupport := tcxSupport.Swap(tcxSupportUnavailable)
	defer tcxSupport.Store(oldSupport)
	device, _ := createTestVethPair(t, "sbrecreate0", "sbrecreate1")
	oldIndex := device.Attrs().Index
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{ListenerPort: 65530, EnableLocal: true, EnableIPv4: true, EnableTCP: true, Policy: policy, AssignmentCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	first, err := attachTCInterface(device, backend, tcInterfaceRole{local: true}, false, 5)
	if err != nil {
		t.Fatal(err)
	}
	plane := &tcDataPlane{backend: backend, attachments: []*tcInterfaceAttachment{first}, localInterface: device.Attrs().Name, priority: 5}
	defer plane.Close()
	if err = netlink.LinkDel(device); err != nil {
		t.Fatal(err)
	}
	replacement, _ := createTestVethPair(t, "sbrecreate0", "sbrecreate1")
	if replacement.Attrs().Index == oldIndex {
		t.Fatal("fixture reused the old ifindex")
	}
	peer, err := attachTCInterface(replacement, backend, tcInterfaceRole{local: true}, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = plane.reconcile(replacement.Attrs().Name, nil, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := peer.filtersAttached(1, false); err != nil || !ok {
		t.Fatalf("recreation removed peer filters: %v %v", ok, err)
	}
	if len(plane.attachments) != 1 || plane.attachments[0].interfaceIndex != replacement.Attrs().Index {
		t.Fatalf("replacement not installed: %+v", plane.attachments)
	}
	if tcLockSlot(plane.attachments[0].lock) == tcLockSlot(peer.lock) {
		t.Fatal("replacement reused the live peer's slot")
	}
	if !first.IsClosed() {
		t.Fatal("old interface slot was retained after successful detach")
	}
}
