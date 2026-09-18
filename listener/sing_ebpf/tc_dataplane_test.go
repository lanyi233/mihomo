//go:build with_ebpf && (linux || android)

// Regression cases adapted from CHIZI-0618/sing-box at 4af7ae48.
package sing_ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestTCXUnsupportedError(t *testing.T) {
	if !tcxUnsupportedError(CiliumEBPF.ErrNotSupported) ||
		!tcxUnsupportedError(errors.Join(errors.New("attach"), unix.EOPNOTSUPP)) ||
		!tcxUnsupportedError(unix.ENOSYS) {
		t.Fatal("expected unsupported TCX errors to be classified")
	}
	if tcxUnsupportedError(unix.EPERM) || tcxUnsupportedError(unix.EINVAL) {
		t.Fatal("permission and interface-specific errors must not disable TCX globally")
	}
}

func TestTCVethNamesFitLinuxLimit(t *testing.T) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(redirectName) > 15 || len(deliveryName) > 15 {
		t.Fatalf("delivery link names exceed Linux limit: %q %q", redirectName, deliveryName)
	}
	if redirectName == deliveryName {
		t.Fatal("delivery link names are identical")
	}
}

func TestRetainLocalAttachmentStatesDuringHandoff(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"wlan2": {
			index:   2,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{shared: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("", desired, attachments)

	state, loaded := desired["rmnet_data1"]
	if !loaded {
		t.Fatal("local attachment was not retained while default interface was unavailable")
	}
	if state.index != 19 || state.framing != commonEBPF.TCLinkFramingRawIP || !state.role.local {
		t.Fatalf("unexpected retained local state: %+v", state)
	}
	if _, loaded = desired["wlan2"]; !loaded {
		t.Fatal("shared attachment was dropped while retaining local attachment")
	}
}

func TestRetainLocalAttachmentStatesDoesNotOverrideNewDefault(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"rmnet_data2": {
			index:   20,
			framing: commonEBPF.TCLinkFramingRawIP,
			role:    tcInterfaceRole{local: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("rmnet_data2", desired, attachments)

	if _, loaded := desired["rmnet_data1"]; loaded {
		t.Fatal("stale local attachment was retained after a new default interface appeared")
	}
}

func TestHandoffTCGlobalSysctls(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].path != "all/rp_filter" {
		t.Fatalf("new delivery did not receive global sysctl ownership: %+v", next.globalSysctls)
	}
}

func TestHandoffTCGlobalSysctlsKeepsFreshState(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "2"}},
	}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].original != "2" {
		t.Fatalf("new delivery state was unexpectedly replaced: %+v", next.globalSysctls)
	}
}

func TestRestoreTCSysctlStatesPreservesExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rp_filter")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, changed, err := setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl: changed=%v err=%v", changed, err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "1" {
		t.Fatalf("sysctl was not restored: value=%q err=%v", value, err)
	}

	state, changed, err = setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl for external change: changed=%v err=%v", changed, err)
	}
	if err = os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err = os.ReadFile(path)
	if err != nil || string(value) != "2\n" {
		t.Fatalf("external sysctl change was overwritten: value=%q err=%v", value, err)
	}
}

func TestTransitionTCXInterfaceRoleAttachesBeforeDetach(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{local: true},
		tcInterfaceRole{shared: true},
		true,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
			} else {
				events = append(events, "attach-shared")
			}
			return nil
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX transition order: got %v, want %v", events, want)
	}
}

func TestTransitionTCXInterfaceRoleRollsBackNewLinks(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{},
		tcInterfaceRole{local: true, shared: true},
		false,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
				return nil
			}
			events = append(events, "attach-shared")
			return errors.New("shared attach failed")
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected TCX transition failure")
	}
	want := []string{"attach-local", "attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX rollback order: got %v, want %v", events, want)
	}
}

// The interface lock is named after the interface index, not the interface, so
// retaining an attachment whose index the kernel has already handed to a
// different interface makes both claim one lock.
func TestRetainLocalAttachmentStatesDropsReusedIndex(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"rmnet_data0": {
			index:   5,
			framing: commonEBPF.TCLinkFramingRawIP,
			role:    tcInterfaceRole{shared: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "wlan0",
			interfaceIndex: 5,
			framing:        commonEBPF.TCLinkFramingEthernet,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("", desired, attachments)

	if _, loaded := desired["wlan0"]; loaded {
		t.Fatal("retained a local attachment whose index another interface now claims")
	}
	if state := desired["rmnet_data0"]; state.index != 5 || state.role.local {
		t.Fatalf("interface that owns the index was disturbed: %+v", state)
	}
}

// A detach that fails must leave the attachment owning both the program and the
// interface lock, or the next attach installs a duplicate filter on top of an
// orphan.
func TestAttachmentKeepsLockWhileDetachFails(t *testing.T) {
	var released bool
	attachment := &tcInterfaceAttachment{
		interfaceName: "wlan0",
		localFilter:   &netlink.BpfFilter{},
		lock:          closerFunc(func() error { released = true; return nil }),
		lockOwned:     true,
		detachFilter:  func(*netlink.BpfFilter) error { return errors.New("device busy") },
	}

	if err := attachment.Close(); err == nil {
		t.Fatal("Close reported success while the filter was still attached")
	}
	if released {
		t.Fatal("interface lock was released while a filter was still attached")
	}
	if attachment.IsClosed() {
		t.Fatal("attachment reported itself closed with a filter still attached")
	}

	attachment.detachFilter = func(*netlink.BpfFilter) error { return nil }
	if err := attachment.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if !released {
		t.Fatal("interface lock was not released once the filter detached")
	}
	if !attachment.IsClosed() {
		t.Fatal("attachment still reports resources after a clean close")
	}
}

// A reconcile that cannot detach has to retry on the next pass rather than
// forget the attachment.
func TestDataPlaneRetriesRetiredAttachments(t *testing.T) {
	fail := true
	attachment := &tcInterfaceAttachment{
		interfaceName: "wlan0",
		localFilter:   &netlink.BpfFilter{},
		lockOwned:     true,
		lock:          closerFunc(func() error { return nil }),
		detachFilter: func(*netlink.BpfFilter) error {
			if fail {
				return errors.New("device busy")
			}
			return nil
		},
	}
	plane := &tcDataPlane{}

	_ = attachment.Close()
	plane.retire(attachment)
	if len(plane.retiredAttachments) != 1 {
		t.Fatalf("attachment that failed to detach was not retired: %d", len(plane.retiredAttachments))
	}
	if err := plane.closeRetired(); err == nil {
		t.Fatal("retry reported success while the kernel still refused")
	}
	if len(plane.retiredAttachments) != 1 {
		t.Fatal("retired attachment was dropped while still attached")
	}

	fail = false
	if err := plane.closeRetired(); err != nil {
		t.Fatalf("retry failed once the kernel let go: %v", err)
	}
	if len(plane.retiredAttachments) != 0 {
		t.Fatal("released attachment stayed on the retired list")
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// The purge deletes by name, and Android's tethering-offload programs sit on
// the same hooks, so the predicate has to be exact rather than a bare "sb"
// prefix -- deleting one of those silently turns off forwarding acceleration.
func TestOwnedTCFilterNameMatchesOnlyOurOwn(t *testing.T) {
	for _, name := range []string{
		"sb_tc_local", "sb_tc_shared", "sb_tc_deliver",
		"sb_share_in", "sb_share_out",
		"sb_icmp_local", "sb_icmp_shared", "sb_icmp_share",
		"sbi1", "sbo1", "sbc1", "sbifff", "sboa2c",
	} {
		if !ownedTCFilterName(name) {
			t.Errorf("own filter %q was not recognised, so a restart leaks it", name)
		}
	}
	for _, name := range []string{
		"", "sb", "sbi", "sbo", "sbc",
		"sbix", "sbo-1", "sbc 1",
		"sb_tc", "sb_tc_localx", "xsb_tc_local",
		"offload", "sched_cls_tether_downstream6_ether", "bpf_prog",
	} {
		if ownedTCFilterName(name) {
			t.Errorf("foreign filter %q would be deleted by the startup purge", name)
		}
	}
}
