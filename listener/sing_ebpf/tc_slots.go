//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"io"
	"strconv"
	"strings"
)

// tcLockSlot is the instance slot an interface lock holds. Test doubles that
// are not slots behave as slot 0.
func tcLockSlot(lock io.Closer) int {
	slot, loaded := lock.(interface{ Index() int })
	if !loaded || slot == nil {
		return 0
	}
	return slot.Index()
}

type tcFilterRole uint8

const (
	tcFilterRoleLocal tcFilterRole = iota
	tcFilterRoleShared
	tcFilterRoleLocalICMP
	tcFilterRoleSharedICMP
	tcFilterRoleRewriteIngress
	tcFilterRoleRewriteEgress
	tcFilterRoleRewriteICMP
	tcFilterRoleCount
)

// tcFilterIdentity is the kernel identity of one sing-ebpf clsact filter.
type tcFilterIdentity struct {
	parent uint32
	name   string
	handle uint16
}

// tcLegacyFilterIdentities are the names and handles of slot 0, generation 0.
// They are the ones single-instance builds used, so a slot-0 owner reclaims and
// health-checks exactly what such a build leaves behind.
var tcLegacyFilterIdentities = [tcFilterRoleCount]tcFilterIdentity{
	tcFilterRoleLocal:          {netlink.HANDLE_MIN_EGRESS, "sb_tc_local", tcLocalFilterHandle},
	tcFilterRoleShared:         {netlink.HANDLE_MIN_INGRESS, "sb_tc_shared", tcSharedFilterHandle},
	tcFilterRoleLocalICMP:      {netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle},
	tcFilterRoleSharedICMP:     {netlink.HANDLE_MIN_INGRESS, "sb_icmp_shared", tcSharedICMPReplyFilterHandle},
	tcFilterRoleRewriteIngress: {netlink.HANDLE_MIN_INGRESS, "sb_share_in", sharedRewriteIngressFilterHandle},
	tcFilterRoleRewriteEgress:  {netlink.HANDLE_MIN_EGRESS, "sb_share_out", sharedRewriteEgressFilterHandle},
	tcFilterRoleRewriteICMP:    {netlink.HANDLE_MIN_INGRESS, "sb_icmp_share", sharedRewriteICMPFilterHandle},
}

// tcSlotFilterHandleBase starts the handle range of every other slot and
// generation. Older builds gave make-before-break packet-rewrite filters
// handles of up to 0x6348, so the range starts above that.
const tcSlotFilterHandleBase = 0x7000

// tcFilterGenerations bounds the make-before-break generations of one slot.
const tcFilterGenerations = 16

// tcSlotFilter names a filter by the interface slot that owns it, the
// generation of a make-before-break replacement, and its role. Two instances
// on one interface hold different slots and therefore never touch each other's
// filters, and two attachments of one slot that have filters at the same time
// use different generations.
func tcSlotFilter(slot int, generation int, role tcFilterRole) tcFilterIdentity {
	identity := tcLegacyFilterIdentities[role]
	if slot == 0 && generation == 0 {
		return identity
	}
	identity.name += "." + strconv.FormatUint(uint64(slot), 16)
	if generation != 0 {
		identity.name += "g" + strconv.FormatUint(uint64(generation), 16)
	}
	identity.handle = uint16(tcSlotFilterHandleBase | slot<<8 | generation<<4 | int(role))
	return identity
}

// tcSlotOwnsFilter reports whether a filter name belongs to slot. A slot-0
// owner also owns the make-before-break names of single-instance builds
// ("sbi", "sbo" or "sbc" and up to three hex digits): those builds held the
// slot-0 lock while they existed.
func tcSlotOwnsFilter(slot int, name string) bool {
	for role := range tcFilterRoleCount {
		for generation := range tcFilterGenerations {
			if tcSlotFilter(slot, generation, role).name == name {
				return true
			}
		}
	}
	return slot == 0 && legacyTemporaryTCFilterName(name)
}

func legacyTemporaryTCFilterName(name string) bool {
	if len(name) < 4 || len(name) > 6 || !strings.HasPrefix(name, "sb") {
		return false
	}
	switch name[2] {
	case 'i', 'o', 'c':
	default:
		return false
	}
	_, err := strconv.ParseUint(name[3:], 16, 16)
	return err == nil
}

// reclaimTCSlotFilters removes the clsact filters a previous holder of slot
// left on the interface. The caller holds the slot, so no live instance owns
// them.
func reclaimTCSlotFilters(interfaceIndex int, slot int) error {
	device, err := netlink.LinkByIndex(interfaceIndex)
	if err != nil {
		if tcLinkNotFound(err) {
			return nil
		}
		return err
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(device, parent)
		if err != nil {
			if tcFilterListAbsent(err) {
				continue
			}
			return err
		}
		for _, filter := range filters {
			bpfFilter, isBPF := filter.(*netlink.BpfFilter)
			if !isBPF || !tcSlotOwnsFilter(slot, bpfFilter.Name) {
				continue
			}
			if err = netlink.FilterDel(filter); err != nil && !tcFilterListAbsent(err) {
				return err
			}
		}
	}
	return nil
}

// tcFilterListAbsent covers a filter, qdisc or interface that is already gone.
func tcFilterListAbsent(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EINVAL)
}

func tcSlotIdentity(name string, handle uint16, slot int) (string, uint16) {
	for role, identity := range tcLegacyFilterIdentities {
		if name == identity.name {
			current := tcSlotFilter(slot, 0, tcFilterRole(role))
			return current.name, current.handle
		}
	}
	return name, handle
}
