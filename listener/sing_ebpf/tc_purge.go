//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"
)

var tcPurgeOnce sync.Once

// tcFilterNames is every classic-TC filter name this package installs at a
// fixed name. attachTCFilter clears a stale filter by name before attaching, so
// these are only left behind on an interface the next run does not attach to.
var tcFilterNames = map[string]struct{}{
	"sb_tc_local":    {},
	"sb_tc_shared":   {},
	"sb_tc_deliver":  {},
	"sb_share_in":    {},
	"sb_share_out":   {},
	"sb_icmp_local":  {},
	"sb_icmp_shared": {},
	"sb_icmp_share":  {},
}

// tcTemporaryFilterPrefixes are the names a rebuild uses while the attachment
// it replaces is still live. They carry a hex sequence, so the suffix is
// checked rather than matching the prefix alone.
var tcTemporaryFilterPrefixes = []string{"sbi", "sbo", "sbc"}

// ownedTCFilterName reports whether a filter name belongs to this package. The
// match is exact rather than a bare "sb" prefix on purpose: Android's tethering
// offload programs sit on the same hooks, and deleting one of those silently
// turns off kernel forwarding acceleration.
func ownedTCFilterName(name string) bool {
	if _, owned := tcFilterNames[name]; owned {
		return true
	}
	for _, prefix := range tcTemporaryFilterPrefixes {
		suffix, found := strings.CutPrefix(name, prefix)
		if !found || suffix == "" {
			continue
		}
		if _, err := strconv.ParseUint(suffix, 16, 32); err == nil {
			return true
		}
	}
	return false
}

// purgeStaleTCFilters removes classic-TC filters this package left behind when
// a previous run died without detaching. TCX links go away on their own when
// their owner exits; classic filters do not, and an orphaned one keeps
// rewriting destinations to a redirect address nobody is listening on -- a
// black hole with no owner, no log, and no reason to go away across restarts.
//
// It refuses to touch an interface another live inbound holds: the same
// abstract-socket lock the attachments use is taken first, so "nobody answers"
// is what distinguishes an orphan from a filter that is doing its job. The
// kernel releases that lock when its owner dies, which is exactly the case this
// sweep is for.
func purgeStaleTCFilters() {
	links, err := netlink.LinkList()
	if err != nil {
		log.Debugln("[EBPF] list interfaces for stale TC filter sweep: %v", err)
		return
	}
	for _, link := range links {
		attributes := link.Attrs()
		lock, err := acquireTCInterfaceLock(attributes.Name, attributes.Index)
		if err != nil {
			// Held by a live inbound, so anything here has an owner.
			continue
		}
		purgeStaleTCFiltersOn(link, netlink.HANDLE_MIN_INGRESS)
		purgeStaleTCFiltersOn(link, netlink.HANDLE_MIN_EGRESS)
		_ = lock.Close()
	}
}

func purgeStaleTCFiltersOn(link netlink.Link, parent uint32) {
	// An interface with no clsact qdisc errors here, which is the common case.
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return
	}
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || !ownedTCFilterName(bpfFilter.Name) {
			continue
		}
		if err = netlink.FilterDel(filter); err != nil {
			log.Warnln("[EBPF] delete stale TC filter %s from %s: %v", bpfFilter.Name, link.Attrs().Name, err)
			continue
		}
		log.Infoln("[EBPF] removed stale TC filter %s left on %s by a previous run", bpfFilter.Name, link.Attrs().Name)
	}
}
