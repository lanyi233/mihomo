//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	"net"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"
)

var tcPurgeOnce sync.Once

// purgeStaleTCFilters removes classic-TC filters this package left behind when
// a previous run died without detaching. TCX links go away on their own when
// their owner exits; classic filters do not, and an orphaned one keeps
// rewriting destinations to a redirect address nobody is listening on -- a
// black hole with no owner, no log, and no reason to go away across restarts.
//
// It takes each slot's abstract-socket lock before reclaiming that slot's
// filters. Slots held by live instances stay untouched. The
// kernel releases that lock when its owner dies, which is exactly the case this
// sweep is for.
func purgeStaleTCFilters() {
	links, err := netlink.LinkList()
	if err != nil {
		log.Debugln("[EBPF] list interfaces for stale TC filter sweep: %v", err)
		return
	}
	for _, device := range links {
		for slotIndex := range commonEBPF.MaxInstanceSlots {
			slot, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: commonEBPF.InstanceSlotName("@sing-box-ebpf-tc-"+strconv.Itoa(device.Attrs().Index), slotIndex), Net: "unixgram"})
			if err != nil {
				continue
			}
			if err = reclaimTCSlotFilters(device.Attrs().Index, slotIndex); err != nil {
				log.Debugln("[EBPF] reclaim stale TC slot: %v", err)
			}
			_ = slot.Close()
		}
	}
}
