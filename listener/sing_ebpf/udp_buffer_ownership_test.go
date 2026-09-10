//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	"net/netip"
	"testing"
)

type trackingPacketAllocator struct {
	pool.Allocator
	returned [][]byte
}

func (a *trackingPacketAllocator) Put(b []byte) error { a.returned = append(a.returned, b); return nil }

func TestRejectedUDPPayloadReturnedOnce(t *testing.T) {
	original := pool.DefaultAllocator
	tracker := &trackingPacketAllocator{Allocator: original}
	pool.DefaultAllocator = tracker
	defer func() { pool.DefaultAllocator = original }()
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	for name, reject := range map[string]func([]byte){
		"local_closed":           func(b []byte) { (&Inbound{}).NewPacket(b, benchmarkOOB(), client) },
		"cgroup_closed":          func(b []byte) { (&Inbound{}).newCgroupPacket(b, netip.MustParseAddr("127.128.0.2"), client) },
		"tc_missing_destination": func(b []byte) { (&Inbound{}).newTCPacket(nil, b, netip.AddrPort{}, 0, client) },
		"tc_closed_map": func(b []byte) {
			(&Inbound{}).newTCPacket(&ECommon.TCBackend{}, b, netip.MustParseAddrPort("1.1.1.1:443"), 0, client)
		},
		"shared_closed": func(b []byte) { (&sharedRewrite{}).NewPacket(b, nil, client) },
		"shared_closed_map": func(b []byte) {
			(&sharedRewrite{inbound: &Inbound{}, sharedBackend: &ECommon.SharedNetworkBackend{}}).NewPacket(b, benchmarkOOB(), client)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tracker.returned = nil
			payload := make([]byte, 100)
			reject(payload)
			if len(tracker.returned) != 1 || &tracker.returned[0][0] != &payload[0] {
				t.Fatalf("payload returned %d times", len(tracker.returned))
			}
		})
	}
}
