//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
)

// The tunnel keys its NAT table on LocalAddr().String(), so the address has to
// be stable per client -- and building it once per client rather than per
// packet is the whole point of caching it.
func TestLocalAddrIsBuiltOncePerClient(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	state := table.loadOrCreate(client)

	first := state.localAddr(client)
	second := state.localAddr(client)
	if first != second {
		t.Fatalf("expected the cached address to be reused, got %p and %p", first, second)
	}
	if first.String() != client.String() {
		t.Fatalf("NAT key changed: %q != %q", first.String(), client.String())
	}
	if first.Network() != C.EBPF.String() {
		t.Fatalf("unexpected network %q", first.Network())
	}
	if allocs := testing.AllocsPerRun(100, func() { state.localAddr(client) }); allocs != 0 {
		t.Fatalf("cached localAddr allocates %v per call", allocs)
	}

	var shared sharedUDPClientTable
	sharedState := shared.loadOrCreate(client)
	if sharedState.localAddr(client) != sharedState.localAddr(client) {
		t.Fatal("expected the shared client address to be reused")
	}
	if sharedState.localAddr(client).String() != client.String() {
		t.Fatal("shared NAT key changed")
	}
}

// The TC data plane validates a flow against the kernel assignment map once;
// packets that follow reuse the binding. A reply alias -- installed because a
// remote answered from a new address -- is not such a validation and must not
// short-circuit the lookup.
func TestHasDirectBindingTracksValidatedFlowsOnly(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	alias := netip.MustParseAddrPort("198.51.100.11:443")

	if table.hasDirectBinding(client, destination) {
		t.Fatal("unknown client must not have a binding")
	}
	table.setDirectBinding(client, destination, nil, 42)
	if !table.hasDirectBinding(client, destination) {
		t.Fatal("expected the validated flow to be cached")
	}
	if table.hasDirectBinding(client, alias) {
		t.Fatal("a destination that was never validated must not be cached")
	}

	state, _ := table.load(client)
	if !table.setDirectReplyBinding(client, state, alias) {
		t.Fatal("reply alias was rejected")
	}
	if table.hasDirectBinding(client, alias) {
		t.Fatal("a reply alias must not count as a validated flow")
	}

	binding, loaded, cgroup := state.replyBinding(destination)
	if !loaded || cgroup || binding.replyAlias {
		t.Fatalf("unexpected reply binding state: loaded=%v cgroup=%v alias=%v", loaded, cgroup, binding.replyAlias)
	}

	table.delete(client, state)
	if table.hasDirectBinding(client, destination) {
		t.Fatal("a deleted client must not keep its bindings")
	}
}

// The read loop hands each datagram to the packet in a pooled buffer and the
// tunnel calls Drop when the outbound has written it. Drop has to give the
// buffer back exactly once -- the tunnel drops a packet on several paths -- and
// must not leave the caller a buffer it can still read through Data().
type droppablePacket interface {
	Data() []byte
	Drop()
}

func TestUDPPacketDropReturnsBufferOnce(t *testing.T) {
	for name, newPacket := range map[string]func([]byte) droppablePacket{
		"local":  func(data []byte) droppablePacket { return &udpPacket{data: data} },
		"shared": func(data []byte) droppablePacket { return &sharedRewritePacket{data: data} },
	} {
		t.Run(name, func(t *testing.T) {
			data := pool.Get(1200)
			packet := newPacket(data)
			if len(packet.Data()) != 1200 {
				t.Fatalf("unexpected payload length %d", len(packet.Data()))
			}
			packet.Drop()
			if packet.Data() != nil {
				t.Fatal("Drop must detach the buffer from the packet")
			}
			// A second Drop must be harmless: the buffer is already back in the
			// pool and handing it back again would let two owners share it.
			packet.Drop()
		})
	}
}

// A client on the cgroup data plane reports so through the same read as the
// binding, and never matches the TC fast path.
func TestReplyBindingReportsCgroupDataPlane(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	redirect := netip.MustParseAddr("127.128.0.10")
	table.setCgroupBinding(client, ECommon.OriginalDestination{Destination: destination}, redirect)

	state, _ := table.load(client)
	binding, loaded, cgroup := state.replyBinding(destination)
	if !loaded || !cgroup || binding.redirectAddress != redirect || len(binding.packetInfo) == 0 {
		t.Fatalf("unexpected cgroup reply binding: loaded=%v cgroup=%v binding=%+v", loaded, cgroup, binding)
	}
	if table.hasDirectBinding(client, destination) {
		t.Fatal("a cgroup client must not take the TC fast path")
	}
}
