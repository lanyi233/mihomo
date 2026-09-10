//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"testing"
	"unsafe"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/sys/unix"
)

// dropTunnel stands in for the tunnel: it consumes packets the way the real
// one eventually does, by dropping them after use.
type dropTunnel struct{}

func (dropTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) { _ = conn.Close() }
func (dropTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	packet.Drop()
}
func (dropTunnel) NatTable() C.NatTable { return nil }

func benchmarkPayload() []byte {
	data := pool.Get(1200)
	for index := range data {
		data[index] = byte(index)
	}
	return data
}

// BenchmarkForwardLocalUDP measures the per-packet tail of the local/TC path
// once the client is known: metadata, packet, NAT key, hand-off to the tunnel.
func BenchmarkForwardLocalUDP(b *testing.B) {
	inbound := &Inbound{tunnel: dropTunnel{}}
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		inbound.forwardLocalUDP(benchmarkPayload(), client, destination, false)
	}
}

// BenchmarkForwardSharedUDP is the same tail for the shared packet-rewrite
// path, which is the busiest one on a gateway.
func BenchmarkForwardSharedUDP(b *testing.B) {
	inbound := &Inbound{tunnel: dropTunnel{}}
	shared := &sharedRewrite{inbound: inbound}
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		shared.forwardSharedUDP(benchmarkPayload(), client, destination, nil)
	}
}

// BenchmarkPerPacketLocalAddr is what every packet used to pay before the NAT
// key address was cached on the client state: format the client address,
// allocate a net.UDPAddr, and box the custom address into an interface.
func BenchmarkPerPacketLocalAddr(b *testing.B) {
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	var sink net.Addr
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink = N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client))
	}
	_ = sink
}

// BenchmarkPacketDestinationsFromOOB walks the control messages the internal
// listener receives with every datagram (IP_PKTINFO + IP_RECVORIGDSTADDR).
func BenchmarkPacketDestinationsFromOOB(b *testing.B) {
	oob := benchmarkOOB()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, _, err := packetDestinationsFromOOB(oob); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOOB() []byte {
	pktinfo := unix.Inet4Pktinfo{Ifindex: 3}
	copy(pktinfo.Spec_dst[:], []byte{127, 128, 0, 9})
	copy(pktinfo.Addr[:], []byte{127, 128, 0, 9})
	oob := make([]byte, 0, 128)
	oob = appendCmsg(oob, unix.IPPROTO_IP, unix.IP_PKTINFO, (*[unix.SizeofInet4Pktinfo]byte)(unsafe.Pointer(&pktinfo))[:])
	original := unix.RawSockaddrInet4{Family: unix.AF_INET, Port: 0xbb01, Addr: [4]byte{198, 51, 100, 10}}
	oob = appendCmsg(oob, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, (*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&original))[:])
	return oob
}

func appendCmsg(oob []byte, level, typ int32, data []byte) []byte {
	space := unix.CmsgSpace(len(data))
	start := len(oob)
	oob = append(oob, make([]byte, space)...)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[start]))
	header.Level = level
	header.Type = typ
	header.SetLen(unix.CmsgLen(len(data)))
	copy(oob[start+unix.CmsgLen(0):], data)
	return oob
}
