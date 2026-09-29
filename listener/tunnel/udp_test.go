package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// packetRecorder hands every UDP packet to the test the way the tunnel sees it:
// wrapped in the PacketAdapter whose Key() picks the NAT session.
type packetRecorder struct{ packets chan C.PacketAdapter }

func (r *packetRecorder) HandleTCPConn(conn net.Conn, _ *C.Metadata) { _ = conn.Close() }

func (r *packetRecorder) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	r.packets <- C.NewPacketAdapter(packet, metadata)
}

func (r *packetRecorder) NatTable() C.NatTable { return nil }

func (r *packetRecorder) next(t *testing.T) C.PacketAdapter {
	t.Helper()
	select {
	case packet := <-r.packets:
		return packet
	case <-time.After(5 * time.Second):
		t.Fatal("no packet reached the tunnel")
		return nil
	}
}

func newTestUDPTunnel(t *testing.T, target string, tunnel C.Tunnel) *PacketConn {
	t.Helper()
	l, err := NewUDP("127.0.0.1:0", target, "", inbound.NewListenConfig(), tunnel)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// One client socket talking to several tunnel listeners (a WireGuard interface
// with a peer behind each one, issue #3052) must get a NAT session per
// listener. The tunnel keys sessions by Key(), and when that was only the
// client address the second listener's packets joined the first one's
// session: its rule decision, and replies written back through whichever
// listener received the latest packet.
func TestUDPTunnelListenersKeepSeparateSessionsForOneClientSocket(t *testing.T) {
	recorder := &packetRecorder{packets: make(chan C.PacketAdapter, 8)}
	a := newTestUDPTunnel(t, "10.0.0.20:51820", recorder)
	b := newTestUDPTunnel(t, "10.0.0.21:51821", recorder)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer client.Close()
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	send := func(l *PacketConn) C.PacketAdapter {
		t.Helper()
		addr, err := net.ResolveUDPAddr("udp", l.Address())
		require.NoError(t, err)
		_, err = client.WriteTo([]byte("ping"), addr)
		require.NoError(t, err)
		return recorder.next(t)
	}

	first := send(a)
	again := send(a)
	other := send(b)

	require.Equal(t, first.Key(), again.Key(), "one listener and one client socket are one session")
	require.NotEqual(t, first.Key(), other.Key(), "the same client socket reaching another listener is another session")

	require.Equal(t, "10.0.0.21", other.Metadata().DstIP.String())
	require.EqualValues(t, 51821, other.Metadata().DstPort)
	require.Equal(t, "127.0.0.1", other.Metadata().SrcIP.String())
	require.EqualValues(t, clientAddr.Port, other.Metadata().SrcPort)

	// Replies still leave through the listener the packet came in on.
	_, err = other.WriteBack([]byte("pong"), nil)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 16)
	n, from, err := client.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf[:n]))
	require.Equal(t, b.Address(), from.String())
}
