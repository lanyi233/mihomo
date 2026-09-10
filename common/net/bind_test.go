package net

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

func TestDNSBindPacketConnDropsUnexpectedSource(t *testing.T) {
	packetConn := &scriptedPacketConn{packets: []scriptedPacket{
		{data: []byte("wrong"), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 53}},
		{data: []byte("right"), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}},
	}}
	target := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 53)
	conn := NewDNSBindPacketConn(packetConn, target)

	buffer := make([]byte, 16)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "right" {
		t.Fatalf("unexpected packet accepted: %q", got)
	}
	if got := packetConn.readCount(); got != 2 {
		t.Fatalf("expected two packet reads, got %d", got)
	}
}

func TestDNSBindPacketConnWaitReadReturnsRejectedBuffer(t *testing.T) {
	packetConn := &scriptedPacketConn{packets: []scriptedPacket{
		{data: []byte("wrong"), addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 53}},
		{data: []byte("right"), addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}},
	}}
	conn := NewDNSBindPacketConn(packetConn, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53})
	waiter, ok := conn.(interface {
		WaitRead() ([]byte, func(), error)
	})
	if !ok {
		t.Fatal("DNS bound connection lost WaitRead support")
	}

	data, put, err := waiter.WaitRead()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "right" {
		t.Fatalf("unexpected packet accepted: %q", got)
	}
	if got := packetConn.putCount(); got != 1 {
		t.Fatalf("rejected buffer was not returned exactly once: %d", got)
	}
	put()
	if got := packetConn.putCount(); got != 2 {
		t.Fatalf("accepted buffer return callback failed: %d", got)
	}
}

func TestLegacyBindPacketConnKeepsPermissiveSourceBehavior(t *testing.T) {
	packetConn := &scriptedPacketConn{packets: []scriptedPacket{
		{data: []byte("legacy"), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 53}},
	}}
	conn := NewBindPacketConn(packetConn, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53})
	buffer := make([]byte, 16)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "legacy" {
		t.Fatalf("legacy bind behavior changed: %q", got)
	}
}

type scriptedPacket struct {
	data []byte
	addr net.Addr
}

type scriptedPacketConn struct {
	mu      sync.Mutex
	packets []scriptedPacket
	reads   int
	puts    int
}

func (c *scriptedPacketConn) nextPacket() (scriptedPacket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.packets) == 0 {
		return scriptedPacket{}, errors.New("no scripted packet")
	}
	packet := c.packets[0]
	c.packets = c.packets[1:]
	c.reads++
	return packet, nil
}

func (c *scriptedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	packet, err := c.nextPacket()
	if err != nil {
		return 0, nil, err
	}
	return copy(buffer, packet.data), packet.addr, nil
}

func (c *scriptedPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	packet, err := c.nextPacket()
	if err != nil {
		return nil, nil, nil, err
	}
	return packet.data, func() {
		c.mu.Lock()
		c.puts++
		c.mu.Unlock()
	}, packet.addr, nil
}

func (c *scriptedPacketConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	return len(buffer), nil
}

func (c *scriptedPacketConn) Close() error                     { return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *scriptedPacketConn) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *scriptedPacketConn) putCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}
