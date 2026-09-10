package net

import (
	"net"
	"net/netip"
	"strconv"
)

type bindPacketConn struct {
	EnhancePacketConn
	rAddr        net.Addr
	strictSource bool
	rAddrPort    netip.AddrPort
}

func (c *bindPacketConn) Read(b []byte) (n int, err error) {
	for {
		var source net.Addr
		n, source, err = c.EnhancePacketConn.ReadFrom(b)
		if err != nil || !c.strictSource || matchAddrPort(source, c.rAddrPort) {
			return n, err
		}
	}
}

func (c *bindPacketConn) WaitRead() (data []byte, put func(), err error) {
	for {
		var source net.Addr
		data, put, source, err = c.EnhancePacketConn.WaitReadFrom()
		if err != nil || !c.strictSource || matchAddrPort(source, c.rAddrPort) {
			return
		}
		if put != nil {
			put()
		}
		data = nil
		put = nil
	}
}

func (c *bindPacketConn) Write(b []byte) (n int, err error) {
	return c.EnhancePacketConn.WriteTo(b, c.rAddr)
}

func (c *bindPacketConn) RemoteAddr() net.Addr {
	return c.rAddr
}

func (c *bindPacketConn) LocalAddr() net.Addr {
	if c.EnhancePacketConn.LocalAddr() == nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	} else {
		return c.EnhancePacketConn.LocalAddr()
	}
}

func (c *bindPacketConn) Upstream() any {
	return c.EnhancePacketConn
}

func NewBindPacketConn(pc net.PacketConn, rAddr net.Addr) net.Conn {
	return &bindPacketConn{
		EnhancePacketConn: NewEnhancePacketConn(pc),
		rAddr:             rAddr,
	}
}

// NewDNSBindPacketConn binds a packet connection to one DNS server and drops
// datagrams from any other source. The target must already be resolved.
func NewDNSBindPacketConn(pc net.PacketConn, rAddr net.Addr) net.Conn {
	rAddrPort, _ := addrPortFromNetAddr(rAddr)
	return &bindPacketConn{
		EnhancePacketConn: NewEnhancePacketConn(pc),
		rAddr:             rAddr,
		strictSource:      true,
		rAddrPort:         rAddrPort,
	}
}

type addrPorter interface {
	AddrPort() netip.AddrPort
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	if provider, ok := addr.(addrPorter); ok {
		addrPort := provider.AddrPort()
		if addrPort.IsValid() {
			return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), true
		}
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 0 || parsedPort > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(parsedPort)), true
}

func matchAddrPort(source net.Addr, expected netip.AddrPort) bool {
	addrPort, valid := addrPortFromNetAddr(source)
	return valid && addrPort == expected
}
