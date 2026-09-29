package tunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

type PacketConn struct {
	conn   net.PacketConn
	addr   string
	natKey string // prefix of this listener's SNAT keys
	target socks5.Addr
	proxy  string
	closed bool
}

// RawAddress implements C.Listener
func (l *PacketConn) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *PacketConn) Address() string {
	return l.conn.LocalAddr().String()
}

// Close implements C.Listener
func (l *PacketConn) Close() error {
	l.closed = true
	return l.conn.Close()
}

func NewUDP(addr, target, proxy string, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*PacketConn, error) {
	l, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		return nil, fmt.Errorf("invalid target address %s", target)
	}

	sl := &PacketConn{
		conn:   l,
		target: targetAddr,
		proxy:  proxy,
		addr:   addr,
		natKey: l.LocalAddr().String() + "-",
	}

	if proxy != "" {
		additions = append([]inbound.Addition{inbound.WithSpecialProxy(proxy)}, additions...)
	}

	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)
				if sl.closed {
					break
				}
				continue
			}
			sl.handleUDP(l, tunnel, buf[:n], remoteAddr, additions...)
		}
	}()

	return sl, nil
}

func (l *PacketConn) handleUDP(pc net.PacketConn, tunnel C.Tunnel, buf []byte, addr net.Addr, additions ...inbound.Addition) {
	// The tunnel keys UDP sessions by LocalAddr().String(). A bare client address
	// is shared by every tunnel listener that client reaches from one source port
	// (one WireGuard socket with a peer behind each listener), so the second
	// listener's packets joined the first one's session, with its rule decision,
	// and replies went back through whichever listener got the latest packet.
	// Scope the key to this listener, as the sing listeners do.
	cPacket := &packet{
		pc:      pc,
		rAddr:   addr,
		srcAddr: N.NewCustomAddr(C.TUNNEL.String(), l.natKey+addr.String(), addr),
		payload: buf,
	}

	tunnel.HandleUDPPacket(inbound.NewPacket(l.target, cPacket, C.TUNNEL, additions...))
}
