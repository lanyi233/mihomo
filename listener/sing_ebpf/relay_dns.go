//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resolver"
)

// relayTCPDNS relays a hijacked TCP DNS connection into mihomo's own resolver
// pipeline (the same pipeline behind dns.listen and the type: dns outbound).
func (i *Inbound) relayTCPDNS(ctx context.Context, conn net.Conn) {
	if err := resolver.RelayDnsConn(ctx, conn, resolver.DefaultDnsReadTimeout); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

// relayUDPDNS relays a hijacked UDP DNS query into mihomo's resolver pipeline
// and writes the reply back to the client through the client's data plane
// (cgroup redirect write-back or the TC reply socket).
//
// It runs on its own goroutine: resolving can take a network round trip, and
// the read loop that received the query must not wait for it. The query
// buffer belongs to this call and goes back to the pool once it is unpacked.
func (i *Inbound) relayUDPDNS(ctx context.Context, data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	reply, buff, err := relayHijackedDNSContext(ctx, data)
	defer pool.Put(buff)
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "relay hijacked UDP DNS: ", err)
		return
	}
	if err := i.writeUDPReply(client, clientState, destination, reply); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "write hijacked UDP DNS reply: ", err)
	}
}

// relaySharedUDPDNS relays a hijacked shared-network UDP DNS query and writes
// the reply back through the shared rewrite reply path. See relayUDPDNS for
// the goroutine and buffer contract.
func (s *sharedRewrite) relaySharedUDPDNS(ctx context.Context, data []byte, client netip.AddrPort, clientState *sharedUDPClientState, destination netip.AddrPort) {
	reply, buff, err := relayHijackedDNSContext(ctx, data)
	defer pool.Put(buff)
	if err != nil {
		s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "relay hijacked shared UDP DNS: ", err)
		return
	}
	s.lifecycleAccess.RLock()
	clientState.activity.touch()
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		s.lifecycleAccess.RUnlock()
		writer := &sharedRewritePacket{shared: s, client: client, clientState: clientState}
		if _, err = writer.WriteBack(reply, net.UDPAddrFromAddrPort(destination)); err != nil {
			s.udpWarnings.cleanup.warn(s.inbound.logWarn, "write hijacked shared UDP DNS reply: ", err)
		}
		return
	}
	defer s.lifecycleAccess.RUnlock()
	if err := s.listeners.writeUDP(reply, binding.packetInfo, client, binding.address); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "write hijacked shared UDP DNS reply: ", err)
	}
}

// relayHijackedDNS resolves one hijacked query. The query buffer is returned to
// the pool as soon as the resolver has unpacked it; the reply is built into a
// pooled buffer the caller returns after writing it.
func relayHijackedDNS(query []byte) ([]byte, []byte, error) {
	return relayHijackedDNSContext(context.Background(), query)
}

func relayHijackedDNSContext(parent context.Context, query []byte) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, resolver.DefaultDnsRelayTimeout)
	defer cancel()
	buff := pool.Get(resolver.SafeDnsPacketSize)
	reply, err := resolver.RelayDnsPacket(ctx, query, buff)
	_ = pool.Put(query)
	return reply, buff, err
}
