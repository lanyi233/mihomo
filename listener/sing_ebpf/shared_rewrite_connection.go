//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (s *sharedRewrite) NewConnection(conn net.Conn) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	client, ok := addrPortOf(conn.RemoteAddr())
	if !ok {
		_ = conn.Close()
		return
	}
	tokenDestination, ok := addrPortOf(conn.LocalAddr())
	if !ok {
		_ = conn.Close()
		return
	}
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if errors.Is(err, unix.ENOENT) {
		s.tcpWarnings.warn(s.inbound.logWarn, "missing shared-network TCP redirect state: client=", client)
		_ = conn.Close()
		return
	}
	if err != nil {
		s.tcpWarnings.warn(s.inbound.logWarn, "lookup shared-network TCP original destination: ", err)
		_ = conn.Close()
		return
	}
	if s.inbound.hijackDNS(original.Destination) {
		s.inbound.startTCPDNSRelay(&sharedRewriteConn{Conn: conn, shared: s, flow: flow})
		return
	}
	wrapped := &sharedRewriteConn{Conn: conn, shared: s, flow: flow}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, s.inbound.additions...)
	s.inbound.tunnel.HandleTCPConn(wrapped, metadata)
}

type sharedRewriteConn struct {
	net.Conn
	shared *sharedRewrite
	flow   *ECommon.SharedNetworkFlowHandle
	once   sync.Once
}

func (c *sharedRewriteConn) Close() error {
	c.once.Do(func() {
		c.shared.releaseFlow(c.flow)
	})
	return c.Conn.Close()
}

// The wrapper exists only to release the kernel flow on Close; it adds
// nothing to reads or writes. Saying so lets the relay unwrap it down to the
// accepted TCP socket, where sing can hand the copy to the kernel (splice)
// when the other side is a plain socket too, instead of pumping bytes through
// userspace buffers.
func (c *sharedRewriteConn) Upstream() any {
	return c.Conn
}

func (c *sharedRewriteConn) ReaderReplaceable() bool {
	return true
}

func (c *sharedRewriteConn) WriterReplaceable() bool {
	return true
}

func (s *sharedRewrite) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	backend := s.sharedBackendInstance()
	if backend == nil {
		_ = pool.Put(data)
		return
	}
	tokenAddress, _, _, err := packetDestinationsFromOOB(oob)
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logWarn, "read shared-network UDP token address: ", err)
		_ = pool.Put(data)
		return
	}
	client := source
	cached, bindingReady, loaded := s.sharedUDPClientTable.cachedPacketState(client, tokenAddress)
	original := cached.original
	flow := cached.sharedFlow
	retainedFlow := false
	if !loaded {
		tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
		original, flow, err = backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if err != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "lookup shared-network UDP original destination: ", err)
			_ = pool.Put(data)
			return
		}
		retainedFlow = true
	}
	if !bindingReady {
		released, installed := s.sharedUDPClientTable.setSharedBinding(client, original, tokenAddress, flow)
		if retainedFlow && !installed {
			s.releaseFlow(flow)
		}
		s.releaseFlows(released)
	}
	if s.inbound.hijackDNS(original.Destination) {
		clientState := s.sharedUDPClientTable.loadOrCreate(client)
		// Resolving may take a network round trip; never do that on the read
		// loop, which every UDP client of the shared interfaces shares.
		s.startUDPDNSRelay(data, client, clientState, original.Destination)
		return
	}
	s.forwardSharedUDP(data, client, original.Destination, flow)
}

func (s *sharedRewrite) forwardSharedUDP(data []byte, client netip.AddrPort, destination netip.AddrPort, flow *ECommon.SharedNetworkFlowHandle) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, s.inbound.additions...)
	clientState := s.sharedUDPClientTable.loadOrCreate(client)
	clientState.activity.retain()
	packet := &sharedRewritePacket{
		shared:      s,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       clientState.localAddr(client),
	}
	s.inbound.tunnel.HandleUDPPacket(packet, metadata)
}

func (s *sharedRewrite) releaseFlows(releases []sharedUDPRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedRewrite) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
	if flow == nil {
		return
	}
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	if err := backend.ReleaseFlow(flow); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "release shared-network flow: ", err)
	}
}

type sharedRewritePacket struct {
	shared      *sharedRewrite
	client      netip.AddrPort
	clientState *sharedUDPClientState
	data        []byte
	lAddr       net.Addr
}

func (p *sharedRewritePacket) Data() []byte {
	return p.data
}

func (p *sharedRewritePacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	destination, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("invalid UDP reply address")
	}
	p.shared.lifecycleAccess.RLock()
	defer p.shared.lifecycleAccess.RUnlock()
	if p.clientState == nil {
		return 0, E.New("missing shared-network UDP state for ", p.client)
	}
	p.clientState.activity.touch()
	destinationAddress := destination.AddrPort()
	binding, loaded := p.clientState.redirectBinding(destinationAddress)
	if !loaded {
		var err error
		binding, err = p.reserveReplyBinding(destinationAddress)
		if err != nil {
			return 0, E.Cause(err, "recover missing shared-network UDP token for ", destination)
		}
	}
	if err := p.shared.listeners.writeUDP(b, binding.packetInfo, p.client, binding.address); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *sharedRewritePacket) reserveReplyBinding(destination netip.AddrPort) (sharedUDPRedirectBinding, error) {
	template, loaded := p.clientState.replyTemplate(destination, true)
	if !loaded {
		template, loaded = p.clientState.replyTemplate(destination, false)
	}
	if !loaded {
		return sharedUDPRedirectBinding{}, E.New("shared-network UDP reply alias limit reached or base flow unavailable")
	}
	backend := p.shared.sharedBackendInstance()
	if backend == nil {
		return sharedUDPRedirectBinding{}, E.New("shared-network eBPF backend is closed")
	}
	sourceMAC := p.clientState.sourceMACAddress()
	redirectAddress, flow, err := backend.ReserveUDPReplyFlow(template.sharedFlow, destination, sourceMAC)
	if err != nil {
		return sharedUDPRedirectBinding{}, err
	}
	released, installed := p.shared.sharedUDPClientTable.setSharedReplyBinding(
		p.client,
		p.clientState,
		ECommon.OriginalDestination{Destination: destination, SourceMAC: sourceMAC},
		redirectAddress,
		flow,
	)
	if !installed {
		released = append(released, sharedUDPRedirectRelease{sharedFlow: flow})
	}
	p.shared.releaseFlows(released)
	if binding, loaded := p.clientState.redirectBinding(destination); loaded {
		return binding, nil
	}
	return sharedUDPRedirectBinding{}, E.New("shared-network UDP session closed or reply alias was rejected")
}

// Drop returns the payload to the pool once the tunnel is done with it; see
// udpPacket.Drop.
func (p *sharedRewritePacket) Drop() {
	if p.data != nil && p.clientState != nil {
		p.clientState.activity.release()
	}
	data := p.data
	if data == nil {
		return
	}
	p.data = nil
	_ = pool.Put(data)
}

func (p *sharedRewritePacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*sharedRewritePacket)(nil)
