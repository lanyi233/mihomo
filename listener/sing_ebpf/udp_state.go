//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64
)

type udpClientTable struct {
	clientShards [udpClientShardCount]udpClientShard
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*udpClientState
}

type udpClientState struct {
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	socketCookie    uint64
	bindings        map[netip.AddrPort]udpRedirectBinding
	replyAliasCount uint16
	closed          bool
	cgroupDataPlane bool
	cgroupOriginals map[netip.Addr]commonEBPF.OriginalDestination
	// lAddr is the address the tunnel keys its NAT table on, built once per
	// client instead of formatted for every packet.
	lAddr net.Addr
}

type udpRedirectBinding struct {
	replyAlias      bool
	redirectAddress netip.Addr
	packetInfo      []byte
	connected       bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	state, loaded := shard.clients[client]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if state, loaded := t.load(client); loaded {
		return state
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[client]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[netip.AddrPort]*udpClientState)
	}
	state := &udpClientState{
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
	}
	shard.clients[client] = state
	return state
}

func (t *udpClientTable) cachedCgroupOriginal(client netip.AddrPort, redirectAddress netip.Addr) (commonEBPF.OriginalDestination, bool) {
	state, loaded := t.load(client)
	if !loaded {
		return commonEBPF.OriginalDestination{}, false
	}
	state.access.RLock()
	original, loaded := state.cgroupOriginals[redirectAddress]
	state.access.RUnlock()
	return original, loaded
}

func (t *udpClientTable) setCgroupBinding(client netip.AddrPort, original commonEBPF.OriginalDestination, redirectAddress netip.Addr) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	state.cgroupOriginals[redirectAddress] = original
	state.socketCookie = original.SocketCookie
	state.cgroupDataPlane = true
	state.bindings[original.Destination] = udpRedirectBinding{
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
		connected:       original.ConnectedUDP,
	}
	state.access.Unlock()
}

func (t *udpClientTable) setCgroupReplyBinding(client netip.AddrPort, expected *udpClientState, destination netip.AddrPort, redirectAddress netip.Addr) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.cgroupOriginals[redirectAddress] = commonEBPF.OriginalDestination{Destination: destination}
	expected.cgroupDataPlane = true
	expected.bindings[destination] = udpRedirectBinding{
		replyAlias:      true,
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
	}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard {
	port := client.Port()
	return &t.clientShards[(port^port>>8)&(udpClientShardCount-1)]
}

func (t *udpClientTable) setDirectBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.bindings[destination] = udpRedirectBinding{}
}

func (t *udpClientTable) setDirectReplyBinding(
	client netip.AddrPort,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return nil
	}
	delete(shard.clients, client)
	expected.access.Lock()
	redirects := make([]netip.Addr, 0, len(expected.cgroupOriginals))
	for address := range expected.cgroupOriginals {
		redirects = append(redirects, address)
	}
	expected.closed = true
	clear(expected.bindings)
	clear(expected.cgroupOriginals)
	expected.cgroupDataPlane = false
	expected.replyAliasCount = 0
	expected.access.Unlock()
	return redirects
}

func (s *udpClientState) isCgroupDataPlane() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.cgroupDataPlane
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

// udpReplySocketPool shares transparent reply sockets between all clients of
// an inbound. A socket bound to an original destination can send replies to any
// client, so keeping it at client-state scope needlessly multiplies sockets.
type udpReplySocketPool struct {
	shards [udpClientShardCount]udpReplySocketShard
	closed atomic.Bool
}

type udpReplySocketShard struct {
	access  sync.Mutex
	sockets map[netip.AddrPort]*net.UDPConn
}

func (p *udpReplySocketPool) get(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, error),
) (*net.UDPConn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	shard := &p.shards[p.shardIndex(source)]
	shard.access.Lock()
	defer shard.access.Unlock()
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	if socket := shard.sockets[source]; socket != nil {
		return socket, nil
	}
	socket, err := create(source)
	if err != nil {
		return nil, err
	}
	if shard.sockets == nil {
		shard.sockets = make(map[netip.AddrPort]*net.UDPConn)
	}
	shard.sockets[source] = socket
	return socket, nil
}

func (p *udpReplySocketPool) shardIndex(source netip.AddrPort) int {
	port := source.Port()
	return int((port ^ port>>8) & (udpClientShardCount - 1))
}

func (p *udpReplySocketPool) close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.closeSockets()
}

// reset closes sockets tied to the previous network path while keeping the
// pool usable for the next interface generation.
func (p *udpReplySocketPool) reset() error {
	if p == nil || p.closed.Load() {
		return nil
	}
	return p.closeSockets()
}

func (p *udpReplySocketPool) closeSockets() error {
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, socket := range shard.sockets {
			closeErr = errors.Join(closeErr, socket.Close())
			delete(shard.sockets, source)
		}
		shard.access.Unlock()
	}
	return closeErr
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}

// localAddr returns the address the tunnel keys its NAT table on. It is the
// same for every packet of a client, so it is built once: formatting the
// client address and allocating a net.UDPAddr per packet was pure overhead on
// the read loop.
func (s *udpClientState) localAddr(client netip.AddrPort) net.Addr {
	s.access.RLock()
	lAddr := s.lAddr
	s.access.RUnlock()
	if lAddr != nil {
		return lAddr
	}
	s.access.Lock()
	if s.lAddr == nil {
		s.lAddr = N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client))
	}
	lAddr = s.lAddr
	s.access.Unlock()
	return lAddr
}

// hasDirectBinding reports whether a TC client already has a validated
// binding for destination, so the per-flow assignment lookup can be skipped
// for the packets that follow the first one. Reply aliases do not count: they
// were installed for a remote that answered, not for a flow the kernel
// assigned.
func (t *udpClientTable) hasDirectBinding(client netip.AddrPort, destination netip.AddrPort) bool {
	state, loaded := t.load(client)
	if !loaded {
		return false
	}
	state.access.RLock()
	binding, loaded := state.bindings[destination]
	ready := loaded && !binding.replyAlias && !state.closed && !state.cgroupDataPlane
	state.access.RUnlock()
	return ready
}

// replyBinding reads the reply binding and the data plane of the client in one
// critical section; the reply path needs both for every packet it writes.
func (s *udpClientState) replyBinding(destination netip.AddrPort) (udpRedirectBinding, bool, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	cgroupDataPlane := s.cgroupDataPlane
	s.access.RUnlock()
	return binding, loaded, cgroupDataPlane
}
