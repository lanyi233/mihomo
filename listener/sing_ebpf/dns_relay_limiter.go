//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"github.com/metacubex/mihomo/common/pool"
	"net"
	"net/netip"
	"sync"
)

const (
	// A UDP relay holds its slot for exactly one datagram, so this is a ceiling
	// on queries in flight.
	maxConcurrentUDPDNSRelays = 256
	// A TCP relay holds its slot for the whole connection: RelayDnsConn loops
	// until the peer goes away, refreshing its read deadline after every query.
	// That is a completely different occupancy profile, so it gets its own
	// budget -- sharing one let a handful of idle-but-open hijacked connections
	// starve every UDP query on the inbound.
	maxConcurrentTCPDNSRelays = 128
	// ...and beyond the halfway mark no single client may hold more than this
	// share, so one LAN host cannot park every slot and switch DNS off for its
	// neighbours.
	//
	// The share only binds under pressure because the source address is a poor
	// identity in local mode: the eBPF hook rewrites the destination, not the
	// source, so every hijacked connection from every local process reports the
	// same peer. A cap that always bound would be a cap on the whole host.
	maxTCPDNSRelaysPerClient = 8
)

type dnsRelayLimiter struct {
	access  sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
	pending sync.WaitGroup

	udpLimit, tcpLimit, tcpClientLimit int
	udpActive, tcpActive               int
	tcpClientActive                    map[netip.Addr]int
}

func newDNSRelayLimiter(parent context.Context) *dnsRelayLimiter {
	return newDNSRelayLimiterWithLimits(parent, maxConcurrentUDPDNSRelays, maxConcurrentTCPDNSRelays, maxTCPDNSRelaysPerClient)
}

func newDNSRelayLimiterWithLimits(parent context.Context, udpLimit, tcpLimit, tcpClientLimit int) *dnsRelayLimiter {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &dnsRelayLimiter{
		ctx:             ctx,
		cancel:          cancel,
		udpLimit:        udpLimit,
		tcpLimit:        tcpLimit,
		tcpClientLimit:  tcpClientLimit,
		tcpClientActive: make(map[netip.Addr]int),
	}
}

// startUDP admits one datagram relay. Retain before exposing work to the janitor.
func (l *dnsRelayLimiter) startUDP(retain, release func(), work func(context.Context)) bool {
	return l.start(func() bool {
		if l.udpActive >= l.udpLimit {
			return false
		}
		l.udpActive++
		return true
	}, func() {
		l.udpActive--
	}, retain, release, work)
}

// startTCP admits one hijacked connection, charged against both the global TCP
// budget and the originating client's share of it.
func (l *dnsRelayLimiter) startTCP(client netip.Addr, work func(context.Context)) bool {
	return l.start(func() bool {
		if l.tcpActive >= l.tcpLimit {
			return false
		}
		// Enforce the per-client share only once the budget is half spent: while
		// there is headroom a single identity may use it, which is what keeps
		// local mode - where every process shares one apparent source - from
		// being capped as if it were one noisy LAN host.
		if l.tcpActive >= l.tcpLimit/2 && l.tcpClientActive[client] >= l.tcpClientLimit {
			return false
		}
		l.tcpActive++
		l.tcpClientActive[client]++
		return true
	}, func() {
		l.tcpActive--
		if remaining := l.tcpClientActive[client] - 1; remaining > 0 {
			l.tcpClientActive[client] = remaining
		} else {
			delete(l.tcpClientActive, client)
		}
	}, nil, nil, work)
}

// start runs work on its own goroutine once acquire admits it. acquire and
// finish both run under l.access; admission never waits for a slot.
func (l *dnsRelayLimiter) start(acquire func() bool, finish func(), retain, release func(), work func(context.Context)) bool {
	l.access.Lock()
	if l.closed || l.ctx.Err() != nil || !acquire() {
		l.access.Unlock()
		return false
	}
	l.pending.Add(1)
	if retain != nil {
		retain()
	}
	l.access.Unlock()
	go func() {
		defer func() {
			if release != nil {
				release()
			}
			l.access.Lock()
			finish()
			l.access.Unlock()
			l.pending.Done()
		}()
		work(l.ctx)
	}()
	return true
}
func (l *dnsRelayLimiter) close() {
	l.access.Lock()
	l.closed = true
	l.cancel()
	l.access.Unlock()
	l.pending.Wait()
}
func (i *Inbound) dnsLimiter() *dnsRelayLimiter {
	i.dnsRelayAccess.Lock()
	defer i.dnsRelayAccess.Unlock()
	if i.dnsRelays == nil {
		i.dnsRelays = newDNSRelayLimiter(i.ctx)
		if i.dnsRelayClosed {
			i.dnsRelays.close()
		}
	}
	return i.dnsRelays
}
func (i *Inbound) stopDNSRelays() {
	i.dnsRelayAccess.Lock()
	i.dnsRelayClosed = true
	l := i.dnsRelays
	i.dnsRelayAccess.Unlock()
	if l != nil {
		l.close()
	}
}
func (i *Inbound) startUDPDNSRelay(data []byte, client netip.AddrPort, state *udpClientState, dest netip.AddrPort) {
	if !i.dnsLimiter().startUDP(state.activity.retain, state.activity.release, func(ctx context.Context) { i.relayUDPDNS(ctx, data, client, state, dest) }) {
		i.udpWarnings.dnsRelay.warn(i.logWarn, "hijacked UDP DNS relay budget is exhausted; refusing query from ", client)
		if reply, ok := refusedDNSReply(data); ok {
			if err := i.writeUDPReply(client, state, dest, reply); err != nil {
				i.udpWarnings.cleanup.warn(i.logWarn, "write refused UDP DNS reply: ", err)
			}
		}
		_ = pool.Put(data)
	}
}
func (s *sharedRewrite) startUDPDNSRelay(data []byte, client netip.AddrPort, state *sharedUDPClientState, dest netip.AddrPort) {
	if !s.inbound.dnsLimiter().startUDP(state.activity.retain, state.activity.release, func(ctx context.Context) { s.relaySharedUDPDNS(ctx, data, client, state, dest) }) {
		s.udpWarnings.dnsRelay.warn(s.inbound.logWarn, "hijacked shared UDP DNS relay budget is exhausted; refusing query from ", client)
		if reply, ok := refusedDNSReply(data); ok {
			s.writeHijackedUDPReply(reply, client, state, dest)
		}
		_ = pool.Put(data)
	}
}

// dnsRelayClient identifies the peer a hijacked TCP connection is charged to.
// An address we cannot read collapses onto the zero Addr, which simply means
// every such connection shares one per-client budget.
func dnsRelayClient(conn net.Conn) netip.Addr {
	if conn == nil {
		return netip.Addr{}
	}
	addrPort, ok := addrPortOf(conn.RemoteAddr())
	if !ok {
		return netip.Addr{}
	}
	return addrPort.Addr()
}

func (i *Inbound) startTCPDNSRelay(conn net.Conn) {
	client := dnsRelayClient(conn)
	if !i.dnsLimiter().startTCP(client, func(ctx context.Context) {
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
		i.relayTCPDNS(ctx, conn)
		if !stop() {
			<-done
		}
	}) {
		i.udpWarnings.dnsRelay.warn(i.logWarn, "hijacked TCP DNS relay budget is exhausted; rejecting connection from ", client)
		_ = conn.Close()
	}
}
