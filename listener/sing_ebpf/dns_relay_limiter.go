//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"github.com/metacubex/mihomo/common/pool"
	"net"
	"net/netip"
	"sync"
)

const maxConcurrentDNSRelays = 256

type dnsRelayLimiter struct {
	access        sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	active, limit int
	closed        bool
	pending       sync.WaitGroup
}

func newDNSRelayLimiter(parent context.Context, limit int) *dnsRelayLimiter {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &dnsRelayLimiter{ctx: ctx, cancel: cancel, limit: limit}
}

// Admission never waits for a worker slot. Retain before exposing work to the janitor.
func (l *dnsRelayLimiter) start(retain, release func(), work func(context.Context)) bool {
	l.access.Lock()
	if l.closed || l.ctx.Err() != nil || l.active >= l.limit {
		l.access.Unlock()
		return false
	}
	l.active++
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
			l.active--
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
		i.dnsRelays = newDNSRelayLimiter(i.ctx, maxConcurrentDNSRelays)
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
	if !i.dnsLimiter().start(state.activity.retain, state.activity.release, func(ctx context.Context) { i.relayUDPDNS(ctx, data, client, state, dest) }) {
		_ = pool.Put(data)
	}
}
func (s *sharedRewrite) startUDPDNSRelay(data []byte, client netip.AddrPort, state *sharedUDPClientState, dest netip.AddrPort) {
	if !s.inbound.dnsLimiter().start(state.activity.retain, state.activity.release, func(ctx context.Context) { s.relaySharedUDPDNS(ctx, data, client, state, dest) }) {
		_ = pool.Put(data)
	}
}

func (i *Inbound) startTCPDNSRelay(conn net.Conn) {
	if !i.dnsLimiter().start(nil, nil, func(ctx context.Context) {
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
		i.relayTCPDNS(ctx, conn)
		if !stop() {
			<-done
		}
	}) {
		_ = conn.Close()
	}
}
