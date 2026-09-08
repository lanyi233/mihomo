//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

const udpIdleSweepBudget = 1024

var udpActivityEpoch = time.Now()

func udpActivityNow() int64 { return time.Since(udpActivityEpoch).Nanoseconds() }

type udpActivity struct {
	last    atomic.Int64
	pending atomic.Int64
}

func (a *udpActivity) touch()                 { a.last.Store(udpActivityNow()) }
func (a *udpActivity) retain()                { a.pending.Add(1) }
func (a *udpActivity) release()               { a.touch(); a.pending.Add(-1) }
func (a *udpActivity) idle(cutoff int64) bool { return a.pending.Load() == 0 && a.last.Load() < cutoff }

// Caller excludes ingress and reply handling with lifecycleAccess. Never
// expire packets queued in the tunnel or DNS requests still being resolved.
func (t *udpClientTable) expire(cutoff int64, all bool) []netip.Addr {
	var redirects []netip.Addr
	remaining := udpIdleSweepBudget
	for idx := range t.clientShards {
		shard := &t.clientShards[idx]
		shard.access.RLock()
		candidates := make(map[netip.AddrPort]*udpClientState)
		for client, state := range shard.clients {
			if all || state.activity.idle(cutoff) {
				candidates[client] = state
				if !all {
					remaining--
					if remaining == 0 {
						break
					}
				}
			}
		}
		shard.access.RUnlock()
		for client, state := range candidates {
			if all || state.activity.idle(cutoff) {
				redirects = append(redirects, t.delete(client, state)...)
			}
		}
		if !all && remaining == 0 {
			break
		}
	}
	return redirects
}
func (t *sharedUDPClientTable) expire(cutoff int64, all bool) []sharedUDPRedirectRelease {
	var releases []sharedUDPRedirectRelease
	remaining := udpIdleSweepBudget
	for idx := range t.clientShards {
		shard := &t.clientShards[idx]
		shard.access.RLock()
		candidates := make(map[netip.AddrPort]*sharedUDPClientState)
		for client, state := range shard.clients {
			if all || state.activity.idle(cutoff) {
				candidates[client] = state
				if !all {
					remaining--
					if remaining == 0 {
						break
					}
				}
			}
		}
		shard.access.RUnlock()
		for client, state := range candidates {
			if all || state.activity.idle(cutoff) {
				releases = append(releases, t.deleteShared(client, state)...)
			}
		}
		if !all && remaining == 0 {
			break
		}
	}
	return releases
}
func (i *Inbound) startUDPJanitor() {
	if !i.enableUDP {
		return
	}
	parent := i.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	i.udpJanitorCancel = cancel
	i.udpJanitorDone = make(chan struct{})
	interval := i.udpTimeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	go func() {
		defer close(i.udpJanitorDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				i.expireUDP(udpActivityNow() - int64(i.udpTimeout))
			}
		}
	}()
}
func (i *Inbound) stopUDPJanitor() {
	if i.udpJanitorCancel != nil {
		i.udpJanitorCancel()
		<-i.udpJanitorDone
	}
}
func (i *Inbound) expireUDP(cutoff int64) {
	i.lifecycleAccess.Lock()
	redirects := i.udpClientTable.expire(cutoff, false)
	if backend := i.cgroupBackendInstance(); backend != nil {
		for _, addr := range redirects {
			_ = backend.DeleteRedirect(ECommon.ProtocolUDP, netip.AddrPortFrom(addr, i.listeners.selectedPort()))
		}
	}
	_ = i.udpReplySockets.sweepIdle(time.Now(), i.udpTimeout)
	i.lifecycleAccess.Unlock()
	if s := i.sharedRewrite; s != nil {
		s.lifecycleAccess.Lock()
		s.releaseFlows(s.sharedUDPClientTable.expire(cutoff, false))
		s.lifecycleAccess.Unlock()
	}
}
