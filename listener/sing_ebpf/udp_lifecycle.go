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
	progress := t.sweepProgress(all)
	var redirects []netip.Addr
	for progress.more() {
		redirects = append(redirects, t.expireBatch(cutoff, all, &progress)...)
	}
	return redirects
}

func (t *udpClientTable) expireBatch(cutoff int64, all bool, progress *udpSweepProgress) []netip.Addr {
	idx, count := progress.nextBatch()
	if count == 0 {
		return nil
	}
	var candidates [udpIdleSweepBatch]*udpClientState
	var clients [udpIdleSweepBatch]netip.AddrPort
	shard := &t.clientShards[idx]
	shard.access.Lock()
	for n := 0; n < count; n++ {
		client, loaded := shard.sweep.advance()
		if !loaded {
			break
		}
		state := shard.clients[client]
		if all || state.activity.idle(cutoff) {
			candidates[n], clients[n] = state, client
		}
	}
	shard.access.Unlock()
	var redirects []netip.Addr
	for n, state := range candidates {
		if state != nil && (all || state.activity.idle(cutoff)) {
			redirects = append(redirects, t.delete(clients[n], state)...)
		}
	}
	return redirects
}

func (t *sharedUDPClientTable) expire(cutoff int64, all bool) []sharedUDPRedirectRelease {
	progress := t.sweepProgress(all)
	var releases []sharedUDPRedirectRelease
	for progress.more() {
		releases = append(releases, t.expireBatch(cutoff, all, &progress)...)
	}
	return releases
}

func (t *sharedUDPClientTable) expireBatch(cutoff int64, all bool, progress *udpSweepProgress) []sharedUDPRedirectRelease {
	idx, count := progress.nextBatch()
	if count == 0 {
		return nil
	}
	var candidates [udpIdleSweepBatch]*sharedUDPClientState
	var clients [udpIdleSweepBatch]netip.AddrPort
	shard := &t.clientShards[idx]
	shard.access.Lock()
	for n := 0; n < count; n++ {
		client, loaded := shard.sweep.advance()
		if !loaded {
			break
		}
		state := shard.clients[client]
		if all || state.activity.idle(cutoff) {
			candidates[n], clients[n] = state, client
		}
	}
	shard.access.Unlock()
	var releases []sharedUDPRedirectRelease
	for n, state := range candidates {
		if state != nil && (all || state.activity.idle(cutoff)) {
			releases = append(releases, t.deleteShared(clients[n], state)...)
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
		timer := time.NewTimer(interval)
		defer timer.Stop()
		var round udpSweepRound
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				next := interval
				if i.expireUDP(udpActivityNow()-int64(i.udpTimeout), &round) {
					next = time.Second
				}
				timer.Reset(next)
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

// A large table is scanned across bounded passes, with one-second continuations
// until the snapshot has been covered. A completed round returns to the normal
// interval, including when all clients are active or there is no traffic.
type udpSweepRound struct {
	local, shared udpSweepProgress
	started       bool
}

func (i *Inbound) expireUDP(cutoff int64, round *udpSweepRound) bool {
	if !round.started {
		round.local = i.udpClientTable.sweepProgress(true)
		round.shared = udpSweepProgress{}
		if s := i.sharedRewrite; s != nil {
			round.shared = s.sharedUDPClientTable.sweepProgress(true)
		}
		round.started = true
	}
	progress := &round.local
	roundLimit := progress.limit
	progress.limit = min(roundLimit, progress.scanned+udpIdleSweepBudget)
	for progress.more() {
		i.lifecycleAccess.Lock()
		redirects := i.udpClientTable.expireBatch(cutoff, false, progress)
		if backend := i.cgroupBackendInstance(); backend != nil {
			for _, addr := range redirects {
				_ = backend.DeleteRedirect(ECommon.ProtocolUDP, netip.AddrPortFrom(addr, i.listeners.selectedPort()))
			}
		}
		i.lifecycleAccess.Unlock()
	}
	progress.limit = roundLimit
	i.lifecycleAccess.Lock()
	_ = i.udpReplySockets.sweepIdle(time.Now(), i.udpTimeout)
	i.lifecycleAccess.Unlock()
	if s := i.sharedRewrite; s != nil {
		progress := &round.shared
		roundLimit := progress.limit
		progress.limit = min(roundLimit, progress.scanned+udpIdleSweepBudget)
		for progress.more() {
			s.lifecycleAccess.Lock()
			s.releaseFlows(s.sharedUDPClientTable.expireBatch(cutoff, false, progress))
			s.lifecycleAccess.Unlock()
		}
		progress.limit = roundLimit
	}
	pending := round.local.more() || round.shared.more()
	if !pending {
		round.started = false
	}
	return pending
}
