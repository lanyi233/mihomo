//go:build with_ebpf && (linux || android)

package sing_ebpf

import "net/netip"

// Intrusive rings keep a resumable sweep cursor without allocating an index
// node or walking a Go map on each sweep. The owning shard lock protects them.
type udpSweepEntry struct {
	client     netip.AddrPort
	next, prev *udpSweepEntry
}

type udpSweepQueue struct {
	cursor *udpSweepEntry
	length int
}

func (q *udpSweepQueue) add(entry *udpSweepEntry, client netip.AddrPort) {
	entry.client = client
	if q.cursor == nil {
		entry.next, entry.prev = entry, entry
		q.cursor = entry
	} else {
		entry.prev, entry.next = q.cursor.prev, q.cursor
		entry.prev.next, entry.next.prev = entry, entry
	}
	q.length++
}

func (q *udpSweepQueue) remove(entry *udpSweepEntry) {
	if entry.next == nil {
		return
	}
	if entry.next == entry {
		q.cursor = nil
	} else {
		entry.prev.next, entry.next.prev = entry.next, entry.prev
		if q.cursor == entry {
			q.cursor = entry.next
		}
	}
	entry.next, entry.prev = nil, nil
	q.length--
}

func (q *udpSweepQueue) advance() (netip.AddrPort, bool) {
	if q.cursor == nil {
		return netip.AddrPort{}, false
	}
	entry := q.cursor
	q.cursor = entry.next
	return entry.client, true
}

const udpIdleSweepBatch = 32

// Snapshot the count, not the clients. Each shard's cursor survives between
// passes; one pass examines each snapshotted slot at most once. New clients
// need not be examined until the next pass.
type udpSweepProgress struct {
	remaining                    [udpClientShardCount]int
	total, scanned, limit, shard int
}

func (p *udpSweepProgress) more() bool { return p.total > 0 && p.scanned < p.limit }

func (p *udpSweepProgress) nextBatch() (int, int) {
	if !p.more() {
		return 0, 0
	}
	for p.remaining[p.shard] == 0 {
		p.shard = (p.shard + 1) % len(p.remaining)
	}
	idx := p.shard
	p.shard = (p.shard + 1) % len(p.remaining)
	count := min(udpIdleSweepBatch, p.remaining[idx], p.limit-p.scanned)
	p.remaining[idx] -= count
	p.total -= count
	p.scanned += count
	return idx, count
}

func (t *udpClientTable) sweepProgress(all bool) udpSweepProgress {
	p := udpSweepProgress{limit: udpIdleSweepBudget}
	for idx := range t.clientShards {
		shard := &t.clientShards[idx]
		shard.access.RLock()
		p.remaining[idx] = shard.sweep.length
		shard.access.RUnlock()
		p.total += p.remaining[idx]
	}
	if all {
		p.limit = p.total
	}
	return p
}

func (t *sharedUDPClientTable) sweepProgress(all bool) udpSweepProgress {
	p := udpSweepProgress{limit: udpIdleSweepBudget}
	for idx := range t.clientShards {
		shard := &t.clientShards[idx]
		shard.access.RLock()
		p.remaining[idx] = shard.sweep.length
		shard.access.RUnlock()
		p.total += p.remaining[idx]
	}
	if all {
		p.limit = p.total
	}
	return p
}
