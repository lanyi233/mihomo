//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func BenchmarkUDPActiveSweep(b *testing.B) {
	for _, size := range []int{1024, 65536} {
		name := "1k"
		if size > 1024 {
			name = "64k"
		}
		b.Run(name, func(b *testing.B) {
			var table udpClientTable
			for n := 0; n < size; n++ {
				client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 1234)
				table.loadOrCreate(client).activity.last.Store(3)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				table.expire(2, false)
			}
		})
	}
}

func TestUDPSweepBoundsActiveScanAndResumes(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "local"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			var local udpClientTable
			var remote sharedUDPClientTable
			clients := make([]netip.AddrPort, udpIdleSweepBudget*3)
			for n := range clients {
				// All clients hash to the same shard: a shard cursor must advance
				// past an arbitrarily long active prefix, not restart a map walk.
				clients[n] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 1234)
				last := int64(1)
				if n < udpIdleSweepBudget {
					last = 3
				}
				if shared {
					remote.loadOrCreate(clients[n]).activity.last.Store(last)
				} else {
					local.loadOrCreate(clients[n]).activity.last.Store(last)
				}
			}
			progress := local.sweepProgress(false)
			if shared {
				progress = remote.sweepProgress(false)
			}
			for progress.more() {
				before := progress.scanned
				if shared {
					remote.expireBatch(2, false, &progress)
				} else {
					local.expireBatch(2, false, &progress)
				}
				if progress.scanned-before > udpIdleSweepBatch {
					t.Fatal("unbounded sweep batch")
				}
			}
			if progress.scanned != udpIdleSweepBudget {
				t.Fatalf("scanned %d", progress.scanned)
			}
			for n := 0; n < 2; n++ {
				if shared {
					remote.expire(2, false)
				} else {
					local.expire(2, false)
				}
			}
			for n, client := range clients {
				_, loaded := local.load(client)
				if shared {
					_, loaded = remote.load(client)
				}
				if loaded != (n < udpIdleSweepBudget) {
					t.Fatalf("client %d retained=%v", n, loaded)
				}
			}
			if shared {
				remote.expire(0, true)
			} else {
				local.expire(0, true)
			}
			progress = local.sweepProgress(true)
			if shared {
				progress = remote.sweepProgress(true)
			}
			if progress.more() {
				t.Fatal("purge retained sweep entries")
			}
		})
	}
}

func TestUDPSweepRoundContinuesWithoutRescanningActiveClients(t *testing.T) {
	i := &Inbound{udpTimeout: time.Minute, sharedRewrite: &sharedRewrite{}}
	const clients = udpIdleSweepBudget*3 + 1
	for n := 0; n < clients; n++ {
		client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 1234)
		i.udpClientTable.loadOrCreate(client).activity.last.Store(3)
		i.sharedRewrite.sharedUDPClientTable.loadOrCreate(client).activity.last.Store(3)
	}
	var round udpSweepRound
	for pass := 0; pass < 4; pass++ {
		beforeLocal, beforeShared := round.local.scanned, round.shared.scanned
		pending := i.expireUDP(2, &round)
		if pending != (pass < 3) {
			t.Fatalf("pass %d pending=%v", pass, pending)
		}
		if round.local.scanned-beforeLocal > udpIdleSweepBudget || round.shared.scanned-beforeShared > udpIdleSweepBudget {
			t.Fatal("unbounded pass")
		}
	}
	if round.started || round.local.scanned != clients || round.shared.scanned != clients {
		t.Fatalf("round did not finish exactly once: %+v", round)
	}
}

func TestUDPSweepUnevenShardsRespectPassBudget(t *testing.T) {
	i := &Inbound{udpTimeout: time.Minute, sharedRewrite: &sharedRewrite{}}
	for shard, count := range []int{1, udpIdleSweepBudget * 2} {
		for n := 0; n < count; n++ {
			client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), uint16(16+shard))
			i.udpClientTable.loadOrCreate(client).activity.last.Store(3)
			i.sharedRewrite.sharedUDPClientTable.loadOrCreate(client).activity.last.Store(3)
		}
	}
	var round udpSweepRound
	for pass := 0; pass < 3; pass++ {
		beforeLocal, beforeShared := round.local.scanned, round.shared.scanned
		pending := i.expireUDP(2, &round)
		if round.local.scanned-beforeLocal > udpIdleSweepBudget || round.shared.scanned-beforeShared > udpIdleSweepBudget {
			t.Fatalf("pass %d exceeded budget: local=%d shared=%d", pass, round.local.scanned-beforeLocal, round.shared.scanned-beforeShared)
		}
		if pending != (pass < 2) {
			t.Fatalf("pass %d pending=%v", pass, pending)
		}
	}
	if round.local.scanned != 1+udpIdleSweepBudget*2 || round.shared.scanned != 1+udpIdleSweepBudget*2 {
		t.Fatal("round did not cover all clients")
	}
}

func TestUDPSweepCursorSurvivesConcurrentClientReplacement(t *testing.T) {
	i := &Inbound{udpTimeout: time.Minute, sharedRewrite: &sharedRewrite{}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 2000; n++ {
			client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 1234)
			i.lifecycleAccess.RLock()
			state := i.udpClientTable.loadOrCreate(client)
			i.udpClientTable.delete(client, state)
			i.udpClientTable.loadOrCreate(client)
			i.lifecycleAccess.RUnlock()
			s := i.sharedRewrite
			s.lifecycleAccess.RLock()
			remote := s.sharedUDPClientTable.loadOrCreate(client)
			s.sharedUDPClientTable.deleteShared(client, remote)
			s.sharedUDPClientTable.loadOrCreate(client)
			s.lifecycleAccess.RUnlock()
		}
	}()
	for n := 0; n < 50; n++ {
		var round udpSweepRound
		for i.expireUDP(-1, &round) {
		}
	}
	wg.Wait()
	i.udpClientTable.expire(0, true)
	i.sharedRewrite.sharedUDPClientTable.expire(0, true)
	if i.udpClientTable.sweepProgress(true).total != 0 || i.sharedRewrite.sharedUDPClientTable.sweepProgress(true).total != 0 {
		t.Fatal("cursor retained removed state")
	}
}
