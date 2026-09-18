//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testReplySocket(netip.AddrPort) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}
func TestReplySocketLeaseSurvivesResetAndClose(t *testing.T) {
	for _, closePool := range []bool{false, true} {
		var pool udpReplySocketPool
		source := netip.MustParseAddrPort("1.1.1.1:53")
		lease, err := pool.lease(source, testReplySocket)
		if err != nil {
			t.Fatal(err)
		}
		socket := lease.entry.socket
		if closePool {
			_ = pool.close()
		} else {
			_ = pool.reset()
		}
		if _, err = socket.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err != nil {
			t.Fatalf("leased socket closed: %v", err)
		}
		lease.release()
		if _, err = socket.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("retired socket not closed: %v", err)
		}
		if closePool {
			if _, err = pool.lease(source, testReplySocket); !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed pool accepted lease")
			}
		}
		_ = pool.close()
	}
}
func TestReplySocketCapacityAndIdleSweep(t *testing.T) {
	var pool udpReplySocketPool
	defer pool.close()
	var keys []netip.AddrPort
	for port := uint16(1); len(keys) < udpReplySocketShardCapacity+1; port++ {
		key := netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), port)
		if pool.shardIndex(key) == 0 {
			keys = append(keys, key)
		}
	}
	leases := make([]udpReplySocketLease, 0, len(keys))
	for _, key := range keys[:len(keys)-1] {
		lease, err := pool.lease(key, testReplySocket)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	if _, err := pool.lease(keys[len(keys)-1], testReplySocket); !errors.Is(err, errUDPReplySocketPoolBusy) {
		t.Fatalf("busy shard: %v", err)
	}
	if err := pool.sweepIdle(time.Now().Add(time.Hour), time.Minute); err != nil {
		t.Fatal(err)
	}
	if pool.shards[0].live != udpReplySocketShardCapacity {
		t.Fatal("sweeper evicted leased socket")
	}
	oldest := leases[0].entry.socket
	leases[0].release()
	extra, err := pool.lease(keys[len(keys)-1], testReplySocket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = oldest.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("LRU did not close idle victim")
	}
	for _, lease := range leases[1:] {
		lease.release()
	}
	extra.release()
	_ = pool.sweepIdle(time.Now().Add(time.Hour), time.Minute)
	if pool.shards[0].live != 0 {
		t.Fatal("idle sockets retained")
	}
}
func TestReplySocketConcurrentSweepAndLeases(t *testing.T) {
	var pool udpReplySocketPool
	defer pool.close()
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				lease, err := pool.lease(netip.MustParseAddrPort("1.1.1.1:53"), testReplySocket)
				if err != nil {
					t.Error(err)
					return
				}
				_, err = lease.entry.socket.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9"))
				if err != nil {
					t.Error(err)
				}
				lease.release()
			}
		}()
	}
	for n := 0; n < 100; n++ {
		_ = pool.sweepIdle(time.Now().Add(time.Hour), time.Minute)
	}
	workers.Wait()
}
func BenchmarkReplySocketCachedLease(b *testing.B) {
	var pool udpReplySocketPool
	defer pool.close()
	key := netip.MustParseAddrPort("1.1.1.1:53")
	lease, err := pool.lease(key, testReplySocket)
	if err != nil {
		b.Fatal(err)
	}
	lease.release()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		lease, err := pool.lease(key, testReplySocket)
		if err != nil {
			b.Fatal(err)
		}
		lease.release()
	}
}

// A port-only shard key collapses whenever many distinct addresses share one
// port, which is the normal case rather than the exotic one: reply sockets are
// keyed by destination and those cluster on well-known ports, and client keys
// collapse for any downstream application dialling from a fixed source port.
func TestShardIndexSpreadsAddressesSharingOnePort(t *testing.T) {
	for _, test := range []struct {
		name string
		port uint16
	}{
		{name: "https", port: 443},
		{name: "dns", port: 53},
		{name: "wireguard", port: 51820},
	} {
		t.Run(test.name, func(t *testing.T) {
			occupied := make(map[int]int, udpClientShardCount)
			for host := 0; host < 256; host++ {
				address := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(host >> 8), byte(host)}), test.port)
				occupied[shardIndexForAddrPort(address, udpClientShardCount)]++
			}
			if len(occupied) != udpClientShardCount {
				t.Fatalf("256 hosts on port %d reached %d of %d shards", test.port, len(occupied), udpClientShardCount)
			}
			// Perfectly even would be 16 per shard; allow a wide band so this
			// asserts "no collapse" rather than a specific hash.
			for shard, count := range occupied {
				if count < 4 || count > 64 {
					t.Fatalf("shard %d holds %d of 256 hosts", shard, count)
				}
			}
		})
	}
}

// Placement only has to be self-consistent: every lookup and insert goes
// through clientShard, so the table must find back what it stored.
func TestClientTablesFindBackEveryStoredClient(t *testing.T) {
	var local udpClientTable
	var shared sharedUDPClientTable
	clients := make([]netip.AddrPort, 0, 512)
	for host := 0; host < 256; host++ {
		for _, port := range []uint16{53, 51820} {
			clients = append(clients, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(host >> 8), byte(host)}), port))
		}
	}
	for _, client := range clients {
		local.loadOrCreate(client)
		shared.loadOrCreate(client)
	}
	for _, client := range clients {
		if _, loaded := local.load(client); !loaded {
			t.Fatalf("local table lost %s", client)
		}
		if _, loaded := shared.load(client); !loaded {
			t.Fatalf("shared table lost %s", client)
		}
	}
}
