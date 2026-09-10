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
