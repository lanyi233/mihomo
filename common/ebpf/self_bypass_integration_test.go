//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"net"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestSelfBypassLazyRegistrationIntegration(t *testing.T) {
	requireEBPFIntegration(t, "register a socket before map preparation")
	bypass, err := NewSelfBypassWithCapacity(8)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	registrations := make(chan error, 8)
	for range cap(registrations) {
		go func() { registrations <- bypass.RegisterSocket(raw) }()
	}
	for range cap(registrations) {
		if err = <-registrations; err != nil {
			t.Fatal(err)
		}
	}
	sockets := bypass.Map()
	if sockets == nil {
		t.Fatal("registration did not prepare the map")
	}
	// Concurrent preparation by data planes must keep the already populated map.
	type result struct {
		sockets *CiliumEBPF.Map
		err     error
	}
	results := make(chan result, 8)
	for range cap(results) {
		go func() {
			m, err := bypass.PreparedMap()
			results <- result{m, err}
		}()
	}
	for range cap(results) {
		r := <-results
		if r.err != nil || r.sockets != sockets {
			t.Fatalf("preparation replaced the registered socket map: %v", r.err)
		}
	}
	var cookie uint64
	var cookieErr error
	if err = raw.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil || cookieErr != nil {
		t.Fatalf("read socket cookie: %v, %v", err, cookieErr)
	}
	var value uint32
	if err = sockets.Lookup(cookie, &value); err != nil || value&SocketMetadataSelfBypass == 0 {
		t.Fatalf("socket missing from shared map: value=%d, error=%v", value, err)
	}
	if err = bypass.Close(); err != nil {
		t.Fatal(err)
	}
	if err = bypass.RegisterSocket(raw); err != nil || bypass.Map() != nil {
		t.Fatalf("late socket registration reopened the map: %v", err)
	}
}

func TestSelfBypassSocketAddressReleaseIntegration(t *testing.T) {
	requireEBPFIntegration(t, "combine socket-address marking with release cleanup")
	requireOwnerMarkingHelper(t, CiliumEBPF.CGroupSockAddr)
	owner := integrationSelfBypassOwner(t)
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 171)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveCurrentProcessToCgroup(t, path, root)
	b, err := NewSelfBypassWithCapacity(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = b.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err = b.attachCgroupSocketAddr(path, SelfBypassCgroupConfig{EnableUDP: true}, owner); err != nil {
		t.Fatal(err)
	}
	if err = b.attachCgroupRelease(path); err != nil {
		t.Fatal(err)
	}
	if len(b.links) != 2 || len(b.programs) != 2 {
		t.Fatal("adding release cleanup lost ownership of the marking hooks")
	}
	for iteration := 0; iteration < 16; iteration++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		err = unix.Sendto(fd, []byte{1}, 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
		if err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		var metadata uint32
		lookupErr := b.sockets.Lookup(cookie, &metadata)
		if err = unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		if lookupErr != nil || metadata&SocketMetadataSelfBypass == 0 {
			t.Fatalf("socket-address hook did not mark socket: metadata=%d error=%v", metadata, lookupErr)
		}
		deadline := time.Now().Add(time.Second)
		for {
			err = b.sockets.Lookup(cookie, &metadata)
			if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("closed socket retained: %v", err)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
