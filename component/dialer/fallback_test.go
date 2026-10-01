package dialer

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDualStackAcceptsFallbackAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// The fallback succeeds between the old ticker's first and second ticks.
	// Once the preference window expires it must not wait for another tick.
	released := make(chan time.Time, 1)
	dial := func(ctx context.Context, _ string, ips []netip.Addr, _ string, _ option) (net.Conn, error) {
		if ips[0].Is6() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		timer := time.NewTimer(dualStackFallbackTimeout + 50*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			released <- time.Now()
			return server, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	conn, err := dualStackDialContext(ctx, dial, "tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}, "80", option{prefer: 6})
	if err != nil || conn != server {
		t.Fatalf("fallback result = %v, %v", conn, err)
	}
	if elapsed := time.Since(<-released); elapsed >= dualStackFallbackTimeout/2 {
		t.Fatalf("ready fallback waited another tick: %s", elapsed)
	}
}

func TestDualStackReturnsPrimaryAndClosesFallback(t *testing.T) {
	fallback, peer := net.Pipe()
	defer fallback.Close()
	defer peer.Close()
	primary, primaryPeer := net.Pipe()
	defer primary.Close()
	defer primaryPeer.Close()
	dial := func(_ context.Context, _ string, ips []netip.Addr, _ string, _ option) (net.Conn, error) {
		if ips[0].Is6() {
			time.Sleep(20 * time.Millisecond)
			return primary, nil
		}
		return fallback, nil
	}
	conn, err := dualStackDialContext(context.Background(), dial, "tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}, "80", option{prefer: 6})
	if err != nil || conn != primary {
		t.Fatalf("primary result = %v, %v", conn, err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err = peer.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("unused fallback did not close: %v", err)
	}
}
