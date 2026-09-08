package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestDoTResetClosesInflightAndDoesNotReuseIt(t *testing.T) {
	started := make(chan struct{})
	var startedOnce sync.Once
	var dials atomic.Int32
	tlsClient := newTestDoTClient(func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		if dials.Add(1) == 1 {
			go func() {
				defer server.Close()
				conn := &D.Conn{Conn: server}
				if _, err := conn.ReadMsg(); err == nil {
					startedOnce.Do(func() { close(started) })
					_, _ = conn.ReadMsg()
				}
			}()
		} else {
			go serveOneDNSPipe(server, nil)
		}
		return client, nil
	})
	t.Cleanup(func() { _ = tlsClient.Close() })

	firstDone := make(chan error, 1)
	go func() {
		_, err := tlsClient.ExchangeContext(context.Background(), testDNSQuery())
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first query did not start")
	}

	tlsClient.ResetConnection()
	select {
	case err := <-firstDone:
		if err == nil {
			t.Fatal("reset did not interrupt the in-flight query")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not unblock the in-flight query")
	}

	response, err := tlsClient.ExchangeContext(context.Background(), testDNSQuery())
	if err != nil {
		t.Fatalf("fresh query after reset failed: %v", err)
	}
	if response == nil || !response.Response {
		t.Fatal("fresh query after reset returned an invalid response")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("expected a new connection after reset, got %d dials", got)
	}
}

func TestDoTCancelClosesIOAndDoesNotReuseConnection(t *testing.T) {
	started := make(chan struct{})
	var startedOnce sync.Once
	var dials atomic.Int32
	tlsClient := newTestDoTClient(func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		if dials.Add(1) == 1 {
			go func() {
				defer server.Close()
				conn := &D.Conn{Conn: server}
				if _, err := conn.ReadMsg(); err == nil {
					startedOnce.Do(func() { close(started) })
					_, _ = conn.ReadMsg()
				}
			}()
		} else {
			go serveOneDNSPipe(server, nil)
		}
		return client, nil
	})
	t.Cleanup(func() { _ = tlsClient.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tlsClient.ExchangeContext(ctx, testDNSQuery())
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock DNS I/O")
	}

	if _, err := tlsClient.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
		t.Fatalf("query after cancellation failed: %v", err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("canceled connection was reused: %d dials", got)
	}
}

func TestDoTDisableReuseDialsEachQuery(t *testing.T) {
	var dials atomic.Int32
	tlsClient := &dnsOverTLS{
		disableReuse: true,
		dialFn: func(context.Context) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			go serveOneDNSPipe(server, nil)
			return client, nil
		},
		pool: newDNSConnectionPool(dnsConnectionPoolOptions{
			maxOpen: dnsMaxOpenConnections,
		}),
	}
	t.Cleanup(func() { _ = tlsClient.Close() })

	for range 3 {
		if _, err := tlsClient.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("disable-reuse unexpectedly pooled DoT connections: %d dials", got)
	}
}

func newTestDoTClient(dial func(context.Context) (net.Conn, error)) *dnsOverTLS {
	return &dnsOverTLS{
		dialFn: dial,
		pool: newDNSConnectionPool(dnsConnectionPoolOptions{
			maxOpen:     dnsMaxOpenConnections,
			maxIdle:     maxOldDotConns,
			idleTimeout: dnsStreamIdleTimeout,
		}),
	}
}

func testDNSQuery() *D.Msg {
	message := new(D.Msg)
	message.SetQuestion("example.org.", D.TypeA)
	return message
}

func serveOneDNSPipe(server net.Conn, mutate func(*D.Msg)) {
	defer server.Close()
	conn := &D.Conn{Conn: server}
	request, err := conn.ReadMsg()
	if err != nil {
		return
	}
	response := new(D.Msg)
	response.SetReply(request)
	if mutate != nil {
		mutate(response)
	}
	_ = conn.WriteMsg(response)
}
