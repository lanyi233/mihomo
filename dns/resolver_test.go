package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	D "github.com/miekg/dns"
)

// gatedClient answers A queries with a cacheable record, but only after gate is
// closed, so a test can hold a query in flight.
type gatedClient struct {
	gate    chan struct{}
	started chan struct{}
	calls   atomic.Int32
}

func (c *gatedClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-c.gate
	reply := new(D.Msg)
	reply.SetReply(m)
	reply.Answer = append(reply.Answer, &D.A{
		Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600},
		A:   net.IPv4(192, 0, 2, 1),
	})
	return reply, nil
}

func (c *gatedClient) Address() string  { return "gated" }
func (c *gatedClient) ResetConnection() {}

// A health check that resolves through a proxied DoH server can still be
// waiting for its answer when the rule providers finish loading. The query was
// routed while the rule-set policies were empty, so its answer must stay out of
// the cache even though it only arrives after the release.
func TestAnswerRoutedWhileTheCacheWasHeldStaysUncachedWhenItArrivesAfterTheRelease(t *testing.T) {
	client := &gatedClient{gate: make(chan struct{}), started: make(chan struct{}, 1)}
	rs := Resolvers{Resolver: NewResolverFromClient(client)}
	rs.HoldCache()

	done := make(chan error, 1)
	go func() {
		_, err := rs.ExchangeContext(context.Background(), testDNSQuery())
		done <- err
	}()
	<-client.started
	rs.ReleaseCache()
	close(client.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if _, err := rs.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
		t.Fatal(err)
	}
	if got := client.calls.Load(); got != 2 {
		t.Fatalf("expected the answer routed while the cache was held to be resolved again, got %d upstream queries", got)
	}

	// Routed after the release, the second answer is cached as usual.
	if _, err := rs.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
		t.Fatal(err)
	}
	if got := client.calls.Load(); got != 2 {
		t.Fatalf("expected an answer routed after the release to be served from the cache, got %d upstream queries", got)
	}
}
