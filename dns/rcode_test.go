package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

// A nameserver-policy entry such as '+.example.com': rcode://success is how a
// domain is blocked at the DNS layer, so the debug log has to show the query it
// answered, just as it does for every other nameserver.
func TestRCodeNameserverPolicyLogsTheQueryItAnswers(t *testing.T) {
	r := NewResolver(Config{
		Policy: []Policy{{
			Domain:      "+.rcode-log.example",
			NameServers: []NameServer{{Net: "rcode", Addr: "success"}},
		}},
	})

	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)

	const domain = "ads.rcode-log.example"
	query := new(D.Msg)
	query.SetQuestion(D.Fqdn(domain), D.TypeA)
	msg, err := r.ExchangeContext(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != D.RcodeSuccess || len(msg.Answer) != 0 {
		t.Fatalf("expected an empty NOERROR answer from rcode://success, got rcode %s with %d answers", D.RcodeToString[msg.Rcode], len(msg.Answer))
	}

	// Anything the exchange logged was sent before ExchangeContext returned, and
	// the log bus keeps the order it was fed in, so a marker logged now arrives
	// after it. Reading up to the marker separates "not logged" from "not yet
	// delivered" without waiting on a timeout.
	const marker = "[test] end of the rcode exchange"
	log.Debugln(marker)

	var logged []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case event, ok := <-subscription:
			if !ok {
				t.Fatal("log subscription closed before the marker arrived")
			}
			if event.Payload == marker {
				for _, line := range logged {
					if strings.Contains(line, domain+" --> ") && strings.Contains(line, "rcode://success") {
						return
					}
				}
				t.Fatalf("expected a debug line reporting the answer rcode://success gave for %s, got %q", domain, logged)
			}
			if strings.Contains(event.Payload, domain) {
				logged = append(logged, event.Payload)
			}
		case <-timeout:
			t.Fatal("timed out waiting for the log marker")
		}
	}
}
