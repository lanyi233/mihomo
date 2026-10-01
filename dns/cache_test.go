package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

func cacheTestReply() *D.Msg {
	query := new(D.Msg).SetQuestion("cache.example.", D.TypeA)
	msg := new(D.Msg).SetReply(query)
	msg.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	return msg
}

func TestCachePreservesRecordsAndUsesMinimumTTL(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			cache := Config{CacheAlgorithm: algorithm}.newCache()
			msg := cacheTestReply()
			msg.Ns = []D.RR{&D.NS{Hdr: D.RR_Header{Name: "example.", Rrtype: D.TypeNS, Class: D.ClassINET, Ttl: 300}, Ns: "ns.example."}}
			msg.Extra = []D.RR{
				&D.OPT{Hdr: D.RR_Header{Name: ".", Rrtype: D.TypeOPT}},
				&D.A{Hdr: D.RR_Header{Name: "ns.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 120}, A: net.IPv4(192, 0, 2, 2)},
			}
			before := msg.Copy()
			start := time.Now()
			putMsgToCache(cache, msg.Question[0], msg)
			cached, expires, ok := getMsgFromCache(cache, msg.Question[0])
			if !ok || cached == nil {
				t.Fatal("expected cached reply")
			}
			if expires.Before(start.Add(119*time.Second)) || expires.After(time.Now().Add(120*time.Second)) {
				t.Fatalf("cache expiry does not use minimum non-OPT TTL: %s", expires)
			}
			if len(cached.Extra) != 1 || cached.Extra[0].Header().Rrtype != D.TypeA {
				t.Fatalf("unexpected cached extras: %v", cached.Extra)
			}
			if msg.String() != before.String() {
				t.Fatal("caching modified the upstream reply")
			}
			cached.Answer[0].Header().Ttl = 1
			again, _, _ := getMsgFromCache(cache, msg.Question[0])
			if again.Answer[0].Header().Ttl != 600 {
				t.Fatal("modifying a cache result modified the stored reply")
			}
		})
	}
}

func TestCacheSeparatesQuestionNamesClassesAndTypes(t *testing.T) {
	cache := Config{}.newCache()
	questions := []D.Question{
		{Name: "example.", Qclass: D.ClassINET, Qtype: D.TypeA},
		{Name: "example.", Qclass: D.ClassCHAOS, Qtype: D.TypeA},
		{Name: "example.", Qclass: D.ClassINET, Qtype: D.TypeAAAA},
		{Name: "example.", Qclass: 65535, Qtype: 65535},
		{Name: "example.\x00", Qclass: D.ClassINET, Qtype: D.TypeA},
		{Name: "other.", Qclass: D.ClassINET, Qtype: D.TypeA},
	}
	for i, question := range questions {
		msg := cacheTestReply()
		msg.Id = uint16(i)
		msg.Question = []D.Question{question}
		putMsgToCache(cache, question, msg)
	}
	for i, question := range questions {
		msg, _, ok := getMsgFromCache(cache, question)
		if !ok || msg.Id != uint16(i) {
			t.Fatalf("cache confused question %v with another question: %v", question, msg)
		}
	}
}

func TestCacheTTLBoundaryCases(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ttl        uint32
		rcode      int
		wantCached bool
	}{
		{name: "zero", ttl: 0, wantCached: false},
		{name: "maximum", ttl: ^uint32(0), wantCached: true},
		{name: "server failure", rcode: D.RcodeServerFailure, wantCached: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := Config{}.newCache()
			msg := cacheTestReply()
			msg.Answer[0].Header().Ttl = tc.ttl
			msg.Rcode = tc.rcode
			putMsgToCache(cache, msg.Question[0], msg)
			_, _, ok := getMsgFromCache(cache, msg.Question[0])
			if ok != tc.wantCached {
				t.Fatalf("cached = %v, want %v", ok, tc.wantCached)
			}
		})
	}
}

func BenchmarkResolverCacheHit(b *testing.B) {
	previous := log.Level()
	log.SetLevel(log.INFO)
	b.Cleanup(func() { log.SetLevel(previous) })
	r := &Resolver{cache: Config{}.newCache()}
	msg := cacheTestReply()
	putMsgToCache(r.cache, msg.Question[0], msg)
	query := new(D.Msg).SetQuestion(msg.Question[0].Name, D.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.ExchangeContext(context.Background(), query); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPutMsgToCache(b *testing.B) {
	cache := Config{}.newCache()
	msg := cacheTestReply()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		putMsgToCache(cache, msg.Question[0], msg)
	}
}

func BenchmarkIPExchangeNoFallback(b *testing.B) {
	r := &Resolver{main: []dnsClient{newRCodeClient("success")}}
	query := new(D.Msg).SetQuestion("example.com.", D.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.ipExchange(context.Background(), query); err != nil {
			b.Fatal(err)
		}
	}
}
