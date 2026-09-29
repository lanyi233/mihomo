package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// startAnsweringDNSServer serves every A query with answer on a loopback UDP
// port and counts the queries it received for host.
func startAnsweringDNSServer(t *testing.T, answer netip.Addr, host string, queried *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, r *D.Msg) {
		reply := new(D.Msg)
		reply.SetReply(r)
		q := r.Question[0]
		if q.Name == D.Fqdn(host) {
			queried.Add(1)
		}
		if q.Qtype == D.TypeA {
			reply.Answer = append(reply.Answer, &D.A{
				Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600},
				A:   answer.AsSlice(),
			})
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// useTempHomeDir points the process-wide home directory at a temporary one
// for the test and puts the previous one back afterwards.
func useTempHomeDir(t *testing.T) {
	t.Helper()
	previous := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previous) })
}

// A 'rule-set:' nameserver-policy can only match once its rule provider has
// loaded, and the providers load after the DNS resolver is already serving:
// proxy-provider health checks, rule-provider downloads and hijacked queries
// all resolve domains in that window, while the rule set is still empty. The
// answers they get from the main nameservers must not be cached, or the policy
// stays bypassed for those domains until their TTL runs out.
//
// The rule provider here is fetched from a host that its own rule set lists,
// so the download resolves that host exactly while the set is still empty.
func TestRuleSetNameserverPolicyAppliesOnceTheRuleProviderHasLoaded(t *testing.T) {
	useTempHomeDir(t)
	// Applying a config opens the process-wide cache file in the home directory;
	// close it before the directory is removed, which Windows refuses otherwise.
	t.Cleanup(func() {
		if db := cachefile.Cache().DB; db != nil {
			_ = db.Close()
		}
	})

	const host = "rules.startup.test"
	var mainQueries, policyQueries atomic.Int32
	// The main nameserver has to send the download to the loopback rule server.
	mainDNS := startAnsweringDNSServer(t, netip.MustParseAddr("127.0.0.1"), host, &mainQueries)
	policyAnswer := netip.MustParseAddr("192.0.2.2")
	policyDNS := startAnsweringDNSServer(t, policyAnswer, host, &policyQueries)

	rules := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, host)
	}))
	t.Cleanup(rules.Close)
	_, rulesPort, err := net.SplitHostPort(strings.TrimPrefix(rules.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseWithBytes([]byte(fmt.Sprintf(`
mode: rule
log-level: silent
ipv6: false
profile:
  store-selected: false
dns:
  enable: true
  ipv6: false
  default-nameserver:
    - udp://%[1]s
  nameserver:
    - udp://%[1]s
  nameserver-policy:
    'rule-set:startup': udp://%[2]s
rule-providers:
  startup:
    type: http
    behavior: domain
    format: text
    url: http://%[3]s:%[4]s/startup.list
    interval: 86400
rules:
  - MATCH,DIRECT
`, mainDNS, policyDNS, host, rulesPort)))
	if err != nil {
		t.Fatal(err)
	}
	ApplyConfig(cfg, true)

	provider, ok := tunnel.RuleProviders()["startup"]
	if !ok || provider.Count() != 1 {
		t.Fatalf("expected the rule provider to have loaded its one domain, got %v", provider)
	}
	if mainQueries.Load() == 0 {
		t.Fatalf("expected the rule download to resolve %s through the main nameserver before the rule set had loaded", host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIPv4WithResolver(ctx, host, resolver.DefaultResolver)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != policyAnswer {
		t.Fatalf("expected %s to be answered by the rule-set nameserver-policy (%s) once the rule set had loaded, got %v (policy nameserver queried %d times)", host, policyAnswer, ips, policyQueries.Load())
	}
}

// ParseRawConfig applies the general section it is parsing through
// temporaryUpdateGeneral and restores, on return, the general it found when
// it started. An ApplyConfig that ran in between -- the startup apply racing a
// PUT /configs, or a reload racing a profile validation -- was undone by that
// restore: geodata-mode went back to false under rules built for geodata, and
// the next GEOIP match opened an MMDB file that does not exist
// (MetaCubeX/mihomo#2837).
func TestAParseDoesNotRollBackAConfigAppliedWhileItRan(t *testing.T) {
	useTempHomeDir(t)
	previousGeodataMode := geodata.GeodataMode()
	t.Cleanup(func() { geodata.SetGeodataMode(previousGeodataMode) })
	geodata.SetGeodataMode(false)

	cfg, err := ParseWithBytes([]byte("geodata-mode: true\nprofile:\n  store-selected: false\n"))
	require.NoError(t, err)
	require.False(t, geodata.GeodataMode(), "a finished parse keeps its general to itself")

	// A parse begins, and while it runs the same config is applied.
	rollback := temporaryUpdateGeneral(cfg.General)
	applied := make(chan struct{})
	go func() {
		ApplyConfig(cfg, true)
		close(applied)
	}()
	select {
	case <-applied:
	case <-time.After(500 * time.Millisecond):
		// ApplyConfig is waiting for the parse, which is what it should do.
	}
	rollback()
	<-applied

	require.True(t, geodata.GeodataMode(), "the parse rolled back geodata-mode from the config applied while it ran")
}
