package outboundgroup

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type healthCheckCountingProxy struct {
	C.Proxy
	name  string
	tests atomic.Int32
}

func (p *healthCheckCountingProxy) Name() string                      { return p.name }
func (p *healthCheckCountingProxy) Type() C.AdapterType               { return C.Http }
func (p *healthCheckCountingProxy) AliveForTestUrl(string) bool       { return true }
func (p *healthCheckCountingProxy) LastDelayForTestUrl(string) uint16 { return 100 }
func (p *healthCheckCountingProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
	return 100, nil
}

// An include-all group builds a compatible provider from the proxy names it
// collects, and that provider's health check probes every one of them.
// `filter` narrowed the names before the provider was built, `exclude-filter`
// did not, so a group using only exclude-filter probed every proxy in the
// config on startup instead of the ones it can select (MetaCubeX/mihomo#3207).
func TestIncludeAllHealthCheckSkipsProxiesTheExcludeFilterRemoves(t *testing.T) {
	names := []string{"日本 01", "美国 01", "香港 01"}
	proxies := make(map[string]*healthCheckCountingProxy, len(names))
	proxyMap := map[string]C.Proxy{
		"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
	}
	for _, name := range names {
		proxies[name] = &healthCheckCountingProxy{name: name}
		proxyMap[name] = proxies[name]
	}
	providersMap := map[string]P.ProxyProvider{}

	group, err := ParseProxyGroup(map[string]any{
		"name":           "其它",
		"type":           "url-test",
		"include-all":    true,
		"exclude-filter": "日本|美国",
	}, proxyMap, providersMap, names, nil)
	require.NoError(t, err)

	selectable := group.Proxies()
	require.Len(t, selectable, 1)
	require.Equal(t, "香港 01", selectable[0].Name())

	for _, pd := range group.Providers() {
		pd.HealthCheck()
	}

	require.EqualValues(t, 1, proxies["香港 01"].tests.Load())
	require.Zero(t, proxies["日本 01"].tests.Load(), "excluded proxy was health checked")
	require.Zero(t, proxies["美国 01"].tests.Load(), "excluded proxy was health checked")
}

type typedHealthCheckCountingProxy struct {
	*healthCheckCountingProxy
	adapterType C.AdapterType
}

func (p typedHealthCheckCountingProxy) Type() C.AdapterType { return p.adapterType }

// exclude-type has the same gap as exclude-filter above: GetProxies hides the
// excluded types, but the provider built from the collected names probed them.
func TestIncludeAllHealthCheckSkipsProxiesTheExcludeTypeRemoves(t *testing.T) {
	socks := &healthCheckCountingProxy{name: "socks 01"}
	http := &healthCheckCountingProxy{name: "http 01"}
	proxyMap := map[string]C.Proxy{
		"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
		socks.name:   typedHealthCheckCountingProxy{socks, C.Socks5},
		http.name:    http,
	}

	group, err := ParseProxyGroup(map[string]any{
		"name":         "no-socks",
		"type":         "url-test",
		"include-all":  true,
		"exclude-type": "socks5",
	}, proxyMap, map[string]P.ProxyProvider{}, []string{socks.name, http.name}, nil)
	require.NoError(t, err)

	selectable := group.Proxies()
	require.Len(t, selectable, 1)
	require.Equal(t, http.name, selectable[0].Name())

	for _, pd := range group.Providers() {
		pd.HealthCheck()
	}

	require.EqualValues(t, 1, http.tests.Load())
	require.Zero(t, socks.tests.Load(), "excluded proxy was health checked")
}
