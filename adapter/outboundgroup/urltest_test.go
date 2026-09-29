package outboundgroup

import (
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type delayTestProxy struct {
	C.Proxy
	name  string
	delay atomic.Uint32
}

func (p *delayTestProxy) Name() string                      { return p.name }
func (p *delayTestProxy) AliveForTestUrl(string) bool       { return true }
func (p *delayTestProxy) LastDelayForTestUrl(string) uint16 { return uint16(p.delay.Load()) }

// fast() decides whether the current node still exists by scanning the
// candidates, but the scan started at proxies[1]. When the current node was
// the first candidate it was taken for gone, and the group switched to any
// node that was faster at all, ignoring tolerance (MetaCubeX/mihomo#2945).
func TestURLTestKeepsTheFirstProxyWithinTolerance(t *testing.T) {
	first := &delayTestProxy{name: "first"}
	second := &delayTestProxy{name: "second"}
	first.delay.Store(100)
	second.delay.Store(120)
	proxies := []C.Proxy{first, second}

	pd, err := provider.NewCompatibleProvider("auto", proxies, provider.NewHealthCheck(proxies, "", 0, 0, true, nil))
	require.NoError(t, err)
	u, err := NewURLTest(
		GroupCommonOption{Name: "auto", URL: "https://example.com/generate_204"},
		URLTestOption{Tolerance: 50},
		adapter.NewProxy(outbound.NewCompatible()),
		[]P.ProxyProvider{pd},
	)
	require.NoError(t, err)

	require.Equal(t, "first", u.fast(false).Name())

	// A health check finished: second is faster now, but by less than the
	// tolerance, so the group must stay where it is.
	second.delay.Store(80)
	u.fastSingle.Reset()
	require.Equal(t, "first", u.fast(false).Name())

	// Beyond the tolerance the group does switch.
	second.delay.Store(40)
	u.fastSingle.Reset()
	require.Equal(t, "second", u.fast(false).Name())
}
