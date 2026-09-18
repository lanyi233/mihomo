// Package netchange fans out the work that has to happen when the default
// network interface changes. Dropping the interface and resolver caches alone
// is not enough: a urltest, fallback or smart group keeps routing to whichever
// node won on the *previous* link until its health check interval elapses, so
// every provider is re-probed as part of the same notification.
package netchange

import (
	"context"
	"sync"

	"github.com/metacubex/mihomo/common/batch"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// A provider health check already fans out over its own proxies, so this only
// bounds how many providers compete for the freshly switched link at once.
const providerConcurrency = 4

// fanOut are the stages of a network change, kept as fields instead of direct
// calls so tests can drive the sequencing without a real resolver or providers.
type fanOut struct {
	flushCache      func()
	resetConnection func()
	providers       func() map[string]P.ProxyProvider
}

type notifier struct {
	access sync.Mutex
	cancel context.CancelFunc // supersedes the fan-out started last
	work   fanOut
	// runAccess serialises the fan-out bodies. A superseded run can still be
	// inside a provider check when its replacement starts, and two resets
	// racing each other would rebuild connections on half-torn-down state.
	runAccess sync.Mutex
}

var defaultNotifier = &notifier{work: fanOut{
	flushCache:      iface.FlushCache,
	resetConnection: resolver.ResetConnection,
	providers:       tunnel.Providers,
}}

// Notify reports that the default interface changed. A flapping link
// supersedes the running fan-out instead of stacking another one on top of it.
func Notify() {
	defaultNotifier.notify()
}

// notify returns a channel closed once this run's goroutine exits, which is
// what the tests wait on instead of sleeping.
func (n *notifier) notify() <-chan struct{} {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	n.access.Lock()
	previous := n.cancel
	n.cancel = cancel
	work := n.work
	n.access.Unlock()
	if previous != nil {
		previous()
	}
	go func() {
		defer close(done)
		defer cancel()
		n.run(ctx, work)
	}()
	return done
}

func (n *notifier) run(ctx context.Context, work fanOut) {
	n.runAccess.Lock()
	defer n.runAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	work.flushCache()
	if ctx.Err() != nil {
		return
	}
	work.resetConnection()
	if ctx.Err() != nil {
		return
	}
	recheckProviders(ctx, work.providers)
}

// recheckProviders forces every provider to probe now. HealthCheck is the only
// entry point that does so unconditionally: scheduleCheck just pokes the
// background loop, which swallows the request while power reports paused, and
// that is exactly the state a device switching networks tends to be in.
func recheckProviders(ctx context.Context, source func() map[string]P.ProxyProvider) {
	if source == nil {
		return
	}
	providers := source()
	if len(providers) == 0 {
		return
	}
	log.Debugln("[NetChange] re-checking %d providers after default interface changed", len(providers))
	b, _ := batch.New[struct{}](ctx, batch.WithConcurrencyNum[struct{}](providerConcurrency))
	for name, provider := range providers {
		b.Go(name, func() (struct{}, error) {
			// HealthCheck blocks for the whole probe timeout and takes no
			// context, so providers still queued behind the concurrency limit
			// are the only place a superseded run can drop out.
			if ctx.Err() == nil {
				provider.HealthCheck()
			}
			return struct{}{}, nil
		})
	}
	_ = b.Wait()
}
