package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type client struct {
	port         string
	host         string
	dialer       *dnsDialer
	schema       string
	disableReuse bool
	dialContext  func(context.Context, string, string) (net.Conn, error)

	poolOnce        sync.Once
	pool            *dnsConnectionPool
	tcpFallbackPool *dnsConnectionPool
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	return fmt.Sprintf("%s://%s", c.schema, net.JoinHostPort(c.host, c.port))
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	defer runtime.KeepAlive(c)
	c.initPools()
	network := "udp"
	if c.schema != "udp" {
		network = "tcp"
	}

	addr := net.JoinHostPort(c.host, c.port)
	message, err := exchangeDNSWithPool(ctx, m, c.pool, func(dialCtx context.Context) (net.Conn, error) {
		return c.dial(dialCtx, network, addr)
	}, network == "udp")
	if err != nil || network != "udp" || !message.Truncated {
		return message, err
	}

	question := "<empty question>"
	if len(m.Question) > 0 {
		question = m.Question[0].String()
	}
	log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, question)
	return exchangeDNSWithPool(ctx, m, c.tcpFallbackPool, func(dialCtx context.Context) (net.Conn, error) {
		return c.dial(dialCtx, "tcp", addr)
	}, false)
}

func (c *client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.dialContext != nil {
		return c.dialContext(ctx, network, addr)
	}
	return c.dialer.DialContext(ctx, network, addr)
}

func (c *client) initPools() {
	c.poolOnce.Do(func() {
		maxIdle := 8
		if c.disableReuse {
			maxIdle = 0
		}
		if c.schema == "udp" {
			c.pool = newDNSConnectionPool(dnsConnectionPoolOptions{
				maxOpen:     dnsMaxOpenConnections,
				maxIdle:     maxIdle,
				idleTimeout: dnsUDPIdleTimeout,
				maxLifetime: dnsUDPMaxLifetime,
				maxUses:     dnsUDPMaxUses,
			})
			c.tcpFallbackPool = newDNSConnectionPool(dnsConnectionPoolOptions{
				maxOpen:     dnsMaxOpenConnections,
				maxIdle:     maxIdle,
				idleTimeout: dnsStreamIdleTimeout,
				maxLifetime: dnsStreamMaxLifetime,
			})
			return
		}
		c.pool = newDNSConnectionPool(dnsConnectionPoolOptions{
			maxOpen:     dnsMaxOpenConnections,
			maxIdle:     maxIdle,
			idleTimeout: dnsStreamIdleTimeout,
			maxLifetime: dnsStreamMaxLifetime,
		})
	})
}

func (c *client) ResetConnection() {
	defer runtime.KeepAlive(c)
	c.initPools()
	c.pool.reset()
	if c.tcpFallbackPool != nil {
		c.tcpFallbackPool.reset()
	}
}

func (c *client) close() {
	runtime.SetFinalizer(c, nil)
	if c.pool != nil {
		_ = c.pool.close()
	}
	if c.tcpFallbackPool != nil {
		_ = c.tcpFallbackPool.close()
	}
}

func newClient(addr string, resolver resolver.Resolver, netType string, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *client {
	host, port, _ := net.SplitHostPort(addr)
	c := &client{
		port:         port,
		host:         host,
		dialer:       newDNSDialer(resolver, proxyAdapter, proxyName),
		schema:       "udp",
		disableReuse: params["disable-reuse"] == "true",
	}
	if strings.HasPrefix(netType, "tcp") {
		c.schema = "tcp"
	}
	c.initPools()
	runtime.SetFinalizer(c, (*client).close)
	return c
}
