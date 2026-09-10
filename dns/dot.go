package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

const maxOldDotConns = 8

type dnsOverTLS struct {
	port           string
	host           string
	dialer         *dnsDialer
	skipCertVerify bool
	nameCertVerify string
	disableReuse   bool

	dialFn func(context.Context) (net.Conn, error)
	pool   *dnsConnectionPool
}

var _ dnsClient = (*dnsOverTLS)(nil)

// Address implements dnsClient
func (t *dnsOverTLS) Address() string {
	return fmt.Sprintf("tls://%s", net.JoinHostPort(t.host, t.port))
}

func (t *dnsOverTLS) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	defer runtime.KeepAlive(t)
	dial := t.dialFn
	if dial == nil {
		dial = t.dialContext
	}
	return exchangeDNSWithPool(ctx, m, t.pool, dial, false)
}

func (t *dnsOverTLS) dialContext(ctx context.Context) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.host, t.port))
	if err != nil {
		return nil, err
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         t.host,
			InsecureSkipVerify: t.skipCertVerify,
		},
		NameCertVerify: t.nameCertVerify,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = tlsConn

	return conn, nil
}

func (t *dnsOverTLS) ResetConnection() {
	defer runtime.KeepAlive(t)
	t.pool.reset()
}

func (t *dnsOverTLS) Close() error {
	runtime.SetFinalizer(t, nil)
	return t.pool.close()
}

func newDoTClient(addr string, resolver resolver.Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverTLS {
	host, port, _ := net.SplitHostPort(addr)
	c := &dnsOverTLS{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
	}
	if params["skip-cert-verify"] == "true" {
		c.skipCertVerify = true
	}
	c.nameCertVerify = params["name-cert-verify"]
	if params["disable-reuse"] == "true" {
		c.disableReuse = true
	}
	maxIdle := maxOldDotConns
	if c.disableReuse {
		maxIdle = 0
	}
	c.pool = newDNSConnectionPool(dnsConnectionPoolOptions{
		maxOpen:     dnsMaxOpenConnections,
		maxIdle:     maxIdle,
		idleTimeout: dnsStreamIdleTimeout,
		maxLifetime: dnsStreamMaxLifetime,
	})
	runtime.SetFinalizer(c, (*dnsOverTLS).Close)
	return c
}
