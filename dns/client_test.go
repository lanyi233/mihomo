package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestPlainTCPClientReusesConnection(t *testing.T) {
	var dials atomic.Int32
	plainClient := newTestPlainClient("tcp", func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			conn := &D.Conn{Conn: server}
			for {
				request, err := conn.ReadMsg()
				if err != nil {
					return
				}
				response := new(D.Msg)
				response.SetReply(request)
				if err = conn.WriteMsg(response); err != nil {
					return
				}
			}
		}()
		return client, nil
	})
	t.Cleanup(plainClient.close)

	for range 3 {
		if _, err := plainClient.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("expected one TCP dial for sequential queries, got %d", got)
	}
}

func TestPlainClientRejectsMismatchedQuestion(t *testing.T) {
	plainClient := newTestPlainClient("tcp", func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go serveOneDNSPipe(server, func(response *D.Msg) {
			response.Question[0].Name = "attacker.example."
		})
		return client, nil
	})
	t.Cleanup(plainClient.close)

	_, err := plainClient.ExchangeContext(context.Background(), testDNSQuery())
	if !errors.Is(err, errInvalidDNSResponse) {
		t.Fatalf("expected invalid response error, got %v", err)
	}
}

func TestPlainTCPClientRetriesFreshAfterServerClosesConnection(t *testing.T) {
	var dials atomic.Int32
	plainClient := newTestPlainClient("tcp", func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go serveOneDNSPipe(server, nil)
		return client, nil
	})
	t.Cleanup(plainClient.close)

	for range 2 {
		if _, err := plainClient.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("expected one fresh retry after the server closed a reused connection, got %d dials", got)
	}
}

func TestPlainClientDisableReuse(t *testing.T) {
	var dials atomic.Int32
	plainClient := &client{
		host:         "127.0.0.1",
		port:         "53",
		schema:       "tcp",
		disableReuse: true,
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			go serveOneDNSPipe(server, nil)
			return client, nil
		},
	}
	plainClient.initPools()
	t.Cleanup(plainClient.close)

	for range 3 {
		if _, err := plainClient.ExchangeContext(context.Background(), testDNSQuery()); err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("disable-reuse unexpectedly pooled connections: %d dials", got)
	}
}

func TestPlainUDPClientReusesAndRotatesWithRandomWireID(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	wireIDs := make(chan uint16, dnsUDPMaxUses+1)
	serverErr := make(chan error, 1)
	go serveUDPQueries(server, wireIDs, serverErr, false)

	originalIDGenerator := newDNSQueryID
	newDNSQueryID = func() uint16 { return 0xBEEF }
	t.Cleanup(func() { newDNSQueryID = originalIDGenerator })

	var dials atomic.Int32
	serverAddr := server.LocalAddr().String()
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	plainClient := &client{
		host:   host,
		port:   port,
		schema: "udp",
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	plainClient.initPools()
	t.Cleanup(plainClient.close)

	for index := 0; index < dnsUDPMaxUses+1; index++ {
		query := testDNSQuery()
		query.Id = 7
		response, exchangeErr := plainClient.ExchangeContext(context.Background(), query)
		if exchangeErr != nil {
			t.Fatalf("query %d failed: %v", index, exchangeErr)
		}
		if response.Id != query.Id {
			t.Fatalf("caller ID was not restored: got %d want %d", response.Id, query.Id)
		}
		select {
		case wireID := <-wireIDs:
			if wireID != 0xBEEF {
				t.Fatalf("query %d used wire ID %d", index, wireID)
			}
		case <-time.After(time.Second):
			t.Fatalf("query %d was not observed by UDP server", index)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("expected one UDP dial plus one rotation after %d uses, got %d", dnsUDPMaxUses, got)
	}
	select {
	case err = <-serverErr:
		t.Fatal(err)
	default:
	}
}

func TestPlainUDPClientFallsBackToReusableTCP(t *testing.T) {
	tcpListener, udpServer := listenTCPAndUDPOnSamePort(t)
	t.Cleanup(func() { _ = tcpListener.Close() })
	t.Cleanup(func() { _ = udpServer.Close() })

	serverErr := make(chan error, 2)
	go serveUDPQueries(udpServer, nil, serverErr, true)
	go serveTCPQueries(tcpListener, serverErr)

	var udpDials atomic.Int32
	var tcpDials atomic.Int32
	host, port, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	plainClient := &client{
		host:   host,
		port:   port,
		schema: "udp",
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network == "udp" {
				udpDials.Add(1)
			} else {
				tcpDials.Add(1)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	plainClient.initPools()
	t.Cleanup(plainClient.close)

	for range 2 {
		response, exchangeErr := plainClient.ExchangeContext(context.Background(), testDNSQuery())
		if exchangeErr != nil {
			t.Fatal(exchangeErr)
		}
		if response.Truncated {
			t.Fatal("TCP fallback returned a truncated response")
		}
	}
	if got := udpDials.Load(); got != 1 {
		t.Fatalf("expected reused UDP connection, got %d dials", got)
	}
	if got := tcpDials.Load(); got != 1 {
		t.Fatalf("expected reused TCP fallback connection, got %d dials", got)
	}
	select {
	case err = <-serverErr:
		t.Fatal(err)
	default:
	}
}

func listenTCPAndUDPOnSamePort(t *testing.T) (net.Listener, *net.UDPConn) {
	t.Helper()
	for range 100 {
		tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverAddr := tcpListener.Addr().(*net.TCPAddr)
		udpServer, udpErr := net.ListenUDP("udp4", &net.UDPAddr{IP: serverAddr.IP, Port: serverAddr.Port})
		if udpErr == nil {
			return tcpListener, udpServer
		}
		_ = tcpListener.Close()
	}
	t.Fatal("could not bind TCP and UDP DNS test servers to the same port")
	return nil, nil
}

func TestValidateDNSResponse(t *testing.T) {
	request := testDNSQuery()
	request.Id = 9
	valid := new(D.Msg)
	valid.SetReply(request)
	valid.Question[0].Name = "EXAMPLE.ORG."
	if err := validateDNSResponse(request, valid); err != nil {
		t.Fatalf("case-insensitive matching response rejected: %v", err)
	}

	tests := map[string]func(*D.Msg){
		"not response": func(message *D.Msg) { message.Response = false },
		"wrong ID":     func(message *D.Msg) { message.Id++ },
		"wrong opcode": func(message *D.Msg) { message.Opcode = D.OpcodeStatus },
		"wrong name":   func(message *D.Msg) { message.Question[0].Name = "other.example." },
		"wrong type":   func(message *D.Msg) { message.Question[0].Qtype = D.TypeAAAA },
		"no question":  func(message *D.Msg) { message.Question = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := valid.Copy()
			mutate(response)
			if err := validateDNSResponse(request, response); !errors.Is(err, errInvalidDNSResponse) {
				t.Fatalf("expected invalid response error, got %v", err)
			}
		})
	}
}

func serveUDPQueries(server *net.UDPConn, wireIDs chan<- uint16, serverErr chan<- error, truncated bool) {
	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := server.ReadFromUDP(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				select {
				case serverErr <- err:
				default:
				}
			}
			return
		}
		request := new(D.Msg)
		if err = request.Unpack(buffer[:n]); err != nil {
			select {
			case serverErr <- err:
			default:
			}
			return
		}
		if wireIDs != nil {
			wireIDs <- request.Id
		}
		response := new(D.Msg)
		response.SetReply(request)
		response.Truncated = truncated
		packed, packErr := response.Pack()
		if packErr != nil {
			select {
			case serverErr <- packErr:
			default:
			}
			return
		}
		if _, err = server.WriteToUDP(packed, clientAddr); err != nil && !errors.Is(err, net.ErrClosed) {
			select {
			case serverErr <- err:
			default:
			}
			return
		}
	}
}

func serveTCPQueries(listener net.Listener, serverErr chan<- error) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				select {
				case serverErr <- err:
				default:
				}
			}
			return
		}
		go func() {
			defer connection.Close()
			conn := &D.Conn{Conn: connection}
			for {
				request, readErr := conn.ReadMsg()
				if readErr != nil {
					return
				}
				response := new(D.Msg)
				response.SetReply(request)
				if writeErr := conn.WriteMsg(response); writeErr != nil {
					return
				}
			}
		}()
	}
}

func newTestPlainClient(schema string, dial func(context.Context, string, string) (net.Conn, error)) *client {
	plainClient := &client{
		host:        "127.0.0.1",
		port:        "53",
		schema:      schema,
		dialContext: dial,
	}
	plainClient.initPools()
	return plainClient
}

func BenchmarkPlainTCPClientReuse(b *testing.B) {
	var dials atomic.Int32
	plainClient := newTestPlainClient("tcp", func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			conn := &D.Conn{Conn: server}
			for {
				request, err := conn.ReadMsg()
				if err != nil {
					return
				}
				response := new(D.Msg)
				response.SetReply(request)
				if err = conn.WriteMsg(response); err != nil {
					return
				}
			}
		}()
		return client, nil
	})
	b.Cleanup(plainClient.close)
	query := testDNSQuery()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := plainClient.ExchangeContext(context.Background(), query); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(dials.Load()), "dials")
	if dials.Load() != 1 {
		b.Fatalf("unexpected dial count %d", dials.Load())
	}
}
