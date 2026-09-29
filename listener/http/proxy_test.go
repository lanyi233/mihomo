package http

import (
	"bufio"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

// upstreamTunnel plays the upstream server. With earlyReply it answers as soon
// as it has the request headers and never reads the upload, like a server
// refusing a body with 413; otherwise it reads each body before answering.
type upstreamTunnel struct{ earlyReply bool }

func (u upstreamTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if u.earlyReply {
			_, _ = io.WriteString(conn, "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		if _, err = io.Copy(io.Discard, req.Body); err != nil {
			return
		}
		if _, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
	}
}

func (upstreamTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}

func (upstreamTunnel) NatTable() C.NatTable { return nil }

// overlapDetectingConn records whether two goroutines were ever inside Read at
// once. Everything HandleConn reads from the client goes through one
// bufio.Reader, so an overlap here is that bufio.Reader being used concurrently.
type overlapDetectingConn struct {
	net.Conn
	readers    atomic.Int32
	overlapped atomic.Bool
}

func (c *overlapDetectingConn) Read(b []byte) (int, error) {
	if c.readers.Add(1) > 1 {
		c.overlapped.Store(true)
	}
	defer c.readers.Add(-1)
	return c.Conn.Read(b)
}

func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	client, err = net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, err = ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// When the upstream answers before the upload is complete, the Transport's
// write goroutine is still reading the request body out of the connection's
// bufio.Reader after client.Do returns. Going back to ReadRequest on that same
// reader races it (issue #3146 panicked in bufio.ReadSlice with r > w), and the
// unread rest of the body would be parsed as the next request anyway, so the
// client connection has to be closed after the response instead.
func TestHandleConnClosesInsteadOfReadingOnWhileTheBodyIsStillBeingSent(t *testing.T) {
	client, server := loopbackPair(t)
	conn := &overlapDetectingConn{Conn: server}

	done := serveHandleConn(conn, upstreamTunnel{earlyReply: true})

	// Announce a body but send none of it: the Transport blocks reading it.
	_, err := io.WriteString(client, "POST http://example.com/upload HTTP/1.1\r\n"+
		"Host: example.com\r\n"+
		"Proxy-Connection: keep-alive\r\n"+
		"Content-Length: 1048576\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(client)
	readProxyResponse(t, client, br, http.StatusRequestEntityTooLarge)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = br.ReadByte()
	require.False(t, conn.overlapped.Load(), "the next ReadRequest ran concurrently with the Transport reading the body")
	require.ErrorIs(t, err, io.EOF, "the connection must be closed while the request body is unread")

	waitHandleConn(t, client, done)
}

// Closing only when the body is still in flight must not cost keep-alive for an
// upload the upstream read in full before answering.
func TestHandleConnKeepsAliveAfterAFullySentBody(t *testing.T) {
	client, server := loopbackPair(t)
	conn := &overlapDetectingConn{Conn: server}
	done := serveHandleConn(conn, upstreamTunnel{})

	br := bufio.NewReader(client)
	for i := 0; i < 3; i++ {
		_, err := io.WriteString(client, "POST http://example.com/upload HTTP/1.1\r\n"+
			"Host: example.com\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Content-Length: 5\r\n\r\nhello")
		require.NoError(t, err)
		readProxyResponse(t, client, br, http.StatusOK)
	}
	require.False(t, conn.overlapped.Load())

	waitHandleConn(t, client, done)
}

func serveHandleConn(conn net.Conn, tunnel C.Tunnel) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleConn(conn, tunnel, authStore.Nil)
	}()
	return done
}

func readProxyResponse(t *testing.T, client net.Conn, br *bufio.Reader, status int) {
	t.Helper()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, status, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
}

func waitHandleConn(t *testing.T, client net.Conn, done <-chan struct{}) {
	t.Helper()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not return")
	}
}
