package route

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gobwas/ws"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type blockingHTTPStreamWriter struct {
	net.Conn
	blockFlush bool
	started    chan struct{}
	once       sync.Once
	deadlineMu sync.Mutex
	deadline   time.Time
}

func (*blockingHTTPStreamWriter) Header() http.Header { return make(http.Header) }
func (*blockingHTTPStreamWriter) WriteHeader(int)     {}
func (w *blockingHTTPStreamWriter) Write(p []byte) (int, error) {
	if w.blockFlush {
		return len(p), nil
	}
	w.once.Do(func() { close(w.started) })
	return w.Conn.Write(p)
}
func (w *blockingHTTPStreamWriter) FlushError() error {
	if !w.blockFlush {
		return nil
	}
	w.once.Do(func() { close(w.started) })
	_, err := w.Conn.Write([]byte("buffered response"))
	return err
}
func (w *blockingHTTPStreamWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlineMu.Lock()
	w.deadline = deadline
	w.deadlineMu.Unlock()
	return w.Conn.SetWriteDeadline(deadline)
}

func TestHTTPStreamCancellationInterruptsBlockedIO(t *testing.T) {
	for _, blockFlush := range []bool{false, true} {
		name := "write"
		if blockFlush {
			name = "flush"
		}
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writer := &blockingHTTPStreamWriter{Conn: server, blockFlush: blockFlush, started: make(chan struct{})}
			stream := newHTTPStreamWriter(ctx, writer)
			done := make(chan error, 1)
			go func() { done <- stream.Write([]byte("response")) }()
			select {
			case <-writer.started:
			case <-time.After(time.Second):
				t.Fatal("stream did not reach blocking I/O")
			}
			writer.deadlineMu.Lock()
			bounded := !writer.deadline.IsZero()
			writer.deadlineMu.Unlock()
			if !bounded {
				t.Fatal("stream started I/O without a write deadline")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked I/O succeeded without a reader")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt blocked I/O")
			}
			if err := stream.Write([]byte("later")); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled stream started another write: %v", err)
			}
			stream.Close()
			writer.deadlineMu.Lock()
			cleared := writer.deadline.IsZero()
			writer.deadlineMu.Unlock()
			if !cleared {
				t.Fatal("stream left a deadline on the reusable HTTP connection")
			}
			// Verify the actual connection, not just the recorded deadline.
			go func() { _, err := server.Write([]byte("next")); done <- err }()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 4)); err != nil {
				t.Fatalf("connection could not be reused: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatalf("next request inherited cancelled deadline: %v", err)
			}
		})
	}
}

func TestHTTPStreamTimesOutBlockedIO(t *testing.T) {
	for _, blockFlush := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			writer := &blockingHTTPStreamWriter{Conn: server, blockFlush: blockFlush, started: make(chan struct{})}
			stream := newHTTPStreamWriter(context.Background(), writer)
			defer stream.Close()
			started := time.Now()
			err := stream.Write([]byte("response"))
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("blocked stream did not time out: %v", err)
			}
			if elapsed := time.Since(started); elapsed != streamWriteTimeout {
				t.Fatalf("blocked stream timed out after %s, want %s", elapsed, streamWriteTimeout)
			}
		})
	}
}

func TestHTTPStreamsStopOnCancellation(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{"traffic": traffic, "memory": memory, "logs": getLogs} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				handler(httptest.NewRecorder(), r)
			}()
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("idle stream retained its handler after request cancellation")
			}
		})
	}
}

func TestWebsocketStreamControlFrames(t *testing.T) {
	server, client := net.Pipe()
	s := newWebsocketStream(context.Background(), server, server)
	t.Cleanup(func() { _ = s.Close(); _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	for _, op := range []ws.OpCode{ws.OpPing, ws.OpClose} {
		payload := []byte("ping")
		if op == ws.OpClose {
			payload = ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")
		}
		if err := ws.WriteFrame(client, ws.MaskFrameInPlace(ws.NewFrame(op, true, payload))); err != nil {
			t.Fatal(err)
		}
		frame, err := ws.ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		want := ws.OpPong
		if op == ws.OpClose {
			want = ws.OpClose
		}
		if frame.Header.OpCode != want {
			t.Fatalf("control reply = %v, want %v", frame.Header.OpCode, want)
		}
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("close frame did not cancel the idle stream")
	}
}

func TestWebsocketStreamPeerDisconnect(t *testing.T) {
	server, client := net.Pipe()
	s := newWebsocketStream(context.Background(), server, server)
	defer s.Close()
	_ = client.Close()
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("peer disconnect did not cancel the idle stream")
	}
}

func TestConnectionsRejectInvalidIntervalBeforeUpgrade(t *testing.T) {
	for _, interval := range []string{"0", "-1", "invalid", "9223372036854775807"} {
		r := httptest.NewRequest(http.MethodGet, "/connections?interval="+interval, nil)
		r.Header.Set("Upgrade", "websocket")
		w := httptest.NewRecorder()
		getConnections(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("interval %q status = %d, want 400", interval, w.Code)
		}
	}
}
