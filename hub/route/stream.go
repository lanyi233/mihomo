package route

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/http"
)

// HTTP no longer owns a hijacked connection. Read control frames so an idle
// stream notices peer closure without waiting for the next outbound update.
type websocketStream struct {
	net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	stopClose func() bool
	writeMu   sync.Mutex
}

func newWebsocketStream(ctx context.Context, conn net.Conn, reader io.Reader) *websocketStream {
	ctx, cancel := context.WithCancel(ctx)
	s := &websocketStream{Conn: conn, ctx: ctx, cancel: cancel}
	s.stopClose = context.AfterFunc(ctx, func() { _ = conn.Close() })
	go s.readControl(reader)
	return s
}

func (s *websocketStream) Close() error {
	s.stopClose()
	s.cancel()
	return s.Conn.Close()
}

func (s *websocketStream) readControl(source io.Reader) {
	defer s.Close()
	control := func(header ws.Header, body io.Reader) error {
		if header.OpCode == ws.OpPing || header.OpCode == ws.OpClose {
			var payload [125]byte
			n, err := io.ReadFull(body, payload[:header.Length])
			if err != nil {
				return err
			}
			if header.OpCode == ws.OpClose {
				_ = wsWriteServerMessage(s, byte(ws.OpClose), payload[:n])
				return io.EOF
			}
			return wsWriteServerMessage(s, byte(ws.OpPong), payload[:n])
		}
		_, err := io.Copy(io.Discard, body)
		return err
	}
	reader := wsutil.NewServerSideReader(source)
	reader.OnIntermediate = control
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return
		}
		if header.OpCode.IsControl() {
			err = control(header, reader)
		} else {
			// These API streams accept no application messages. Discard them
			// without allocating a buffer proportional to the advertised size.
			err = reader.Discard()
		}
		if err != nil {
			return
		}
	}
}

func streamContext(r *http.Request, conn net.Conn) context.Context {
	if stream, ok := conn.(*websocketStream); ok {
		return stream.ctx
	}
	return r.Context()
}

const streamWriteTimeout = 10 * time.Second

// Keep writes and flushes bounded even if an HTTP client stops reading. A
// cancelled request interrupts outstanding I/O; cleanup waits for that callback
// before clearing the deadline so it cannot poison a reused HTTP connection.
type httpStreamWriter struct {
	ctx        context.Context
	writer     http.ResponseWriter
	controller *http.ResponseController
	deadlineMu sync.Mutex
	stopCancel func() bool
	cancelDone chan struct{}
}

func newHTTPStreamWriter(ctx context.Context, writer http.ResponseWriter) *httpStreamWriter {
	s := &httpStreamWriter{
		ctx: ctx, writer: writer,
		controller: http.NewResponseController(writer),
		cancelDone: make(chan struct{}),
	}
	s.stopCancel = context.AfterFunc(ctx, func() {
		defer close(s.cancelDone)
		s.deadlineMu.Lock()
		defer s.deadlineMu.Unlock()
		_ = s.controller.SetWriteDeadline(time.Now())
	})
	return s
}

func (s *httpStreamWriter) Write(payload []byte) error {
	s.deadlineMu.Lock()
	if err := s.ctx.Err(); err != nil {
		s.deadlineMu.Unlock()
		return err
	}
	_ = s.controller.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	s.deadlineMu.Unlock()
	if _, err := s.writer.Write(payload); err != nil {
		return err
	}
	return s.controller.Flush()
}

func (s *httpStreamWriter) Close() {
	if !s.stopCancel() {
		<-s.cancelDone
	}
	_ = s.controller.SetWriteDeadline(time.Time{})
}
