package httpmask

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"
	"testing/synctest"
	"time"

	mhttp "github.com/metacubex/http"
)

func TestBatchTimerIdleAndReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var timer batchTimer
		defer timer.stop()
		if timer.timer != nil || timer.C != nil {
			t.Fatal("idle timer should not allocate or arm a runtime timer")
		}
		timer.start(5 * time.Millisecond)
		time.Sleep(4 * time.Millisecond)
		timer.start(5 * time.Millisecond)
		time.Sleep(time.Millisecond)
		select {
		case <-timer.C:
		default:
			t.Fatal("additional writes postponed the flush deadline")
		}
		timer.stop()
		if timer.C != nil {
			t.Fatal("flushed timer still enabled")
		}
		time.Sleep(time.Second)
		timer.start(5 * time.Millisecond)
		time.Sleep(time.Millisecond)
		timer.stop()
		time.Sleep(time.Second)
		select {
		case <-timer.timer.C:
			t.Fatal("stopped upload timer fired while idle")
		default:
		}
	})
}

func TestPushLoopBatchingAfterIdle(t *testing.T) {
	for _, mode := range []TunnelMode{TunnelModePoll, TunnelModeStream} {
		t.Run(string(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				uploads := make(chan []byte, 16)
				fin := make(chan struct{}, 1)
				client := &mhttp.Client{Transport: roundTripFunc(func(req *mhttp.Request) (*mhttp.Response, error) {
					if req.URL.Path == "/fin" {
						fin <- struct{}{}
					} else {
						payload, err := io.ReadAll(req.Body)
						if err != nil {
							return nil, err
						}
						if mode == TunnelModePoll {
							var decoded []byte
							scanner := bufio.NewScanner(bytes.NewReader(payload))
							for scanner.Scan() {
								line, err := base64.StdEncoding.DecodeString(scanner.Text())
								if err != nil {
									return nil, err
								}
								decoded = append(decoded, line...)
							}
							if err := scanner.Err(); err != nil {
								return nil, err
							}
							payload = decoded
						}
						uploads <- payload
					}
					return &mhttp.Response{StatusCode: mhttp.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(mhttp.Header)}, nil
				})}
				var conn *queuedConn
				maxBatch := 64 * 1024
				if mode == TunnelModePoll {
					c := &pollConn{queuedConn: newQueuedConn(), ctx: context.Background(), client: client,
						readiness: newTunnelReadiness(), pushURL: "http://tunnel/push", finURL: "http://tunnel/fin", headerHost: "tunnel"}
					conn = &c.queuedConn
					go c.pushLoop()
				} else {
					c := &streamSplitConn{queuedConn: newQueuedConn(), ctx: context.Background(), client: client,
						readiness: newTunnelReadiness(), pushURL: "http://tunnel/push", finURL: "http://tunnel/fin", headerHost: "tunnel"}
					conn = &c.queuedConn
					maxBatch = 256 * 1024
					go c.pushLoop()
				}
				defer conn.closeWithError(io.ErrClosedPipe)
				write := func(b []byte) {
					t.Helper()
					if _, err := conn.Write(b); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
				}
				checkUpload := func(want []byte) {
					t.Helper()
					synctest.Wait()
					select {
					case got := <-uploads:
						if !bytes.Equal(got, want) {
							t.Fatalf("upload mismatch: got %d bytes, want %d", len(got), len(want))
						}
					default:
						t.Fatal("pending upload was not flushed")
					}
				}
				for range 2 {
					time.Sleep(time.Second)
					write([]byte("a"))
					time.Sleep(4 * time.Millisecond)
					write([]byte("b"))
					if len(uploads) != 0 {
						t.Fatal("batch flushed before its deadline")
					}
					time.Sleep(time.Millisecond)
					checkUpload([]byte("ab"))
				}
				large := bytes.Repeat([]byte("x"), maxBatch)
				write(large)
				checkUpload(large)
				write([]byte("tail"))
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				checkUpload([]byte("tail"))
				select {
				case <-fin:
				default:
					t.Fatal("CloseWrite did not send FIN")
				}
			})
		})
	}
}
