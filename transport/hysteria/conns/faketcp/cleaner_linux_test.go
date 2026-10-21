//go:build linux && !no_fake_tcp

package faketcp

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestCleanerRepeatsAndStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &TCPConn{die: make(chan struct{}), flowTable: make(map[string]*tcpFlow)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn.cleanerLoop(time.Second)
		}()
		synctest.Wait()
		for round := 0; round < 3; round++ {
			conn.flowsLock.Lock()
			conn.flowTable["expired"] = &tcpFlow{ts: time.Now().Add(-2 * expire)}
			conn.flowTable["live"] = &tcpFlow{ts: time.Now()}
			conn.flowsLock.Unlock()
			time.Sleep(time.Second)
			synctest.Wait()
			conn.flowsLock.Lock()
			_, expired := conn.flowTable["expired"]
			_, live := conn.flowTable["live"]
			conn.flowsLock.Unlock()
			if expired || !live {
				t.Fatalf("round %d: expired=%v live=%v", round, expired, live)
			}
		}
		close(conn.die)
		<-done
	})
}
