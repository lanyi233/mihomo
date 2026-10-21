package session

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestClientClosesDialThatFinishesAfterClose(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	conn, peer := net.Pipe()
	defer peer.Close()
	c := NewClient(context.Background(), func(context.Context) (net.Conn, error) {
		close(started)
		<-finish
		return conn, nil
	}, nil, "", time.Hour, time.Hour, 0, true)
	defer c.Close()
	result := make(chan error, 1)
	go func() {
		_, err := c.createSession(context.Background())
		result <- err
	}()
	<-started
	c.Close()
	close(finish)
	if err := <-result; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("late dial error = %v", err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late connection was not closed: %v", err)
	}
}

func TestIdleCleanupWakesForExcessSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewClient(context.Background(), nil, nil, "", 10*time.Second, 10*time.Second, 1, false)
		defer c.Close()
		addIdle := func(seq uint64) *Session {
			conn, peer := net.Pipe()
			t.Cleanup(func() { peer.Close() })
			s := NewClientSession(conn, nil, "")
			s.seq, s.idleSince = seq, time.Now()
			c.sessionsLock.Lock()
			c.sessions[seq] = s
			c.sessionsLock.Unlock()
			c.idleSessionLock.Lock()
			c.idleSession.Insert(math.MaxUint64-seq, s)
			c.idleSessionLock.Unlock()
			c.idleWake <- struct{}{}
			synctest.Wait()
			return s
		}
		time.Sleep(time.Hour)
		first := addIdle(1)
		time.Sleep(time.Hour)
		if first.IsClosed() {
			t.Fatal("minimum idle session was closed")
		}
		second := addIdle(2)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if !first.IsClosed() || second.IsClosed() {
			t.Fatalf("idle retention: first closed=%v, second closed=%v", first.IsClosed(), second.IsClosed())
		}
	})
}
