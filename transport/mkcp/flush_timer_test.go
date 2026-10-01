package mkcp

import (
	"testing"
	"testing/synctest"
	"time"
)

type packetCapture chan []byte

func (p packetCapture) Write(b []byte) (int, error) {
	p <- append([]byte(nil), b...)
	return len(b), nil
}

func TestIdleFlushKeepsPingAndInactivityDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		packets := make(packetCapture, 32)
		conn := newConn(nil, nil, 1, packetWriter{writer: packets}, nil, Config{})
		defer conn.terminate()
		synctest.Wait()
		if got := conn.nextFlushDelay(time.Now()); got != 3*time.Second {
			t.Fatalf("idle flush delay = %v, want 3s", got)
		}
		time.Sleep(2999 * time.Millisecond)
		if len(packets) != 0 {
			t.Fatal("idle connection sent an early packet")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		select {
		case wire := <-packets:
			seg, _ := readSegment(wire)
			if seg.command() != commandPing {
				t.Fatalf("expected keepalive ping, got %v", seg.command())
			}
		default:
			t.Fatal("idle keepalive was delayed")
		}
		time.Sleep(27 * time.Second)
		synctest.Wait()
		conn.mu.Lock()
		state := conn.state
		conn.mu.Unlock()
		if state != stateTerminating {
			t.Fatalf("inactivity timeout was delayed: state = %v", state)
		}
	})
}

func TestIdleFlushWakesForWriteAndRetransmits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		packets := make(packetCapture, 32)
		conn := newConn(nil, nil, 1, packetWriter{writer: packets}, nil, Config{})
		defer conn.terminate()
		synctest.Wait()
		time.Sleep(time.Second)
		if _, err := conn.Write([]byte("payload")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(packets) != 1 {
			t.Fatal("write did not wake the idle flush loop immediately")
		}
		<-packets
		if got := conn.nextFlushDelay(time.Now()); got != 50*time.Millisecond {
			t.Fatalf("pending data changed transmission interval: %v", got)
		}
		time.Sleep(99 * time.Millisecond)
		if len(packets) != 0 {
			t.Fatal("data retransmitted before RTO")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if len(packets) != 1 {
			t.Fatal("data was not retransmitted at its RTO")
		}
		<-packets
		conn.Input([]segment{&ackSegment{conv: 1, receivingNext: 1}})
		synctest.Wait()
		if got := conn.nextFlushDelay(time.Now()); got != 3*time.Second {
			t.Fatalf("acknowledged connection did not return to idle cadence: %v", got)
		}
	})
}

func TestIdleFlushWakesForControlClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		packets := make(packetCapture, 128)
		conn := newConn(nil, nil, 1, packetWriter{writer: packets}, nil, Config{})
		defer conn.terminate()
		synctest.Wait()
		time.Sleep(time.Second)
		conn.Input([]segment{&cmdOnlySegment{conv: 1, cmd: commandTerminate}})
		synctest.Wait()
		// The peer-termination grace period is still four seconds, followed
		// by the original transmission cadence for the terminate handshake.
		time.Sleep(4100 * time.Millisecond)
		synctest.Wait()
		terminated := false
		for len(packets) > 0 {
			seg, _ := readSegment(<-packets)
			terminated = terminated || seg.command() == commandTerminate
		}
		if !terminated {
			t.Fatal("control close waited for an idle ping instead of the close deadline")
		}
	})
}
