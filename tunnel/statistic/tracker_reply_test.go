package statistic

import (
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// trackerReplyNetConn answers every read with a few bytes, so a read through
// the tracker counts as a reply.
type trackerReplyNetConn struct{ trackerTestNetConn }

func (trackerReplyNetConn) Read(b []byte) (int, error) { return copy(b, "pong"), nil }

func TestAwaitingReplyOnlyForAnUnansweredSend(t *testing.T) {
	const wait = 10 * time.Second
	now := time.Now()
	ago := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }

	for _, testCase := range []struct {
		name       string
		upload     int64
		download   int64
		awaitReply bool
	}{
		{name: "nothing carried yet", awaitReply: false},
		{name: "only ever received", download: ago(time.Minute), awaitReply: false},
		{name: "answered, then idle", upload: ago(time.Minute), download: ago(59 * time.Second), awaitReply: false},
		{name: "sent just now", upload: ago(time.Second), download: ago(time.Minute), awaitReply: false},
		{name: "sent and never answered", upload: ago(20 * time.Second), awaitReply: true},
		{name: "sent after the last answer and left unanswered", upload: ago(20 * time.Second), download: ago(30 * time.Second), awaitReply: true},
		{name: "unanswered for exactly the wait", upload: ago(wait), awaitReply: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			info := &TrackerInfo{}
			info.LastUpload.Store(testCase.upload)
			info.LastDownload.Store(testCase.download)
			if got := info.AwaitingReply(now, wait); got != testCase.awaitReply {
				t.Fatalf("AwaitingReply = %v, want %v", got, testCase.awaitReply)
			}
		})
	}
}

func TestTCPTrackerStampsEachDirectionItCarries(t *testing.T) {
	conn := &trackerTestConn{ExtendedConn: N.NewExtendedConn(trackerReplyNetConn{}), chain: C.Chain{uniqueTrackerTestName(t)}}
	tracker := NewTCPTracker(conn, &Manager{}, &C.Metadata{}, nil, 0, 0, false)
	defer tracker.Close()
	later := func() time.Time { return time.Now().Add(time.Minute) }

	if tracker.AwaitingReply(later(), time.Second) {
		t.Fatal("a connection that has carried nothing is awaiting a reply")
	}
	if _, err := tracker.Write([]byte("ping")); err != nil {
		t.Fatalf("write tracker: %v", err)
	}
	if !tracker.AwaitingReply(later(), time.Second) {
		t.Fatal("a write through the tracker was not stamped")
	}
	if _, err := tracker.Read(make([]byte, 16)); err != nil {
		t.Fatalf("read tracker: %v", err)
	}
	if tracker.AwaitingReply(later(), time.Second) {
		t.Fatal("a read through the tracker did not count as the reply")
	}
}

// Bytes a dial already moved before the tracker existed -- a peeked ClientHello,
// most often -- still went out, and a connection whose only traffic is that
// unanswered hello is as stuck as any other.
func TestTCPTrackerStampsTrafficCountedBeforeTracking(t *testing.T) {
	conn := newTrackerTestConn(uniqueTrackerTestName(t), nil)
	tracker := NewTCPTracker(conn, &Manager{}, &C.Metadata{}, nil, 128, 0, false)
	defer tracker.Close()

	if !tracker.AwaitingReply(tracker.Start.Add(time.Minute), time.Second) {
		t.Fatal("upload counted at creation was not stamped")
	}
	if tracker.AwaitingReply(tracker.Start, time.Second) {
		t.Fatal("upload counted at creation was stamped in the past")
	}
}
