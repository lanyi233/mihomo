package httpmask

import "time"

// batchTimer bounds the age of a pending upload without waking idle tunnels.
// It is owned by the push loop; more writes must not postpone an armed timer.
type batchTimer struct {
	timer *time.Timer
	C     <-chan time.Time
}

func (t *batchTimer) start(delay time.Duration) {
	if t.C != nil {
		return
	}
	if t.timer == nil {
		t.timer = time.NewTimer(delay)
	} else {
		resetTimer(t.timer, delay)
	}
	t.C = t.timer.C
}

func (t *batchTimer) stop() {
	if t.timer != nil {
		t.timer.Stop()
	}
	t.C = nil
}
