package log

import "testing"

func TestDebugEnabledIncludesLiveSubscribers(t *testing.T) {
	oldLevel := Level()
	SetLevel(INFO)
	t.Cleanup(func() { SetLevel(oldLevel) })

	if DebugEnabled() {
		t.Fatal("debug unexpectedly enabled without a subscriber")
	}

	sub := Subscribe()
	if !DebugEnabled() {
		t.Fatal("debug subscriber must keep debug event construction enabled")
	}
	UnSubscribe(sub)

	if DebugEnabled() {
		t.Fatal("debug remained enabled after the last subscriber left")
	}
}
