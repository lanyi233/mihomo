package power

import "testing"

func TestBackgroundNetworkOwnership(t *testing.T) {
	m := newBackgroundManager()
	a := m.newNetworkSource()
	assertState := func(want bool) {
		t.Helper()
		got, _ := m.state()
		if got != want {
			t.Fatalf("paused=%v, want %v", got, want)
		}
	}
	assertState(false) // Unknown is not evidence that the network is offline.
	a.SetAvailable(false)
	assertState(true)
	b := m.newNetworkSource()
	assertState(false) // A replacement monitor is still starting.
	b.SetAvailable(true)
	assertState(false)
	a.Close()
	a.SetAvailable(false) // Late callback from a closed monitor must be ignored.
	assertState(false)
	b.SetAvailable(false)
	assertState(true)
	b.Close()
	assertState(false)
}

func TestBackgroundNotificationsAndDevicePause(t *testing.T) {
	m := newBackgroundManager()
	_, changed := m.state()
	m.setDevicePaused(false)
	select {
	case <-changed:
		t.Fatal("unchanged state woke subscribers")
	default:
	}
	m.setDevicePaused(true)
	select {
	case <-changed:
	default:
		t.Fatal("missing pause notification")
	}
	a := m.newNetworkSource()
	a.SetAvailable(true)
	paused, changed := m.state()
	if !paused {
		t.Fatal("network availability cleared device pause")
	}
	m.setDevicePaused(false)
	select {
	case <-changed:
	default:
		t.Fatal("missing resume notification")
	}
	if paused, _ := m.state(); paused {
		t.Fatal("did not resume")
	}
}
