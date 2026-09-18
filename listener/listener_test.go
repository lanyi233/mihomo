package listener

import (
	"errors"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

type stubInboundConfig struct{ name string }

func (c stubInboundConfig) Name() string { return c.name }

func (c stubInboundConfig) Equal(config C.InboundConfig) bool {
	other, ok := config.(stubInboundConfig)
	return ok && other.name == c.name
}

type stubInboundListener struct {
	name      string
	listens   int
	closes    int
	listenErr error
}

func (s *stubInboundListener) Name() string                 { return s.name }
func (s *stubInboundListener) Listen(tunnel C.Tunnel) error { s.listens++; return s.listenErr }
func (s *stubInboundListener) Close() error                 { s.closes++; return nil }
func (s *stubInboundListener) Address() string              { return "" }
func (s *stubInboundListener) RawAddress() string           { return "" }
func (s *stubInboundListener) Config() C.InboundConfig      { return stubInboundConfig{name: s.name} }

type stubStaleListener struct {
	stubInboundListener
	stale bool
}

func (s *stubStaleListener) Stale() bool { return s.stale }

func withInboundListeners(t *testing.T, listeners map[string]C.InboundListener) {
	t.Helper()
	previous := inboundListeners
	t.Cleanup(func() { inboundListeners = previous })
	inboundListeners = listeners
}

// A tun listener bakes the eBPF route exclusion into its device, and the patch
// loop walks a map: it can build that device before the eBPF inbound has
// published anything, and an unchanged tun section would never rebuild it again.
// Only the listeners that say they moved are restarted.
func TestRebuildStaleListenersRestartsOnlyWhatMoved(t *testing.T) {
	stale := &stubStaleListener{stale: true}
	current := &stubStaleListener{}
	plain := &stubInboundListener{}
	withInboundListeners(t, map[string]C.InboundListener{
		"tun-stale": stale,
		"tun":       current,
		"http":      plain,
	})

	rebuildStaleListeners(nil)

	if stale.closes != 1 || stale.listens != 1 {
		t.Fatalf("expected the stale listener to be closed and restarted once, got %d close(s) and %d listen(s)", stale.closes, stale.listens)
	}
	if _, ok := inboundListeners["tun-stale"]; !ok {
		t.Fatal("expected a restarted listener to stay registered")
	}
	if current.closes != 0 || current.listens != 0 {
		t.Fatal("expected a listener that did not move to be left alone")
	}
	if plain.closes != 0 || plain.listens != 0 {
		t.Fatal("expected a listener with no build state of its own to be left alone")
	}
}

// A listener that cannot come back is closed and gone. Leaving it registered
// would hand later reloads a dead listener that compares equal to its config and
// is therefore never rebuilt.
func TestRebuildStaleListenersDropsOneThatCannotRestart(t *testing.T) {
	broken := &stubStaleListener{stale: true}
	broken.listenErr = errors.New("device busy")
	withInboundListeners(t, map[string]C.InboundListener{"tun": broken})

	rebuildStaleListeners(nil)

	if broken.closes != 1 || broken.listens != 1 {
		t.Fatalf("expected one close and one failed listen, got %d and %d", broken.closes, broken.listens)
	}
	if _, ok := inboundListeners["tun"]; ok {
		t.Fatal("expected a listener that failed to restart to be dropped")
	}
}

// The rebuild has to be wired into the patch itself: a config that did not
// change makes the loop keep the running listener, and that is exactly the case
// where the state underneath it may have moved.
func TestPatchInboundListenersRebuildsAListenerItLeftAlone(t *testing.T) {
	running := &stubStaleListener{stale: true}
	running.name = "tun"
	withInboundListeners(t, map[string]C.InboundListener{"tun": running})

	replacement := &stubStaleListener{}
	replacement.name = "tun"
	PatchInboundListeners(map[string]C.InboundListener{"tun": replacement}, nil, true)

	if replacement.listens != 0 {
		t.Fatal("expected an unchanged config to keep the running listener rather than swap in a new one")
	}
	if running.closes != 1 || running.listens != 1 {
		t.Fatalf("expected the running listener to be restarted for the state that moved, got %d close(s) and %d listen(s)", running.closes, running.listens)
	}
}

// Cleanup tears the TUN device down, so the config that described it has to stop
// answering for it. ReCreateTun compares against both of these, and a later call
// with the same config would otherwise decide nothing changed and leave the
// tunnel with no device at all.
func TestCleanupClearsTheTunStateItInvalidated(t *testing.T) {
	withInboundListeners(t, map[string]C.InboundListener{})

	previousConf, previousExclude := LastTunConf, lastTunEBPFExclude
	t.Cleanup(func() { LastTunConf, lastTunEBPFExclude = previousConf, previousExclude })
	LastTunConf = LC.Tun{Enable: true, Device: "utun0"}
	lastTunEBPFExclude = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	Cleanup()

	if LastTunConf.Enable || LastTunConf.Device != "" {
		t.Fatalf("expected the tun config to be cleared, got %+v", LastTunConf)
	}
	if lastTunEBPFExclude != nil {
		t.Fatalf("expected the recorded route exclusion to be cleared, got %v", lastTunEBPFExclude)
	}
}

type stubUpdatableListener struct {
	stubInboundListener
	updates   int
	handled   bool
	updateErr error
	applied   C.InboundConfig
}

func (s *stubUpdatableListener) Update(newConfig C.InboundConfig) (bool, error) {
	s.updates++
	if s.updateErr != nil {
		return false, s.updateErr
	}
	if s.handled {
		s.applied = newConfig
	}
	return s.handled, nil
}

// Rebuilding the eBPF inbound destroys every kernel map it owns, so a listener
// that can take the difference in place keeps running and the replacement is
// discarded unused.
func TestPatchInboundListenersKeepsAListenerThatAbsorbedTheChange(t *testing.T) {
	running := &stubUpdatableListener{handled: true}
	running.name = "ebpf"
	withInboundListeners(t, map[string]C.InboundListener{"ebpf": running})

	replacement := &stubInboundListener{name: "ebpf-changed"}
	PatchInboundListeners(map[string]C.InboundListener{"ebpf": replacement}, nil, true)

	if running.updates != 1 {
		t.Fatalf("expected the running listener to be offered the change once, got %d", running.updates)
	}
	if running.closes != 0 {
		t.Fatal("expected a listener that absorbed the change to stay running")
	}
	if replacement.listens != 0 {
		t.Fatal("expected the replacement to be discarded unused")
	}
	if inboundListeners["ebpf"] != C.InboundListener(running) {
		t.Fatal("expected the running listener to stay registered")
	}
	if running.applied == nil {
		t.Fatal("expected the new config to be handed to the running listener")
	}
}

// Anything the listener will not take falls back to exactly what used to
// happen, so a listener can implement Update for one field and stay correct.
func TestPatchInboundListenersRebuildsWhatTheListenerDeclines(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		listener *stubUpdatableListener
	}{
		{name: "declined", listener: &stubUpdatableListener{handled: false}},
		{name: "failed", listener: &stubUpdatableListener{updateErr: errors.New("map is full")}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			running := testCase.listener
			running.name = "ebpf"
			withInboundListeners(t, map[string]C.InboundListener{"ebpf": running})

			replacement := &stubInboundListener{name: "ebpf-changed"}
			PatchInboundListeners(map[string]C.InboundListener{"ebpf": replacement}, nil, true)

			if running.closes != 1 {
				t.Fatalf("expected the declined listener to be closed, got %d close(s)", running.closes)
			}
			if replacement.listens != 1 {
				t.Fatalf("expected the replacement to be started, got %d listen(s)", replacement.listens)
			}
			if inboundListeners["ebpf"] != C.InboundListener(replacement) {
				t.Fatal("expected the replacement to be registered")
			}
		})
	}
}

// An unchanged config never reaches Update at all: there is nothing to apply,
// and asking would make every reload do work for no reason.
func TestPatchInboundListenersDoesNotOfferAnUnchangedConfig(t *testing.T) {
	running := &stubUpdatableListener{handled: true}
	running.name = "ebpf"
	withInboundListeners(t, map[string]C.InboundListener{"ebpf": running})

	replacement := &stubInboundListener{name: "ebpf"}
	PatchInboundListeners(map[string]C.InboundListener{"ebpf": replacement}, nil, true)

	if running.updates != 0 {
		t.Fatalf("expected no update for an unchanged config, got %d", running.updates)
	}
	if running.closes != 0 || replacement.listens != 0 {
		t.Fatal("expected an unchanged config to leave both listeners alone")
	}
}
