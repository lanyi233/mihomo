package power

import "sync"

// BackgroundState returns a consistent pause state and change notification.
// Only optional maintenance should pause; application traffic is unaffected.
func BackgroundState() (bool, <-chan struct{}) { return background.state() }

// SetDevicePaused accepts explicit suspend/resume events from platform hosts.
// Screen-off alone must not be treated as suspend: background apps can be active.
func SetDevicePaused(paused bool) { background.setDevicePaused(paused) }

// NewNetworkSource gives a network monitor its own lifetime. Unknown network
// state defaults to active, and a usable route reported by any source wins.
func NewNetworkSource() *NetworkSource { return background.newNetworkSource() }

type networkAvailability struct{ known, available bool }

type backgroundManager struct {
	mu           sync.Mutex
	devicePaused bool
	paused       bool
	changed      chan struct{}
	networks     map[*NetworkSource]networkAvailability
}

type NetworkSource struct{ manager *backgroundManager }

var background = newBackgroundManager()

func newBackgroundManager() *backgroundManager {
	return &backgroundManager{changed: make(chan struct{}), networks: make(map[*NetworkSource]networkAvailability)}
}

func (m *backgroundManager) state() (bool, <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused, m.changed
}

func (m *backgroundManager) publishLocked() {
	offline := len(m.networks) != 0
	for _, state := range m.networks {
		if !state.known || state.available {
			offline = false
			break
		}
	}
	paused := m.devicePaused || offline
	if paused != m.paused {
		m.paused = paused
		close(m.changed)
		m.changed = make(chan struct{})
	}
}

func (m *backgroundManager) setDevicePaused(paused bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devicePaused = paused
	m.publishLocked()
}

func (m *backgroundManager) newNetworkSource() *NetworkSource {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &NetworkSource{manager: m}
	m.networks[s] = networkAvailability{}
	m.publishLocked()
	return s
}

func (s *NetworkSource) SetAvailable(available bool) {
	if s == nil {
		return
	}
	m := s.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, registered := m.networks[s]; !registered {
		return
	}
	m.networks[s] = networkAvailability{known: true, available: available}
	m.publishLocked()
}

func (s *NetworkSource) Close() error {
	if s == nil {
		return nil
	}
	m := s.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.networks, s)
	m.publishLocked()
	return nil
}
