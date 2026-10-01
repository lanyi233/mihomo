package hysteria2_realm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"sync"
	"time"
)

const (
	sessionTTL              = time.Minute
	reaperInterval          = time.Second
	defaultRealmNamePattern = `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`
)

const (
	eventsBufferSize   = 16
	maxPendingAttempts = eventsBufferSize
)

type session struct {
	id        string
	realmID   string
	addresses []string
	expires   time.Time
	events    chan sessionEvent
	done      chan struct{}
	closed    bool
	clientIP  string
	pending   map[string]chan punchResponsePayload
}

type sessionEvent struct {
	kind string
	data any
}

type punchResponsePayload struct {
	addresses []string
}

type serverConfig struct {
	realmToken     string
	maxRealms      int
	maxRealmsPerIP int
	proxyHeader    string
	realmIDPattern *regexp.Regexp
}

type server struct {
	mu             sync.Mutex
	realms         map[string]*session // realmID -> session
	sessions       map[string]*session // sessionID -> session
	ipCounts       map[string]int      // clientIP -> realm count
	reaperWake     chan struct{}
	realmToken     string
	maxRealms      int
	maxRealmsPerIP int
	proxyHeader    string
	realmIDPattern *regexp.Regexp
}

func newServer(cfg serverConfig) *server {
	pat := cfg.realmIDPattern
	if pat == nil {
		pat = regexp.MustCompile(defaultRealmNamePattern)
	}
	return &server{
		realms:         make(map[string]*session),
		sessions:       make(map[string]*session),
		ipCounts:       make(map[string]int),
		reaperWake:     make(chan struct{}, 1),
		realmToken:     cfg.realmToken,
		maxRealms:      cfg.maxRealms,
		maxRealmsPerIP: cfg.maxRealmsPerIP,
		proxyHeader:    cfg.proxyHeader,
		realmIDPattern: pat,
	}
}

func randToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *server) getSessionByToken(token string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[token]
	if sess == nil || sess.closed || time.Now().After(sess.expires) {
		return nil
	}
	return sess
}

func (s *server) removeSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeSessionLocked(sess)
}

func (s *server) removeSessionLocked(sess *session) {
	if sess.closed {
		return
	}
	sess.closed = true
	close(sess.done)
	if s.realms[sess.realmID] == sess {
		delete(s.realms, sess.realmID)
	}
	if _, ok := s.sessions[sess.id]; ok {
		s.ipCounts[sess.clientIP]--
		if s.ipCounts[sess.clientIP] <= 0 {
			delete(s.ipCounts, sess.clientIP)
		}
	}
	delete(s.sessions, sess.id)
	if len(s.sessions) == 0 {
		s.wakeReaper()
	}
	for nonce, ch := range sess.pending {
		close(ch)
		delete(sess.pending, nonce)
	}
}

func (s *server) registerPending(sess *session, nonce string) (chan punchResponsePayload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed || len(sess.pending) >= maxPendingAttempts {
		return nil, false
	}
	if _, exists := sess.pending[nonce]; exists {
		// Nonce collision? Silently drop the attempt.
		return nil, false
	}
	ch := make(chan punchResponsePayload, 1)
	sess.pending[nonce] = ch
	return ch, true
}

func (s *server) deliverPending(sess *session, nonce string, payload punchResponsePayload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	ch, ok := sess.pending[nonce]
	if !ok {
		return false
	}
	delete(sess.pending, nonce)
	select {
	case ch <- payload:
	default:
	}
	return true
}

func (s *server) cancelPending(sess *session, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(sess.pending, nonce)
}

func (s *server) sendEvent(sess *session, ev sessionEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	select {
	case sess.events <- ev:
		return true
	default:
		return false
	}
}

func (s *server) reaper(ctx context.Context) {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		next := s.reapExpiredSessions(time.Now())
		var timerC <-chan time.Time
		if !next.IsZero() {
			// Keep the existing one-second sweep bound for a busy server,
			// while skipping all polls before the earliest possible expiry.
			delay := max(time.Until(next), reaperInterval)
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				timer.Reset(delay)
			}
			timerC = timer.C
		} else if timer != nil {
			timer.Stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-s.reaperWake:
		case <-timerC:
		}
	}
}

func (s *server) wakeReaper() {
	select {
	case s.reaperWake <- struct{}{}:
	default:
	}
}

func (s *server) reapExpiredSessions(now time.Time) time.Time {
	s.mu.Lock()
	var next time.Time
	var expired []*session
	for _, sess := range s.sessions {
		if now.After(sess.expires) {
			s.removeSessionLocked(sess)
			expired = append(expired, sess)
		} else if next.IsZero() || sess.expires.Before(next) {
			next = sess.expires
		}
	}
	s.mu.Unlock()
	for _, sess := range expired {
		debugf("session expired realm=%s session=%s", sess.realmID, sess.id)
	}
	if !next.IsZero() {
		// Session authorization remains valid at the exact deadline, and
		// expires just after it, as in getSessionByToken.
		next = next.Add(time.Nanosecond)
	}
	return next
}
