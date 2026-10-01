package hysteria2_realm

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func registerTestRealm(t *testing.T, s *server, name string) *session {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/"+name, strings.NewReader(`{"addresses":["192.0.2.1:443"]}`))
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("register returned %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.realms[name]
}

func TestReaperRestartsAfterIdleAndClosesExpiredSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newServer(serverConfig{realmToken: "test-token"})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.reaper(ctx)
		synctest.Wait()
		time.Sleep(time.Hour)
		for range 2 {
			sess := registerTestRealm(t, s, "restart")
			pending, ok := s.registerPending(sess, "pending")
			if !ok {
				t.Fatal("pending attempt was rejected")
			}
			synctest.Wait()
			time.Sleep(sessionTTL)
			synctest.Wait()
			if s.getSessionByToken(sess.id) == nil {
				t.Fatal("session expired at or before the authorization deadline")
			}
			time.Sleep(reaperInterval)
			synctest.Wait()
			select {
			case <-sess.done:
			default:
				t.Fatal("reaper did not close the expired session")
			}
			if _, open := <-pending; open {
				t.Fatal("reaper left a pending attempt open")
			}
			if len(s.sessions) != 0 || len(s.realms) != 0 || len(s.ipCounts) != 0 {
				t.Fatal("expired session retained realm or IP quota")
			}
			time.Sleep(time.Hour)
		}
	})
}

func TestReaperHonorsHeartbeatAndLaterRegistrations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newServer(serverConfig{realmToken: "test-token"})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.reaper(ctx)
		first := registerTestRealm(t, s, "first")
		synctest.Wait()
		time.Sleep(sessionTTL / 2)
		second := registerTestRealm(t, s, "second")
		r := httptest.NewRequest(http.MethodPost, "/v1/first/heartbeat", nil)
		r.Header.Set("Authorization", "Bearer "+first.id)
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat returned %d", w.Code)
		}
		time.Sleep(sessionTTL/2 + reaperInterval)
		synctest.Wait()
		if s.getSessionByToken(first.id) == nil || s.getSessionByToken(second.id) == nil {
			t.Fatal("reaper discarded a renewed or later-registered session")
		}
		// Removing one session must not stop the expiry timer for the other.
		s.removeSession(first)
		time.Sleep(sessionTTL / 2)
		synctest.Wait()
		select {
		case <-second.done:
		default:
			t.Fatal("later session did not expire after the first was removed")
		}
		if len(s.sessions) != 0 || len(s.ipCounts) != 0 {
			t.Fatal("reaper retained expired sessions")
		}
	})
}
