package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// memSessions is an in-memory SessionStore fake for testing SessionManager.
type memSessions struct{ m map[string]store.Session }

func (s *memSessions) Create(_ context.Context, sess store.Session) (store.Session, error) {
	s.m[sess.ID] = sess
	return sess, nil
}

func (s *memSessions) GetByID(_ context.Context, id string) (store.Session, error) {
	v, ok := s.m[id]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return v, nil
}

func (s *memSessions) Touch(_ context.Context, id string, exp int64) error {
	v, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	v.ExpiresAt = exp
	s.m[id] = v
	return nil
}

func (s *memSessions) Delete(_ context.Context, id string) error {
	delete(s.m, id)
	return nil
}

func newSM(u store.User) (*SessionManager, *memSessions) {
	ms := &memSessions{m: map[string]store.Session{}}
	return NewSessionManager(ms, fakeUsers{u: u}, 720*time.Hour, 7*24*time.Hour), ms
}

func TestSession_CreateAuthenticate(t *testing.T) {
	sm, _ := newSM(store.User{ID: "u1"})
	sess, err := sm.Create(t.Context(), "u1", "1.2.3.4", "agent")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" || sess.CSRFToken == "" {
		t.Fatal("session must have id + csrf")
	}
	u, got, err := sm.Authenticate(t.Context(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "u1" || got.ID != sess.ID {
		t.Fatal("authenticate returned wrong identity")
	}
}

func TestSession_Authenticate_SlidesExpiry(t *testing.T) {
	sm, ms := newSM(store.User{ID: "u1"})
	start := int64(1_700_000_000)
	sm.now = func() int64 { return start }
	sess, err := sm.Create(t.Context(), "u1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	origExpiry := sess.ExpiresAt

	// Advance the clock past the slide threshold; expiry must extend and
	// the new value must be persisted back to the store via Touch.
	sm.now = func() int64 { return start + int64((7*24*time.Hour + time.Second).Seconds()) }
	_, got, err := sm.Authenticate(t.Context(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt <= origExpiry {
		t.Fatalf("slide must extend expiry: got %d, want > %d", got.ExpiresAt, origExpiry)
	}
	if ms.m[sess.ID].ExpiresAt != got.ExpiresAt {
		t.Fatal("slide must persist the new expiry via Touch")
	}
}

func TestSession_Authenticate_DisabledUser(t *testing.T) {
	// The user is valid at Create time but disabled by the time Authenticate
	// re-fetches it; a disabled user must fail closed with ErrUnauthorized.
	sm, _ := newSM(store.User{ID: "u1", Disabled: true})
	sess, err := sm.Create(t.Context(), "u1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sm.Authenticate(t.Context(), sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled user must be ErrUnauthorized, got %v", err)
	}
}

func TestSession_Expired(t *testing.T) {
	sm, ms := newSM(store.User{ID: "u1"})
	sess, _ := sm.Create(t.Context(), "u1", "", "")
	s := ms.m[sess.ID]
	s.ExpiresAt = 1
	ms.m[sess.ID] = s // force expired
	if _, _, err := sm.Authenticate(t.Context(), sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired session must be ErrUnauthorized, got %v", err)
	}
}

func TestSession_Destroy(t *testing.T) {
	sm, _ := newSM(store.User{ID: "u1"})
	sess, _ := sm.Create(t.Context(), "u1", "", "")
	if err := sm.Destroy(t.Context(), sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sm.Authenticate(t.Context(), sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("destroyed session must not authenticate")
	}
}

func TestSession_AuthenticateRequest(t *testing.T) {
	const cookieName = "diyddns_session"

	sm, _ := newSM(store.User{ID: "u1"})
	sess, err := sm.Create(t.Context(), "u1", "1.2.3.4", "agent")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid cookie returns user and session", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sess.ID})

		u, got, err := sm.AuthenticateRequest(r, cookieName)
		if err != nil {
			t.Fatal(err)
		}
		if u.ID != "u1" || got.ID != sess.ID {
			t.Fatal("AuthenticateRequest returned wrong identity")
		}
	})

	t.Run("missing cookie is unauthorized", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		if _, _, err := sm.AuthenticateRequest(r, cookieName); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("missing cookie must be ErrUnauthorized, got %v", err)
		}
	})

	t.Run("unknown cookie value is unauthorized", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "does-not-exist"})

		if _, _, err := sm.AuthenticateRequest(r, cookieName); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("unknown cookie must be ErrUnauthorized, got %v", err)
		}
	})
}

// errSessions injects a session-lookup failure that is NOT store.ErrNotFound,
// so session_store_error is reachable separately from unknown_session.
type errSessions struct{ err error }

func (e errSessions) Create(context.Context, store.Session) (store.Session, error) {
	return store.Session{}, e.err
}

func (e errSessions) GetByID(context.Context, string) (store.Session, error) {
	return store.Session{}, e.err
}

func (e errSessions) Touch(context.Context, string, int64) error { return e.err }

func (e errSessions) Delete(context.Context, string) error { return e.err }

// newLiveSession mints a session in a fresh memSessions so a case that needs a
// custom UserReader can still reach the user lookup.
func newLiveSession(t *testing.T, u UserReader) (*SessionManager, string) {
	t.Helper()
	ms := &memSessions{m: map[string]store.Session{}}
	seed := NewSessionManager(ms, fakeUsers{u: store.User{ID: "u"}}, 720*time.Hour, 7*24*time.Hour)
	sess, err := seed.Create(t.Context(), "u", "", "")
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	return NewSessionManager(ms, u, 720*time.Hour, 7*24*time.Hour), sess.ID
}

// All nine Authenticate/AuthenticateRequest reasons. newSM hardcodes both
// stores, so the store-failure cases build the SessionManager directly.
func TestAuthenticate_ReasonPerBranch(t *testing.T) {
	errBoom := errors.New("database is on fire")

	// *_lookup_cancelled: net/http cancels the request context when a browser
	// disconnects mid-request, and the store wraps whatever the driver returns
	// (internal/store/devices.go: `devices.GetByID: %w`). The fake reproduces
	// that wrap so the classification is tested against the shape the real
	// store produces, not against a bare context.Canceled.
	errCancelled := fmt.Errorf("sessions.GetByID: %w", context.Canceled)

	expiredSM, expiredMS := newSM(store.User{ID: "u"})
	expiredSess, err := expiredSM.Create(t.Context(), "u", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := expiredMS.m[expiredSess.ID]
	s.ExpiresAt = 1
	expiredMS.m[expiredSess.ID] = s

	disabledSM, disabledID := newLiveSession(t, fakeUsers{u: store.User{ID: "u", Disabled: true}})
	unknownUserSM, unknownUserID := newLiveSession(t, fakeUsers{err: store.ErrNotFound})
	userErrSM, userErrID := newLiveSession(t, fakeUsers{err: errBoom})

	userCancelledSM, userCancelledID := newLiveSession(t, fakeUsers{err: errCancelled})

	tests := []struct {
		name       string
		sm         *SessionManager
		sessionID  string
		wantReason string
		cancelCtx  bool // run with an already-cancelled context
	}{
		{"unknown_session", NewSessionManager(errSessions{err: store.ErrNotFound}, fakeUsers{u: store.User{ID: "u"}}, 720*time.Hour, 7*24*time.Hour), "sid", "unknown_session", false},
		{"session_lookup_cancelled", NewSessionManager(errSessions{err: errCancelled}, fakeUsers{u: store.User{ID: "u"}}, 720*time.Hour, 7*24*time.Hour), "sid", "session_lookup_cancelled", true},
		{"session_store_error", NewSessionManager(errSessions{err: errBoom}, fakeUsers{u: store.User{ID: "u"}}, 720*time.Hour, 7*24*time.Hour), "sid", "session_store_error", false},
		{"session_expired", expiredSM, expiredSess.ID, "session_expired", false},
		{"unknown_user", unknownUserSM, unknownUserID, "unknown_user", false},
		{"user_lookup_cancelled", userCancelledSM, userCancelledID, "user_lookup_cancelled", true},
		{"user_store_error", userErrSM, userErrID, "user_store_error", false},
		{"user_disabled", disabledSM, disabledID, "user_disabled", false},
	}

	seen := map[string]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if tt.cancelCtx {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			_, _, err := tt.sm.Authenticate(ctx, tt.sessionID)
			// The property that must survive: one sentinel for every reason.
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("errors.Is(err, ErrUnauthorized) = false (err=%v)", err)
			}
			if err.Error() != ErrUnauthorized.Error() {
				t.Fatalf("Error() = %q, want %q", err.Error(), ErrUnauthorized.Error())
			}
			if got := ReasonOf(err); got != tt.wantReason {
				t.Fatalf("ReasonOf = %q, want %q", got, tt.wantReason)
			}
		})
		seen[tt.wantReason] = true
	}

	// The seventh reason belongs to AuthenticateRequest, not Authenticate.
	t.Run("no_cookie", func(t *testing.T) {
		sm, _ := newSM(store.User{ID: "u"})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := sm.AuthenticateRequest(r, "diyddns_session")
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("errors.Is(err, ErrUnauthorized) = false (err=%v)", err)
		}
		if got := ReasonOf(err); got != "no_cookie" {
			t.Fatalf("ReasonOf = %q, want no_cookie", got)
		}
	})
	seen["no_cookie"] = true

	// Counted outside the subtests on purpose: a Fatalf-ing subtest must not
	// also trip this guard and bury the real failure under a second one.
	if len(seen) != 9 {
		t.Fatalf("table covers %d distinct reasons, want 9", len(seen))
	}
}

// Design §11 item 8: "revoked" is not a reachable reason. Destroy deletes the
// row, so a logged-out session is indistinguishable from one that never
// existed and must report unknown_session.
func TestAuthenticate_NoRevokedReason(t *testing.T) {
	sm, _ := newSM(store.User{ID: "u"})
	sess, err := sm.Create(t.Context(), "u", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sm.Destroy(t.Context(), sess.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	_, _, err = sm.Authenticate(t.Context(), sess.ID)
	if got := ReasonOf(err); got == "revoked" {
		t.Fatal(`reason "revoked" is unreachable: Destroy deletes the row, so a logged-out session is indistinguishable from an unknown one`)
	}
	if got := ReasonOf(err); got != "unknown_session" {
		t.Fatalf("ReasonOf = %q, want unknown_session", got)
	}
}

func TestGenerateCSRFToken_Distinct(t *testing.T) {
	a, _ := GenerateCSRFToken()
	b, _ := GenerateCSRFToken()
	if a == "" || a == b {
		t.Fatal("csrf tokens must be non-empty and unique")
	}
}
