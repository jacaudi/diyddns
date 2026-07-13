package auth

import (
	"context"
	"errors"
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

func TestGenerateCSRFToken_Distinct(t *testing.T) {
	a, _ := GenerateCSRFToken()
	b, _ := GenerateCSRFToken()
	if a == "" || a == b {
		t.Fatal("csrf tokens must be non-empty and unique")
	}
}
