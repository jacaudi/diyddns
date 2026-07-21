package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// SessionStore is the narrow session-persistence surface SessionManager depends on.
type SessionStore interface {
	Create(ctx context.Context, s store.Session) (store.Session, error)
	GetByID(ctx context.Context, id string) (store.Session, error)
	Touch(ctx context.Context, id string, expiresAt int64) error
	Delete(ctx context.Context, id string) error
}

// SessionManager is the DB-backed cookie-session store for the browser API.
// It mints and validates sessions, sliding their expiry on active use.
type SessionManager struct {
	sessions SessionStore
	users    UserReader
	ttl      time.Duration
	slide    time.Duration
	now      func() int64 // injectable for tests; defaults to time.Now().Unix
}

// NewSessionManager constructs a SessionManager. ttl is how long a freshly
// minted or slid session stays valid; slide is the minimum idle time before
// Authenticate extends a session's expiry on use.
func NewSessionManager(s SessionStore, u UserReader, ttl, slide time.Duration) *SessionManager {
	return &SessionManager{sessions: s, users: u, ttl: ttl, slide: slide, now: func() int64 { return time.Now().Unix() }}
}

// RandToken returns an n-byte URL-safe random token. Exported so the service
// package can mint enrollment codes and the bootstrap token from one source.
func RandToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("auth.RandToken: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateCSRFToken returns a random URL-safe token.
func GenerateCSRFToken() (string, error) {
	t, err := RandToken(32)
	if err != nil {
		return "", fmt.Errorf("auth.GenerateCSRFToken: %w", err)
	}
	return t, nil
}

// Create mints a new session (opaque id + rotated CSRF token) for userID.
func (m *SessionManager) Create(ctx context.Context, userID, ip, ua string) (store.Session, error) {
	id, err := RandToken(32)
	if err != nil {
		return store.Session{}, fmt.Errorf("auth.Session.Create: id: %w", err)
	}
	csrf, err := GenerateCSRFToken()
	if err != nil {
		return store.Session{}, err
	}
	now := m.now()
	return m.sessions.Create(ctx, store.Session{
		ID: id, UserID: userID, CSRFToken: csrf, IP: ip, UserAgent: ua,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now + int64(m.ttl.Seconds()),
	})
}

// Authenticate validates a session id, slides its expiry, and returns the user.
func (m *SessionManager) Authenticate(ctx context.Context, sessionID string) (store.User, store.Session, error) {
	sess, err := m.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	now := m.now()
	if sess.ExpiresAt <= now {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	usr, err := m.users.GetByID(ctx, sess.UserID)
	if err != nil || usr.Disabled {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	// Slide: if last seen more than `slide` ago, extend expiry.
	if now-sess.LastSeenAt >= int64(m.slide.Seconds()) {
		newExp := now + int64(m.ttl.Seconds())
		if err := m.sessions.Touch(ctx, sess.ID, newExp); err == nil {
			sess.ExpiresAt = newExp
		}
	}
	return usr, sess, nil
}

// AuthenticateRequest is the single, framework-agnostic home for "authenticate
// a browser request by its session cookie": it reads cookieName off r and
// validates it via Authenticate. A missing or empty cookie fails closed with
// ErrUnauthorized, same as an unknown or expired one. Both the huma session
// middleware (internal/server/api) and the stdlib webui middleware
// (internal/server/webui) call this instead of duplicating the cookie-read.
func (m *SessionManager) AuthenticateRequest(r *http.Request, cookieName string) (store.User, store.Session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	return m.Authenticate(r.Context(), c.Value)
}

// Destroy removes a session (logout). A missing session is not an error.
func (m *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	if err := m.sessions.Delete(ctx, sessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("auth.Session.Destroy: %w", err)
	}
	return nil
}
