package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// AuthService handles browser-session lifecycle. Local password login and
// self-service password change were removed with the Plan 10 flip to
// passkeys + OIDC only; login is now a passkey (or OIDC) ceremony, so the
// only session operation left owned here is Logout.
type AuthService struct {
	sessions *auth.SessionManager
	audit    AuditSink
}

// NewAuthService constructs an AuthService.
func NewAuthService(sessions *auth.SessionManager, audit AuditSink) *AuthService {
	return &AuthService{sessions: sessions, audit: audit}
}

// Logout destroys sess. A missing session is not an error (see
// auth.SessionManager.Destroy). sess carries the actor and source IP so the
// audit row records who signed out and from where, matching both login paths.
func (s *AuthService) Logout(ctx context.Context, sess store.Session) error {
	if err := s.sessions.Destroy(ctx, sess.ID); err != nil {
		return fmt.Errorf("service.Logout: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: sess.UserID, EventType: "user.logout", IP: sess.IP})
	return nil
}
