package service

import (
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// newTestSessionManager builds a SessionManager bound directly to st's
// session/user repos, mirroring how the real server wires it.
func newTestSessionManager(st *store.Store) *auth.SessionManager {
	return auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, 10*time.Minute)
}

func TestAuthService_Logout_DestroysSessionAndAudits(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	sessions := newTestSessionManager(st)
	svc := NewAuthService(sessions, NewAuditWriter(st))

	sess, err := sessions.Create(t.Context(), usr.ID, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}

	if err := svc.Logout(t.Context(), sess.ID); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, _, err := sessions.Authenticate(t.Context(), sess.ID); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("Authenticate after Logout = %v, want auth.ErrUnauthorized", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.logout"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.logout entries = %d, want 1", len(page.Rows))
	}
}

func TestAuthService_Logout_MissingSessionIsNotAnError(t *testing.T) {
	st := openTestStore(t)
	svc := NewAuthService(newTestSessionManager(st), discardAudit{})

	if err := svc.Logout(t.Context(), "no-such-session"); err != nil {
		t.Fatalf("Logout (missing session) = %v, want nil", err)
	}
}
