package service

import (
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// testPasswordCfg returns cheap argon2id params (fast tests) with a
// realistic minimum length policy.
func testPasswordCfg() config.PasswordCfg {
	return config.PasswordCfg{Argon2Time: 1, Argon2MemoryKiB: 8 * 1024, Argon2Parallelism: 1, MinLength: 8}
}

// newTestSessionManager builds a SessionManager bound directly to st's
// session/user repos, mirroring how the real server wires it.
func newTestSessionManager(st *store.Store) *auth.SessionManager {
	return auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, 10*time.Minute)
}

func newTestAuthService(t *testing.T, st *store.Store, audit AuditSink) *AuthService {
	t.Helper()
	svc, err := NewAuthService(st, newTestSessionManager(st), testPasswordCfg(), audit)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	return svc
}

func TestAuthService_Login_ValidCredentials_ReturnsSessionThatAuthenticates(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	sessions := newTestSessionManager(st)
	svc, err := NewAuthService(st, sessions, testPasswordCfg(), discardAudit{})
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	sess, err := svc.Login(t.Context(), "a@b.co", "correct horse battery staple", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("Login returned a session with an empty ID")
	}

	gotUser, gotSess, err := sessions.Authenticate(t.Context(), sess.ID)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if gotUser.ID != usr.ID || gotSess.ID != sess.ID {
		t.Fatalf("Authenticate resolved user=%+v session=%+v, want user.ID=%q session.ID=%q", gotUser, gotSess, usr.ID, sess.ID)
	}
}

func TestAuthService_Login_ValidCredentials_AuditsLoginLocal(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	svc := newTestAuthService(t, st, NewAuditWriter(st))

	if _, err := svc.Login(t.Context(), "a@b.co", "correct horse battery staple", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.login.local"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.login.local entries = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].ActorUserID != usr.ID {
		t.Fatalf("ActorUserID = %q, want %q", page.Rows[0].ActorUserID, usr.ID)
	}
}

func TestAuthService_Login_WrongPassword_UniformErrorAndAudit(t *testing.T) {
	st := openTestStore(t)
	seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	svc := newTestAuthService(t, st, NewAuditWriter(st))

	_, err := svc.Login(t.Context(), "a@b.co", "wrong-password", "1.2.3.4", "ua")
	if !errors.Is(err, errInvalidCreds) {
		t.Fatalf("Login (wrong password) error = %v, want errInvalidCreds", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.login.failed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.login.failed entries = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].ActorUserID != "" {
		t.Fatalf("ActorUserID = %q, want empty (uniform failure shape)", page.Rows[0].ActorUserID)
	}
}

func TestAuthService_Login_UnknownEmail_SameUniformErrorAndAuditShape(t *testing.T) {
	st := openTestStore(t)
	svc := newTestAuthService(t, st, NewAuditWriter(st))

	_, err := svc.Login(t.Context(), "nobody@b.co", "whatever", "1.2.3.4", "ua")
	if !errors.Is(err, errInvalidCreds) {
		t.Fatalf("Login (unknown email) error = %v, want errInvalidCreds", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.login.failed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.login.failed entries = %d, want 1", len(page.Rows))
	}
	// Identical shape to the wrong-password failure: no ActorUserID, so a
	// reader of the audit log cannot tell "no such user" from "wrong password".
	if page.Rows[0].ActorUserID != "" {
		t.Fatalf("ActorUserID = %q, want empty (identical shape to a wrong-password failure)", page.Rows[0].ActorUserID)
	}
}

func TestAuthService_Login_DisabledUser_UniformError(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	if err := st.Users().SetDisabled(t.Context(), usr.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	svc := newTestAuthService(t, st, discardAudit{})

	if _, err := svc.Login(t.Context(), "a@b.co", "correct horse battery staple", "1.2.3.4", "ua"); !errors.Is(err, errInvalidCreds) {
		t.Fatalf("Login (disabled user) error = %v, want errInvalidCreds", err)
	}
}

func TestAuthService_Login_OIDCOnlyUser_UniformError(t *testing.T) {
	st := openTestStore(t)
	seedUser(t, st, "a@b.co", "user") // no password hash => OIDC-only
	svc := newTestAuthService(t, st, discardAudit{})

	if _, err := svc.Login(t.Context(), "a@b.co", "whatever", "1.2.3.4", "ua"); !errors.Is(err, errInvalidCreds) {
		t.Fatalf("Login (OIDC-only user) error = %v, want errInvalidCreds", err)
	}
}

func TestAuthService_Logout_DestroysSessionAndAudits(t *testing.T) {
	st := openTestStore(t)
	seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	sessions := newTestSessionManager(st)
	svc, err := NewAuthService(st, sessions, testPasswordCfg(), NewAuditWriter(st))
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	sess, err := svc.Login(t.Context(), "a@b.co", "correct horse battery staple", "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("Login: %v", err)
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
	svc := newTestAuthService(t, st, discardAudit{})

	if err := svc.Logout(t.Context(), "no-such-session"); err != nil {
		t.Fatalf("Logout (missing session) = %v, want nil", err)
	}
}

func TestAuthService_ChangePassword_WrongOldPassword_Errors(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "old-password-1")
	svc := newTestAuthService(t, st, discardAudit{})

	if err := svc.ChangePassword(t.Context(), usr.ID, "wrong-old-password", "new-password-1"); err == nil {
		t.Fatal("ChangePassword: expected error for wrong old password")
	}
}

func TestAuthService_ChangePassword_TooShortNewPassword_Errors(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "old-password-1")
	svc := newTestAuthService(t, st, discardAudit{})

	if err := svc.ChangePassword(t.Context(), usr.ID, "old-password-1", "short"); err == nil {
		t.Fatal("ChangePassword: expected error for too-short new password")
	}
}

func TestAuthService_ChangePassword_Success_NewHashVerifiesAndAudits(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "old-password-1")
	svc := newTestAuthService(t, st, NewAuditWriter(st))

	if err := svc.ChangePassword(t.Context(), usr.ID, "old-password-1", "new-password-1"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	updated, err := st.Users().GetByID(t.Context(), usr.ID)
	if err != nil {
		t.Fatalf("Users.GetByID: %v", err)
	}
	ok, err := auth.VerifyPassword(updated.PasswordHash, "new-password-1")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("ChangePassword: new password does not verify against the stored hash")
	}
	if updated.Email != usr.Email || updated.Role != usr.Role {
		t.Fatalf("ChangePassword must preserve other fields: got %+v, want Email=%q Role=%q", updated, usr.Email, usr.Role)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.password_change"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.password_change entries = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].ActorUserID != usr.ID {
		t.Fatalf("ActorUserID = %q, want %q", page.Rows[0].ActorUserID, usr.ID)
	}
}
