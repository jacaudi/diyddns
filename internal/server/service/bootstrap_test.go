package service

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// discardLogger returns a *slog.Logger that writes nowhere, for tests that
// don't assert on log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testBootstrapCfg(email, password string) config.BootstrapCfg {
	return config.BootstrapCfg{AdminEmail: email, AdminPassword: password}
}

func newTestBootstrapService(t *testing.T, st *store.Store, cfg config.BootstrapCfg, audit AuditSink, emitToken func(string)) *BootstrapService {
	t.Helper()
	return NewBootstrapService(st, cfg, testPasswordCfg(), discardLogger(), audit, emitToken)
}

func TestBootstrapService_Startup_EnvPath_CreatesAdmin(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapService(t, st, testBootstrapCfg("admin@example.com", "correct horse battery staple"), discardAudit{}, nil)

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	u, err := st.Users().GetByEmail(t.Context(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users.GetByEmail: %v", err)
	}
	if u.Role != "admin" {
		t.Fatalf("created user Role = %q, want admin", u.Role)
	}
	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("users after Startup = %d, want 1", len(users))
	}
}

func TestBootstrapService_Startup_EnvPath_SecondCallIsNoOp(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapService(t, st, testBootstrapCfg("admin@example.com", "correct horse battery staple"), discardAudit{}, nil)

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("second Startup: %v", err)
	}

	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("users after two Startup calls = %d, want 1 (second call must be a no-op)", len(users))
	}
}

func TestBootstrapService_Startup_TokenPath_SetsHashAndEmitsToken(t *testing.T) {
	st := openTestStore(t)
	var captured string
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, func(token string) { captured = token })

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	if captured == "" {
		t.Fatal("Startup (token path) did not emit a token via the injected sink")
	}
	bs, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}
	if bs.TokenHash == "" {
		t.Fatal("Bootstrap.Get: TokenHash is empty, want a hash set by Startup")
	}
	if bs.ConsumedAt != 0 {
		t.Fatalf("Bootstrap.Get: ConsumedAt = %d, want 0 (unconsumed)", bs.ConsumedAt)
	}

	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("users after token-path Startup = %d, want 0", len(users))
	}
}

func TestBootstrapService_Startup_TokenPath_PendingTokenNotReemitted(t *testing.T) {
	st := openTestStore(t)
	var calls int
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, func(string) { calls++ })

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	firstHash, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	secondHash, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}

	if calls != 1 {
		t.Fatalf("emitToken called %d times across two Startup calls, want 1 (pending token must not be reprinted)", calls)
	}
	if firstHash.TokenHash != secondHash.TokenHash {
		t.Fatal("second Startup replaced the pending token hash, want it left unchanged")
	}
}

func TestBootstrapService_Consume_HappyPath_CreatesAdminAndClearsToken(t *testing.T) {
	st := openTestStore(t)
	var token string
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), NewAuditWriter(st), func(tok string) { token = tok })
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	u, err := svc.Consume(t.Context(), token, "admin@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if u.Role != "admin" || u.Email != "admin@example.com" {
		t.Fatalf("Consume returned %+v, want Role=admin Email=admin@example.com", u)
	}

	bs, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}
	if bs.TokenHash != "" {
		t.Fatal("Bootstrap.Get: TokenHash not cleared after Consume")
	}
	if bs.ConsumedAt == 0 {
		t.Fatal("Bootstrap.Get: ConsumedAt = 0, want set after Consume")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "bootstrap.consumed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("bootstrap.consumed audit entries = %d, want 1", len(page.Rows))
	}
}

func TestBootstrapService_Consume_WrongToken_NoAdminCreated(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, nil)
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	if _, err := svc.Consume(t.Context(), "wrong-token", "admin@example.com", "correct horse battery staple"); !errors.Is(err, ErrBootstrapToken) {
		t.Fatalf("Consume (wrong token) error = %v, want ErrBootstrapToken", err)
	}

	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("users after wrong-token Consume = %d, want 0", len(users))
	}
}

func TestBootstrapService_Consume_AdminAlreadyExists_ReturnsClosed(t *testing.T) {
	st := openTestStore(t)
	seedUserWithPassword(t, st, "existing-admin@example.com", "admin", "some-password-1")
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, nil)

	if _, err := svc.Consume(t.Context(), "any-token", "new-admin@example.com", "correct horse battery staple"); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatalf("Consume (admin exists) error = %v, want ErrBootstrapClosed", err)
	}
}

func TestBootstrapService_Consume_AtomicGate_SecondConsumeFailsExactlyOneAdmin(t *testing.T) {
	st := openTestStore(t)
	var token string
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, func(tok string) { token = tok })
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	if _, err := svc.Consume(t.Context(), token, "admin@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	_, err := svc.Consume(t.Context(), token, "second-admin@example.com", "correct horse battery staple")
	if !errors.Is(err, ErrBootstrapClosed) && !errors.Is(err, ErrBootstrapToken) {
		t.Fatalf("second Consume error = %v, want ErrBootstrapClosed or ErrBootstrapToken", err)
	}

	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("users after two Consume calls with the same token = %d, want exactly 1", len(users))
	}
}

func TestBootstrapService_AdminExists(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapService(t, st, testBootstrapCfg("", ""), discardAudit{}, nil)

	ok, err := svc.AdminExists(t.Context())
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if ok {
		t.Fatal("AdminExists = true on empty store, want false")
	}

	seedUserWithPassword(t, st, "admin@example.com", "admin", "some-password-1")

	ok, err = svc.AdminExists(t.Context())
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if !ok {
		t.Fatal("AdminExists = false after creating an admin user, want true")
	}
}
