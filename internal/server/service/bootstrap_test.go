package service

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/store"
)

// bootstrapAPIPath is the route that begins the first-admin claim ceremony.
// The operator-facing log messages must name it, so a first-run operator is
// not sent to a route that does not exist.
//
// Claiming is a WebAuthn registration ceremony, so this is deliberately
// asserted against the real registered path rather than a remembered one:
// the previous password-era endpoint (POST /api/v1/auth/bootstrap) no longer
// exists, and a stale constant here would let the log go on naming it while
// the test still passed.
const bootstrapAPIPath = "POST /api/v1/register/begin"

// discardLogger returns a *slog.Logger that writes nowhere, for tests that
// don't assert on log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestBootstrapService(t *testing.T, st *store.Store, audit AuditSink, emitToken func(string)) *BootstrapService {
	t.Helper()
	return NewBootstrapService(st, discardLogger(), audit, emitToken, nil, nil)
}

// newTestBootstrapServiceWithPasskeys builds a BootstrapService wired to a
// real PasskeyService (and a matching seal key) for tests that drive
// BeginClaim/FinishClaim.
func newTestBootstrapServiceWithPasskeys(t *testing.T, st *store.Store, audit AuditSink, emitToken func(string)) *BootstrapService {
	t.Helper()
	passkeys := newTestPasskeyService(t, st, audit)
	return NewBootstrapService(st, discardLogger(), audit, emitToken, passkeys, testKey32())
}

// driveClaim completes a full BeginClaim -> FinishClaim ceremony via
// virtualwebauthn, returning whatever FinishClaim returns.
func driveClaim(t *testing.T, svc *BootstrapService, token, email, name string, rp virtualwebauthn.RelyingParty) (store.User, error) {
	t.Helper()

	sealed, optsJSON, err := svc.BeginClaim(t.Context(), token, email)
	if err != nil {
		t.Fatalf("BeginClaim: %v", err)
	}

	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)

	return svc.FinishClaim(t.Context(), sealed, jsonRequest(attResp), name)
}

func TestBootstrapService_Startup_TokenPath_SetsHashAndEmitsToken(t *testing.T) {
	st := openTestStore(t)
	var captured string
	svc := newTestBootstrapService(t, st, discardAudit{}, func(token string) { captured = token })

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
	svc := newTestBootstrapService(t, st, discardAudit{}, func(string) { calls++ })

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

// TestBootstrapService_Startup_TokenPath_LogNamesBootstrapAPI pins the
// default emitToken sink's message. The `BOOTSTRAP_TOKEN=<token>` prefix is
// machine-greppable (scripts/smoke-test.sh scrapes it), and the instruction
// that follows must name the real endpoint — there is no /bootstrap route
// and no web UI served at that path.
func TestBootstrapService_Startup_TokenPath_LogNamesBootstrapAPI(t *testing.T) {
	st := openTestStore(t)
	var buf bytes.Buffer
	// nil emitToken => the default logToken sink, which is what operators see.
	svc := NewBootstrapService(st, slog.New(slog.NewTextHandler(&buf, nil)), discardAudit{}, nil, nil, nil)

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "BOOTSTRAP_TOKEN=") {
		t.Errorf("Startup log = %q, want it to contain the greppable %q prefix", got, "BOOTSTRAP_TOKEN=")
	}
	if !strings.Contains(got, bootstrapAPIPath) {
		t.Errorf("Startup log = %q, want it to name %q", got, bootstrapAPIPath)
	}
}

// TestBootstrapService_Startup_PendingTokenLogNamesBootstrapAPI covers the
// second message: on a restart with an unconsumed token the plaintext cannot
// be reprinted, so the reminder must still point at the real endpoint.
func TestBootstrapService_Startup_PendingTokenLogNamesBootstrapAPI(t *testing.T) {
	st := openTestStore(t)
	var buf bytes.Buffer
	svc := NewBootstrapService(st, slog.New(slog.NewTextHandler(&buf, nil)), discardAudit{}, nil, nil, nil)

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	buf.Reset() // isolate the second call's output from the minted-token line
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("second Startup: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "bootstrap pending") {
		t.Fatalf("second Startup log = %q, want the pending-token reminder", got)
	}
	if !strings.Contains(got, bootstrapAPIPath) {
		t.Errorf("second Startup log = %q, want it to name %q", got, bootstrapAPIPath)
	}
}
func TestStartup_BootstrapsWhenUsersExistButNoAdmin(t *testing.T) {
	st := openTestStore(t) // service package's helper: migrated :memory: store
	// Seed a non-admin user (simulating an OIDC signup) so len(users) > 0
	// but AdminExists == false.
	if _, err := st.Users().Create(t.Context(), store.User{
		Email: "oidc-user@example.com", Role: "user", OIDCProvider: "https://idp", OIDCSubject: "sub-1",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	var emitted string
	svc := NewBootstrapService(st, discardLogger(), NewAuditWriter(st), func(tok string) { emitted = tok }, nil, nil)

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if emitted == "" {
		t.Fatal("expected a bootstrap token to be emitted when users exist but no admin does; got none")
	}
}

func TestBootstrapService_AdminExists(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapService(t, st, discardAudit{}, nil)

	ok, err := svc.AdminExists(t.Context())
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if ok {
		t.Fatal("AdminExists = true on empty store, want false")
	}

	seedUser(t, st, "admin@example.com", "admin")

	ok, err = svc.AdminExists(t.Context())
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if !ok {
		t.Fatal("AdminExists = false after creating an admin user, want true")
	}
}

func TestBootstrapService_FinishClaim_CreatesAdminAndFirstPasskey(t *testing.T) {
	st := openTestStore(t)
	var token string
	svc := newTestBootstrapServiceWithPasskeys(t, st, NewAuditWriter(st), func(tok string) { token = tok })
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	rp := testRP()

	u, err := driveClaim(t, svc, token, "admin@example.com", "My Key", rp)
	if err != nil {
		t.Fatalf("driveClaim: %v", err)
	}
	if u.Role != "admin" || u.Email != "admin@example.com" {
		t.Fatalf("FinishClaim returned %+v, want Role=admin Email=admin@example.com", u)
	}
	if u.OIDCSubject != "" {
		t.Errorf("FinishClaim: OIDCSubject = %q, want empty (passkey-only admin)", u.OIDCSubject)
	}

	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials after FinishClaim = %d, want 1", len(creds))
	}

	bs, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}
	if bs.ConsumedAt == 0 {
		t.Error("Bootstrap.Get: ConsumedAt = 0, want set after FinishClaim")
	}

	for _, evt := range []string{"user.created", "bootstrap.consumed", "passkey.registered"} {
		page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: evt}, "", 10)
		if err != nil {
			t.Fatalf("ListPaginated(%s): %v", evt, err)
		}
		if len(page.Rows) != 1 {
			t.Errorf("%s entries = %d, want 1", evt, len(page.Rows))
		}
	}
}

func TestBootstrapService_AbandonedClaim_LeavesTokenReusable(t *testing.T) {
	st := openTestStore(t)
	var token string
	svc := newTestBootstrapServiceWithPasskeys(t, st, discardAudit{}, func(tok string) { token = tok })
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	// BeginClaim only — no FinishClaim. Simulates a user who never completed
	// (or abandoned) the WebAuthn ceremony.
	if _, _, err := svc.BeginClaim(t.Context(), token, "admin@example.com"); err != nil {
		t.Fatalf("BeginClaim: %v", err)
	}

	bs, err := st.Bootstrap().Get(t.Context())
	if err != nil {
		t.Fatalf("Bootstrap.Get: %v", err)
	}
	if bs.ConsumedAt != 0 {
		t.Fatalf("Bootstrap.Get: ConsumedAt = %d, want 0 (abandoned claim must not spend the token)", bs.ConsumedAt)
	}

	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("Users.List: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("users after abandoned claim = %d, want 0 (no orphan admin)", len(users))
	}

	// The token must still work end-to-end.
	rp := testRP()
	if _, err := driveClaim(t, svc, token, "admin@example.com", "My Key", rp); err != nil {
		t.Fatalf("driveClaim after abandoned BeginClaim: %v", err)
	}
}

func TestBootstrapService_BeginClaim_WrongTokenRejected(t *testing.T) {
	st := openTestStore(t)
	svc := newTestBootstrapServiceWithPasskeys(t, st, discardAudit{}, func(string) {})
	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	if _, _, err := svc.BeginClaim(t.Context(), "wrong-token", "admin@example.com"); !errors.Is(err, ErrBootstrapToken) {
		t.Fatalf("BeginClaim (wrong token): got %v, want ErrBootstrapToken", err)
	}
}

func TestBootstrapService_BeginClaim_AdminAlreadyExists_ReturnsClosed(t *testing.T) {
	st := openTestStore(t)
	seedUser(t, st, "existing-admin@example.com", "admin")
	svc := newTestBootstrapServiceWithPasskeys(t, st, discardAudit{}, func(string) {})

	if _, _, err := svc.BeginClaim(t.Context(), "any-token", "new-admin@example.com"); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatalf("BeginClaim (admin exists): got %v, want ErrBootstrapClosed", err)
	}
}
