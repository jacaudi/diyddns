package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// testRP returns the RelyingParty description shared by every ceremony a
// test drives; it must match the rpID/rpOrigin passed to
// newTestPasskeyService.
func testRP() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test", Origin: "http://localhost:8080"}
}

// newTestPasskeyService builds a PasskeyService bound to st, using a fixed
// AEAD seal key and RP identity consistent across all tests in this file.
func newTestPasskeyService(t *testing.T, st *store.Store, audit AuditSink) *PasskeyService {
	t.Helper()
	cfg := config.WebAuthnCfg{RPDisplayName: "Test", Timeout: 2 * time.Minute}
	svc, err := NewPasskeyService(st, newTestSessionManager(st), testKey32(), cfg, "localhost", "http://localhost:8080", audit, discardLogger())
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	return svc
}

// jsonRequest wraps body in an *http.Request the way huma's humago.Unwrap
// would hand one to the service: a POST with a JSON content type.
func jsonRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// registerPasskey drives a full BeginRegister -> FinishRegister ceremony for
// userID via virtualwebauthn, returning the persisted credential row plus
// the virtual authenticator/credential pair a later login can replay against.
// The authenticator's UserHandle is taken from the server's register-begin
// options (attOpts.UserID) exactly as a real platform authenticator would
// receive and bake it in — not invented by the test.
func registerPasskey(t *testing.T, svc *PasskeyService, userID, name string, rp virtualwebauthn.RelyingParty) (store.WebAuthnCredential, virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	t.Helper()

	optsJSON, sealed, err := svc.BeginRegister(t.Context(), userID)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if len(optsJSON) == 0 {
		t.Fatal("BeginRegister: empty options")
	}
	if sealed == "" {
		t.Fatal("BeginRegister: empty sealed cookie")
	}

	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}

	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)

	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)

	stored, err := svc.FinishRegister(t.Context(), userID, sealed, name, jsonRequest(attResp))
	if err != nil {
		t.Fatalf("FinishRegister: %v", err)
	}
	return stored, authr, cred
}

// loginPasskey drives a full BeginLogin -> FinishLogin discoverable-login
// ceremony against authr/cred (as returned by registerPasskey), returning
// whatever FinishLogin returns so callers can assert on success or failure.
func loginPasskey(t *testing.T, svc *PasskeyService, rp virtualwebauthn.RelyingParty, authr virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, ip, ua string) (store.Session, error) {
	t.Helper()

	optsJSON, sealed, err := svc.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertResp := virtualwebauthn.CreateAssertionResponse(rp, authr, cred, *assertOpts)

	return svc.FinishLogin(t.Context(), sealed, jsonRequest(assertResp), ip, ua)
}

func TestPasskeyService_BeginRegister_ReturnsOptionsAndSealedCookie(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, discardAudit{})
	u := seedUser(t, st, "alice@example.com", "user")

	opts, sealed, err := svc.BeginRegister(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if len(opts) == 0 {
		t.Error("BeginRegister: expected non-empty options JSON")
	}
	if sealed == "" {
		t.Error("BeginRegister: expected non-empty sealed cookie")
	}
}

// TestPasskeyService_BeginRegister_ExcludesExistingCredentials verifies that
// a second registration ceremony for a user who already has a passkey
// advertises it in excludeCredentials, so a browser can proactively refuse
// letting the user re-register the same physical authenticator (rather than
// silently relying on the credential_id PRIMARY KEY to reject the duplicate
// only after the whole ceremony completes).
func TestPasskeyService_BeginRegister_ExcludesExistingCredentials(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, discardAudit{})
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	stored, _, _ := registerPasskey(t, svc, u.ID, "First Key", rp)

	optsJSON, _, err := svc.BeginRegister(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}

	wantID := base64.RawURLEncoding.EncodeToString(stored.CredentialID)
	if !slices.Contains(attOpts.ExcludeCredentials, wantID) {
		t.Errorf("BeginRegister: excludeCredentials = %v, want to contain %q", attOpts.ExcludeCredentials, wantID)
	}
}

func TestPasskeyService_FinishRegister_StoresCredentialAndMintsHandle(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	stored, _, _ := registerPasskey(t, svc, u.ID, "My Key", rp)

	if len(stored.CredentialID) == 0 {
		t.Error("FinishRegister: expected non-empty CredentialID")
	}
	if stored.UserID != u.ID {
		t.Errorf("FinishRegister: UserID = %q, want %q", stored.UserID, u.ID)
	}
	if stored.Name != "My Key" {
		t.Errorf("FinishRegister: Name = %q, want %q", stored.Name, "My Key")
	}

	handle, err := st.Users().GetWebAuthnHandle(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetWebAuthnHandle: %v", err)
	}
	if len(handle) == 0 {
		t.Error("FinishRegister: expected webauthn_handle to be minted")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.registered"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("passkey.registered entries = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].ActorUserID != u.ID {
		t.Errorf("passkey.registered ActorUserID = %q, want %q", page.Rows[0].ActorUserID, u.ID)
	}
}

func TestPasskeyService_SecondRegistration_ReusesHandle_BothCredentialsLogin(t *testing.T) {
	// Regression coverage for the store.UserRepo.GetWebAuthnHandle fix this
	// task adds: every credential a user registers must share the one
	// webauthn_handle baked into their authenticators, or discoverable login
	// breaks for whichever credential's handle isn't the one currently on
	// the user's row (see GetWebAuthnHandle's doc comment).
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, discardAudit{})
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	_, authr1, cred1 := registerPasskey(t, svc, u.ID, "Key 1", rp)
	_, authr2, cred2 := registerPasskey(t, svc, u.ID, "Key 2", rp)

	if _, err := loginPasskey(t, svc, rp, authr1, cred1, "1.2.3.4", "ua"); err != nil {
		t.Errorf("login via first credential: %v", err)
	}
	if _, err := loginPasskey(t, svc, rp, authr2, cred2, "1.2.3.4", "ua"); err != nil {
		t.Errorf("login via second credential: %v", err)
	}
}

func TestPasskeyService_FinishLogin_ReturnsSessionAndBumpsLastUsed(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	stored, authr, cred := registerPasskey(t, svc, u.ID, "My Key", rp)
	if stored.LastUsedAt != 0 {
		t.Fatalf("precondition: LastUsedAt = %d, want 0", stored.LastUsedAt)
	}

	sess, err := loginPasskey(t, svc, rp, authr, cred, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("FinishLogin: expected non-empty session ID")
	}
	if sess.UserID != u.ID {
		t.Errorf("FinishLogin: session UserID = %q, want %q", sess.UserID, u.ID)
	}

	got, err := st.WebAuthnCredentials().GetByID(t.Context(), stored.CredentialID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastUsedAt == 0 {
		t.Error("FinishLogin: expected LastUsedAt to be bumped")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.login.passkey"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("user.login.passkey entries = %d, want 1", len(page.Rows))
	}
}

func TestPasskeyService_FinishLogin_ReplayedFinishRejected(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, discardAudit{})
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	_, authr, cred := registerPasskey(t, svc, u.ID, "My Key", rp)

	optsJSON, sealed, err := svc.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertResp := virtualwebauthn.CreateAssertionResponse(rp, authr, cred, *assertOpts)

	if _, err := svc.FinishLogin(t.Context(), sealed, jsonRequest(assertResp), "1.2.3.4", "ua"); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}

	_, err = svc.FinishLogin(t.Context(), sealed, jsonRequest(assertResp), "1.2.3.4", "ua")
	if !errors.Is(err, ErrPasskeyVerification) {
		t.Fatalf("replayed FinishLogin: got %v, want ErrPasskeyVerification", err)
	}
}

func TestPasskeyService_FinishLogin_CloneWarningRejectsAndAudits(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	stored, authr, cred := registerPasskey(t, svc, u.ID, "My Key", rp)

	// Rewind: rewrite the persisted credential's sign count to a value
	// higher than what the (unmodified) virtual authenticator is about to
	// present (its Counter field never advanced past its zero-value
	// default), simulating a cloned authenticator whose next assertion
	// looks non-increasing relative to the stored high-water mark.
	got, err := st.WebAuthnCredentials().GetByID(t.Context(), stored.CredentialID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	var wc webauthn.Credential
	if err := json.Unmarshal(got.CredentialJSON, &wc); err != nil {
		t.Fatalf("unmarshal stored credential: %v", err)
	}
	wc.Authenticator.SignCount = 999
	rewound, err := json.Marshal(&wc)
	if err != nil {
		t.Fatalf("marshal rewound credential: %v", err)
	}
	got.CredentialJSON = rewound
	if err := st.WebAuthnCredentials().Update(t.Context(), got); err != nil {
		t.Fatalf("Update (rewind): %v", err)
	}

	sess, err := loginPasskey(t, svc, rp, authr, cred, "1.2.3.4", "ua")
	if !errors.Is(err, ErrPasskeyVerification) {
		t.Fatalf("FinishLogin (clone warning): got err=%v, want ErrPasskeyVerification", err)
	}
	if sess.ID != "" {
		t.Errorf("FinishLogin (clone warning): expected no session minted, got %+v", sess)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.signcount_anomaly"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("passkey.signcount_anomaly entries = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].ActorUserID != u.ID {
		t.Errorf("passkey.signcount_anomaly ActorUserID = %q, want %q", page.Rows[0].ActorUserID, u.ID)
	}

	// No session.login.passkey audit entry should have been recorded either.
	loginPage, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.login.passkey"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(loginPage.Rows) != 0 {
		t.Errorf("user.login.passkey entries = %d, want 0", len(loginPage.Rows))
	}
}

func TestPasskeyService_FinishLogin_DisabledUserRejected(t *testing.T) {
	st := openTestStore(t)
	svc := newTestPasskeyService(t, st, discardAudit{})
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	_, authr, cred := registerPasskey(t, svc, u.ID, "My Key", rp)

	if err := st.Users().SetDisabled(t.Context(), u.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	_, err := loginPasskey(t, svc, rp, authr, cred, "1.2.3.4", "ua")
	if !errors.Is(err, ErrPasskeyVerification) {
		t.Fatalf("FinishLogin (disabled user): got %v, want ErrPasskeyVerification", err)
	}
}

func TestPasskeyService_Remove_LastCredentialGuard(t *testing.T) {
	tests := []struct {
		name         string
		oidcProvider string
		oidcSubject  string
		wantErr      error // nil means the removal must succeed
	}{
		{name: "no OIDC link: guard blocks removing the last credential", wantErr: ErrLastCredential},
		{name: "OIDC-linked: last credential may be removed", oidcProvider: "test-provider", oidcSubject: "sub-123", wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openTestStore(t)
			svc := newTestPasskeyService(t, st, NewAuditWriter(st))
			u, err := st.Users().Create(t.Context(), store.User{
				Email: "alice@example.com", Role: "user",
				OIDCProvider: tt.oidcProvider,
				OIDCSubject:  tt.oidcSubject,
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			rp := testRP()
			stored, _, _ := registerPasskey(t, svc, u.ID, "Only Key", rp)

			err = svc.Remove(t.Context(), u.ID, stored.CredentialID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Remove: got %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Remove: %v", err)
			}
			if _, err := st.WebAuthnCredentials().GetByID(t.Context(), stored.CredentialID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetByID after Remove: got %v, want ErrNotFound", err)
			}
		})
	}
}

// TestVerifyRegistration_LogsTheCauseButDoesNotReturnIt pins both halves of the
// #78 fix: the returned error stays the uniform ErrPasskeyVerification (a
// security property — callers must not learn which check failed), while the
// underlying go-webauthn cause is written to the server log, so the next person
// diagnosing a 401 does not have to patch the binary.
func TestVerifyRegistration_LogsTheCauseButDoesNotReturnIt(t *testing.T) {
	st := openTestStore(t)
	var buf lockedBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := config.WebAuthnCfg{RPDisplayName: "DIYDDNS"}
	svc, err := NewPasskeyService(st, newTestSessionManager(st), testKey32(), cfg,
		"localhost", "http://localhost:8080", discardAudit{}, log)
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}

	// An empty JSON body cannot parse as an attestation response, so
	// FinishRegistration fails with a real, specific go-webauthn error.
	// jsonRequest is this file's own existing helper (passkey_test.go:42).
	r := jsonRequest("{}")
	_, err = svc.verifyRegistration("user@example.test", []byte("handle"), webauthn.SessionData{}, r)

	if !errors.Is(err, ErrPasskeyVerification) {
		t.Fatalf("err = %v, want ErrPasskeyVerification", err)
	}
	// The sentinel must be returned BARE. errors.Is unwraps, so it alone
	// cannot see a cause that has been %w-wrapped into the returned error --
	// which is precisely the leak this test exists to prevent. Compare
	// identity as well.
	if err != ErrPasskeyVerification { //nolint:errorlint // intentional: proving err is NOT wrapped, so errors.Is would defeat the point
		t.Errorf("err must be the bare sentinel, not wrapped: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "passkey registration verification failed") {
		t.Errorf("log does not record the cause; got:\n%s", got)
	}
	// The message alone proves nothing: a handler that logs the message with
	// no error attribute at all would satisfy the Contains check above and
	// still leak zero diagnostic information. Pin the cause itself -- the
	// go-webauthn error text attached as the "error" attribute -- so a
	// mutant that drops slog.String("error", ...) while keeping the message
	// is caught here.
	if !strings.Contains(got, `error="Parse error for Registration"`) {
		t.Errorf("log does not record the cause as an error attribute; got:\n%s", got)
	}
}

// lockedBuffer is a bytes.Buffer safe for a slog handler to write while the
// test reads it. slog handlers may be called from other goroutines, and the
// race detector flags an unsynchronised bytes.Buffer.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
