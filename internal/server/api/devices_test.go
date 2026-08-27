package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// fullHarness wires every ServerDeps field through api.Build onto a fresh
// mux backed by a real :memory: store — the single source of "how the full
// server is assembled" that both this file's device-op tests and
// guard_test.go's behavioral fail-open test share. If ServerDeps grows a
// field, this is the one place that needs updating for both test files.
type fullHarness struct {
	srv *httptest.Server
	st  *store.Store
}

// apiTestRP is the WebAuthn Relying Party identity every passkey ceremony
// test in this package drives against — must match cfg.WebAuthn below.
func apiTestRP() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{ID: "localhost", Name: "Test", Origin: "http://localhost:8080"}
}

// fakeMailer is a real-enough Mailer double for buildServerDeps: Enabled
// reports true (so GrantService.RequestSelfServiceRecovery's mailer-enabled
// gate doesn't short-circuit before this file's tests can observe the
// account-exists/has-a-passkey checks that follow it) and Send always
// succeeds without touching the network. mirrors discardAgentAudit's
// no-op-double style (agent_test.go).
type fakeMailer struct{}

func (fakeMailer) Send(context.Context, string, string, string) error { return nil }
func (fakeMailer) Enabled() bool                                      { return true }

// buildServerDeps assembles every ServerDeps field common to the full-server
// harness (agent HMAC surface, browser auth surface, device management,
// passkey ceremonies) onto a fresh :memory: store, WITHOUT registering it
// onto a mux. It is the single place that "how the full server's non-OIDC
// deps are wired" lives, so both newFullHarness and newOIDCHarness build from
// the same deps rather than each hand-duplicating the ~10-field ServerDeps
// literal.
func buildServerDeps(t *testing.T) (*store.Store, api.ServerDeps) {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, 120*time.Second, 120*time.Second)
	enroll := service.NewEnrollmentService(st, key, 15*time.Minute, discardAgentAudit{})
	checkinSvc := service.NewCheckinService(st, service.NopNotifier{})
	devicesSvc := service.NewDeviceService(st, key, verifier, discardAgentAudit{})

	cfg := config.Auth{
		Session: config.SessionCfg{
			CookieName:   authTestCookieName,
			CookieSecure: false,
			TTL:          time.Hour,
			SlideWindow:  time.Minute,
		},
		WebAuthn: config.WebAuthnCfg{
			RPID: "localhost", RPOrigin: "http://localhost:8080", RPDisplayName: "Test", Timeout: 2 * time.Minute,
		},
	}
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Session.TTL, cfg.Session.SlideWindow)
	authSvc := service.NewAuthService(sessions, discardAgentAudit{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// One 32-byte master key seals both the agent HMAC envelope (via
	// verifier) and every AEAD-sealed browser cookie (session challenge,
	// bootstrap claim) below — mirrors production's single
	// cfg.Auth.HMAC.SecretKey reused across auth.SealWithAAD call sites
	// (e.g. oidc.go's flow cookie), domain-separated by AAD, not by key.
	passkeySvc, err := service.NewPasskeyService(st, sessions, key, cfg.WebAuthn, cfg.WebAuthn.RPID, cfg.WebAuthn.RPOrigin, discardAgentAudit{}, log)
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	mailer := fakeMailer{}
	grantsSvc := service.NewGrantService(st, passkeySvc, mailer, "http://localhost", discardAgentAudit{}, log)
	bootstrapSvc := service.NewBootstrapService(st, log, discardAgentAudit{}, nil, passkeySvc, key)
	adminSvc := service.NewAdminService(st, discardAgentAudit{}, grantsSvc)

	return st, api.ServerDeps{
		Log:       log,
		Store:     st,
		Verifier:  verifier,
		Sessions:  sessions,
		Enroll:    enroll,
		Devices:   devicesSvc,
		Checkin:   checkinSvc,
		Auth:      authSvc,
		Bootstrap: bootstrapSvc,
		Admin:     adminSvc,
		Passkey:   passkeySvc,
		Grants:    grantsSvc,
		Mailer:    mailer,
		Cfg:       cfg,
		Info:      version.Info{Version: "v1.2.3"},
		HMACKey:   key,
	}
}

// newFullHarness assembles the full server: agent HMAC surface (enroll,
// checkin, self), browser auth surface (logout, me, passkey + OIDC login,
// passkey bootstrap claim), and the device management surface under test
// here. OIDC is left unset (disabled) — see newOIDCHarness for the
// OIDC-enabled variant.
func newFullHarness(t *testing.T) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)

	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return fullHarness{srv: srv, st: st}
}

// newOIDCHarness builds on buildServerDeps, additionally wiring an OIDC
// Manager (discovered against cfgOIDC.Issuer) and OIDCService into
// ServerDeps. The httptest.Server's URL is only known once the server is
// started, so it starts the server FIRST (its mux gets the OIDC routes added
// immediately after, before any request is made) and only then constructs the
// Manager with that URL as its redirect base — otherwise the Manager's
// baked-in oauth2 RedirectURL could never match the server it's registered
// against, and the mock IdP's /authorize would redirect the test client
// nowhere reachable.
func newOIDCHarness(t *testing.T, cfgOIDC config.OIDCCfg) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mgr := oidc.NewManager(cfgOIDC, srv.URL, deps.Log)
	if err := mgr.Discover(t.Context()); err != nil {
		t.Fatalf("oidc manager discover: %v", err)
	}

	deps.Cfg.OIDC = cfgOIDC
	deps.OIDCMgr = mgr
	deps.OIDC = service.NewOIDCService(st, deps.Sessions, cfgOIDC, service.NewAuditWriter(st), deps.Log)

	api.Build(mux, deps)

	return fullHarness{srv: srv, st: st}
}

// seedUser creates a credential-less user (no password, no passkey) — the
// password-free replacement for the old seedAuthUserWithPassword now that
// local password auth is gone. role is "user" or "admin".
func seedUser(t *testing.T, st *store.Store, email, role string) store.User {
	t.Helper()
	u, err := st.Users().Create(context.Background(), store.User{Email: email, Role: role})
	if err != nil {
		t.Fatalf("seed user %q: %v", email, err)
	}
	return u
}

// sessionFor mints a real DB-backed browser session for the already-seeded
// user with email and returns the session cookie plus its CSRF token — the
// password-free replacement for loginAndGetCSRF. Login is now a passkey
// ceremony, so session-guarded tests seed the session directly via
// SessionManager rather than POSTing credentials; the resulting cookie
// authenticates through sessionMiddleware exactly as a browser's would.
func sessionFor(t *testing.T, h fullHarness, email string) (*http.Cookie, string) {
	t.Helper()
	u, err := h.st.Users().GetByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("sessionFor lookup %q: %v", email, err)
	}
	sm := auth.NewSessionManager(h.st.Sessions(), h.st.Users(), time.Hour, time.Minute)
	sess, err := sm.Create(context.Background(), u.ID, "", "")
	if err != nil {
		t.Fatalf("sessionFor create for %q: %v", email, err)
	}
	return &http.Cookie{Name: authTestCookieName, Value: sess.ID}, sess.CSRFToken
}

func TestMintCode_LoggedInWithCSRFReturnsWorkingCode(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "mint@example.com", "user")
	cookie, csrf := sessionFor(t, h, "mint@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices", map[string]string{
		"label": "laptop",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, body)
	}
	if got.Code == "" {
		t.Fatal("empty code")
	}
	if got.ExpiresAt <= 0 {
		t.Fatalf("ExpiresAt = %d, want > 0", got.ExpiresAt)
	}

	// The minted code must actually work against the real enroll endpoint.
	enrollStatus, enrollBody := postJSON(t, h.srv.URL+"/agent/v1/enroll/code", map[string]string{"code": got.Code})
	if enrollStatus != http.StatusOK {
		t.Fatalf("enroll with minted code: status = %d, want 200, body=%s", enrollStatus, enrollBody)
	}
}

func TestMintCode_WithoutCSRFReturns403(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "mint2@example.com", "user")
	cookie, _ := sessionFor(t, h, "mint2@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices", map[string]string{
		"label": "laptop",
	}, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
}

func TestListDevices_ReturnsOnlyCallersDevices(t *testing.T) {
	h := newFullHarness(t)
	userA := seedUser(t, h.st, "lista@example.com", "user")
	userB := seedUser(t, h.st, "listb@example.com", "user")

	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "a-laptop"}); err != nil {
		t.Fatalf("seed device A: %v", err)
	}
	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-laptop"}); err != nil {
		t.Fatalf("seed device B: %v", err)
	}

	cookie, _ := sessionFor(t, h, "lista@example.com")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode list response: %v, body=%s", err, body)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1 (only caller's own): %+v", len(got), got)
	}
	if got[0].Label != "a-laptop" {
		t.Fatalf("device label = %q, want a-laptop", got[0].Label)
	}
}

func TestGetDevice_AnotherUsersDeviceReturns404(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "geta@example.com", "user")
	userB := seedUser(t, h.st, "getb@example.com", "user")

	devB, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-laptop"})
	if err != nil {
		t.Fatalf("seed device B: %v", err)
	}

	cookie, _ := sessionFor(t, h, "geta@example.com")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+devB.ID, nil, cookie, "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

func TestGetDevice_OwnDeviceReturns200(t *testing.T) {
	h := newFullHarness(t)
	userA := seedUser(t, h.st, "getown@example.com", "user")

	devA, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "own-laptop"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	cookie, _ := sessionFor(t, h, "getown@example.com")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+devA.ID, nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode get response: %v, body=%s", err, body)
	}
	if got.ID != devA.ID || got.Label != "own-laptop" {
		t.Fatalf("got = %+v, want id=%q label=own-laptop", got, devA.ID)
	}
}
