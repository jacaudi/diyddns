package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// buildServerDeps assembles every ServerDeps field common to the full-server
// harness (agent HMAC surface, browser auth surface, device management) onto
// a fresh :memory: store, WITHOUT registering it onto a mux. It is the single
// place that "how the full server's non-OIDC deps are wired" lives, so both
// newFullHarness and newOIDCHarness build from the same deps rather than each
// hand-duplicating the ~10-field ServerDeps literal.
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
	checkinSvc := service.NewCheckinService(st, discardAgentAudit{})
	devicesSvc := service.NewDeviceService(st, key, verifier, discardAgentAudit{})

	cfg := config.Auth{
		Session: config.SessionCfg{
			CookieName:   authTestCookieName,
			CookieSecure: false,
			TTL:          time.Hour,
			SlideWindow:  time.Minute,
		},
		Password: cheapPasswordCfg(),
	}
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Session.TTL, cfg.Session.SlideWindow)
	authSvc, err := service.NewAuthService(st, sessions, cfg.Password, discardAgentAudit{})
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bootstrapSvc := service.NewBootstrapService(st, cfg.Bootstrap, cfg.Password, log, discardAgentAudit{}, nil)

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
		Cfg:       cfg,
		Info:      version.Info{Version: "v1.2.3"},
		HMACKey:   key,
	}
}

// newFullHarness assembles the full server: agent HMAC surface (enroll,
// checkin, self), browser auth surface (login, logout, me, password,
// bootstrap), and the device management surface under test here. OIDC is
// left unset (disabled) — see newOIDCHarness for the OIDC-enabled variant.
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

// loginAndGetCSRF logs email/password in via the real HTTP endpoint and
// returns the session cookie plus the CSRF token from /api/v1/auth/me, so
// device-op tests exercise the same cookie+CSRF path a browser would.
func loginAndGetCSRF(t *testing.T, h fullHarness, email, password string) (*http.Cookie, string) {
	t.Helper()
	_, loginHeader, loginBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, nil, "")
	cookie := findCookie(loginHeader, authTestCookieName)
	if cookie == nil {
		t.Fatalf("no session cookie from login, body=%s", loginBody)
	}

	_, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	var me struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	return cookie, me.CSRF
}

func TestMintCode_LoggedInWithCSRFReturnsWorkingCode(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "mint@example.com", "correct horse battery staple")
	cookie, csrf := loginAndGetCSRF(t, h, "mint@example.com", "correct horse battery staple")

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
	seedAuthUserWithPassword(t, h.st, "mint2@example.com", "correct horse battery staple")
	cookie, _ := loginAndGetCSRF(t, h, "mint2@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices", map[string]string{
		"label": "laptop",
	}, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
}

func TestListDevices_ReturnsOnlyCallersDevices(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "lista@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "listb@example.com", "correct horse battery staple")

	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "a-laptop"}); err != nil {
		t.Fatalf("seed device A: %v", err)
	}
	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-laptop"}); err != nil {
		t.Fatalf("seed device B: %v", err)
	}

	cookie, _ := loginAndGetCSRF(t, h, "lista@example.com", "correct horse battery staple")
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
	seedAuthUserWithPassword(t, h.st, "geta@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "getb@example.com", "correct horse battery staple")

	devB, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-laptop"})
	if err != nil {
		t.Fatalf("seed device B: %v", err)
	}

	cookie, _ := loginAndGetCSRF(t, h, "geta@example.com", "correct horse battery staple")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+devB.ID, nil, cookie, "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

func TestGetDevice_OwnDeviceReturns200(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "getown@example.com", "correct horse battery staple")

	devA, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "own-laptop"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	cookie, _ := loginAndGetCSRF(t, h, "getown@example.com", "correct horse battery staple")
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
