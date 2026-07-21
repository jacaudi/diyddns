package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// webauthnChallengeCookieName mirrors passkey.go's cookie-name constant, kept
// as a local literal so this file doesn't depend on an unexported symbol
// across the test/production package boundary (api_test is a separate
// package from api).
const webauthnChallengeCookieName = "diyddns_webauthn_challenge"

// jarClient returns an *http.Client backed by a fresh, empty cookie jar, so a
// sequence of requests (login -> register begin -> register finish -> ...)
// accumulates and replays cookies exactly the way a browser would, without
// this file having to thread multiple *http.Cookie values through doJSON by
// hand.
func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{Jar: jar}
}

// jarDo sends method to url via client with an optional JSON-marshalable
// body and CSRF header, and returns the status, response header (for
// Set-Cookie inspection via findCookie), and raw body bytes.
func jarDo(t *testing.T, client *http.Client, method, url string, body any, csrf string) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, resp.Header, respBody
}

func jarPost(t *testing.T, client *http.Client, url string, body any, csrf string) (int, http.Header, []byte) {
	t.Helper()
	return jarDo(t, client, http.MethodPost, url, body, csrf)
}

// jarLoginAndCSRF logs email/password in via client (so the session cookie
// lands in its jar) and returns the CSRF token from /api/v1/auth/me.
func jarLoginAndCSRF(t *testing.T, client *http.Client, h fullHarness, email, password string) string {
	t.Helper()
	status, _, body := jarPost(t, client, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login: status = %d, body=%s", status, body)
	}
	status, _, meBody := jarDo(t, client, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, "")
	if status != http.StatusOK {
		t.Fatalf("me: status = %d, body=%s", status, meBody)
	}
	var me struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	return me.CSRF
}

// seedAdminWithPassword creates an admin user with an argon2id password
// hash — mirrors devices_test.go/auth_ops_test.go's seedAuthUserWithPassword
// but with Role "admin", needed by this file's admin-recovery test.
func seedAdminWithPassword(t *testing.T, st *store.Store, email, password string) store.User {
	t.Helper()
	hash, err := auth.HashPassword(password, auth.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := st.Users().Create(context.Background(), store.User{Email: email, Role: "admin", PasswordHash: hash})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return u
}

// seedBootstrapToken plants a known bootstrap token on st's single-row
// bootstrap record so a test can drive the passkey-based first-admin claim
// (design D9) without invoking Startup (whose default token sink only logs
// the token). VerifyPassword reads the argon2 params back out of the encoded
// hash, so the params used here need not match the harness's — only the
// plaintext token must round-trip.
func seedBootstrapToken(t *testing.T, st *store.Store, token string) {
	t.Helper()
	hash, err := auth.HashPassword(token, auth.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("hash bootstrap token: %v", err)
	}
	if err := st.Bootstrap().SetTokenHash(context.Background(), hash); err != nil {
		t.Fatalf("seed bootstrap token: %v", err)
	}
}

// mergeField decodes jsonBody, sets key to value, and re-encodes it — used to
// merge the extra fields (credential nickname, grant token) this package's
// finish operations accept alongside the raw WebAuthn response body (see
// passkey.go's webauthnFinishInput doc comment: go-webauthn's decoder
// ignores unrecognized top-level JSON fields).
func mergeField(t *testing.T, jsonBody, key, value string) string {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(jsonBody), &payload); err != nil {
		t.Fatalf("unmarshal for merge: %v", err)
	}
	payload[key] = value
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal merged: %v", err)
	}
	return string(out)
}

// registerPasskeyHTTP drives POST /api/v1/account/passkeys/register/begin
// then /finish over real HTTP via client (whose jar already carries a
// session cookie from jarLoginAndCSRF), using virtualwebauthn to fabricate a
// real authenticator/credential pair. It returns that pair so a later call
// can replay a discoverable login against it, and the credential id's
// base64url wire form (matching decodeCredID's encoding) for management ops.
func registerPasskeyHTTP(t *testing.T, client *http.Client, h fullHarness, csrf, name string) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, string) {
	t.Helper()
	rp := apiTestRP()

	status, _, beginBody := jarPost(t, client, h.srv.URL+"/api/v1/account/passkeys/register/begin", nil, "")
	if status != http.StatusOK {
		t.Fatalf("register begin: status = %d, body=%s", status, beginBody)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}

	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)

	finishBody := mergeField(t, attResp, "name", name)
	status, _, respBody := jarPost(t, client, h.srv.URL+"/api/v1/account/passkeys/register/finish", json.RawMessage(finishBody), csrf)
	if status != http.StatusOK {
		t.Fatalf("register finish: status = %d, body=%s", status, respBody)
	}
	return authr, cred, base64.RawURLEncoding.EncodeToString(cred.ID)
}

// loginPasskeyHTTP drives POST /api/v1/auth/passkey/login/begin then /finish
// over real HTTP via client, replaying authr/cred (as returned by
// registerPasskeyHTTP) via a discoverable-login ceremony, and returns the
// status/headers/body of the finish call so callers can assert on the
// session cookie or a failure status.
func loginPasskeyHTTP(t *testing.T, client *http.Client, h fullHarness, authr virtualwebauthn.Authenticator, cred virtualwebauthn.Credential) (int, http.Header, []byte) {
	t.Helper()
	rp := apiTestRP()

	status, _, beginBody := jarPost(t, client, h.srv.URL+"/api/v1/auth/passkey/login/begin", nil, "")
	if status != http.StatusOK {
		t.Fatalf("login begin: status = %d, body=%s", status, beginBody)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertResp := virtualwebauthn.CreateAssertionResponse(rp, authr, cred, *assertOpts)

	return jarPost(t, client, h.srv.URL+"/api/v1/auth/passkey/login/finish", json.RawMessage(assertResp), "")
}

// mustUserID looks up email's user id directly via the store, for tests that
// need it to build a path (e.g. the admin recovery endpoint's {id}).
func mustUserID(t *testing.T, h fullHarness, email string) string {
	t.Helper()
	u, err := h.st.Users().GetByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("GetByEmail(%s): %v", email, err)
	}
	return u.ID
}

// tokenFromLink extracts the token query parameter GrantService.issue embeds
// in every minted link ("<baseURL>/register?token=...").
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("link %q has no token query param", link)
	}
	return tok
}

func TestPasskeyLoginBegin_ReturnsOptionsAndChallengeCookie(t *testing.T) {
	h := newFullHarness(t)
	status, header, body := jarDo(t, jarClient(t), http.MethodPost, h.srv.URL+"/api/v1/auth/passkey/login/begin", nil, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	cookie := findCookie(header, webauthnChallengeCookieName)
	if cookie == nil {
		t.Fatalf("no %s cookie in response; headers=%v", webauthnChallengeCookieName, header)
	}
	if cookie.Value == "" {
		t.Fatal("challenge cookie has empty value")
	}

	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &opts); err != nil {
		t.Fatalf("decode options body: %v, body=%s", err, body)
	}
	if opts.PublicKey.Challenge == "" {
		t.Error("options body has no publicKey.challenge field")
	}
}

func TestPasskeyRegisterThenLogin_MintsSessionCookie(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "passkey@example.com", "correct horse battery staple")

	registerClient := jarClient(t)
	csrf := jarLoginAndCSRF(t, registerClient, h, "passkey@example.com", "correct horse battery staple")
	authr, cred, _ := registerPasskeyHTTP(t, registerClient, h, csrf, "My Laptop")

	// A fresh, cookie-free client proves the login ceremony below is
	// discoverable (usernameless) and self-sufficient — no leftover session
	// from the registration step is doing the work.
	loginClient := jarClient(t)
	status, header, body := loginPasskeyHTTP(t, loginClient, h, authr, cred)
	if status != http.StatusOK {
		t.Fatalf("login finish: status = %d, want 200, body=%s", status, body)
	}
	sessionCookie := findCookie(header, authTestCookieName)
	if sessionCookie == nil {
		t.Fatalf("no %s cookie after passkey login; headers=%v", authTestCookieName, header)
	}
	if sessionCookie.Value == "" {
		t.Fatal("session cookie has empty value")
	}
}

func TestDeletePasskey_LastOneReturns409(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "onlykey@example.com", "correct horse battery staple")

	client := jarClient(t)
	csrf := jarLoginAndCSRF(t, client, h, "onlykey@example.com", "correct horse battery staple")
	_, _, credID := registerPasskeyHTTP(t, client, h, csrf, "Only Key")

	status, _, body := jarDo(t, client, http.MethodDelete, h.srv.URL+"/api/v1/account/passkeys/"+credID, nil, csrf)
	if status != http.StatusConflict {
		t.Fatalf("delete last passkey: status = %d, want 409, body=%s", status, body)
	}
}

func TestRecoveryRequest_UniformlyReturns200(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "known@example.com", "correct horse battery staple")
	client := jarClient(t)
	csrf := jarLoginAndCSRF(t, client, h, "known@example.com", "correct horse battery staple")
	registerPasskeyHTTP(t, client, h, csrf, "Recovery Key")

	knownStatus, _, knownBody := jarDo(t, jarClient(t), http.MethodPost, h.srv.URL+"/api/v1/auth/recovery/request", map[string]string{
		"email": "known@example.com",
	}, "")
	if knownStatus != http.StatusOK {
		t.Fatalf("recovery request (known email): status = %d, want 200, body=%s", knownStatus, knownBody)
	}

	unknownStatus, _, unknownBody := jarDo(t, jarClient(t), http.MethodPost, h.srv.URL+"/api/v1/auth/recovery/request", map[string]string{
		"email": "unknown@example.com",
	}, "")
	if unknownStatus != http.StatusOK {
		t.Fatalf("recovery request (unknown email): status = %d, want 200, body=%s", unknownStatus, unknownBody)
	}
}

// TestAdminRecovery_IssuedLinkRedeemsViaRegisterEndpoint drives the admin
// recovery endpoint end to end: an admin issues a recovery link for a user
// whose existing passkey was just revoked at issue (design D10), then the
// user redeems the link's token through the shared /api/v1/register/begin +
// /finish grant-redeem path (design §7's "one token, one redeem flow"),
// proving passkey.go's discriminator correctly routes a token-bearing body
// to GrantService rather than BootstrapService.
func TestAdminRecovery_IssuedLinkRedeemsViaRegisterEndpoint(t *testing.T) {
	h := newFullHarness(t)
	seedAdminWithPassword(t, h.st, "admin@example.com", "correct horse battery staple")
	seedAuthUserWithPassword(t, h.st, "target@example.com", "correct horse battery staple")

	targetClient := jarClient(t)
	targetCSRF := jarLoginAndCSRF(t, targetClient, h, "target@example.com", "correct horse battery staple")
	registerPasskeyHTTP(t, targetClient, h, targetCSRF, "Old Key")

	adminClient := jarClient(t)
	adminCSRF := jarLoginAndCSRF(t, adminClient, h, "admin@example.com", "correct horse battery staple")
	targetID := mustUserID(t, h, "target@example.com")

	status, _, body := jarPost(t, adminClient, h.srv.URL+"/api/v1/admin/users/"+targetID+"/recovery", nil, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("admin recovery: status = %d, want 200, body=%s", status, body)
	}
	var recovery struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &recovery); err != nil {
		t.Fatalf("decode recovery response: %v, body=%s", err, body)
	}
	token := tokenFromLink(t, recovery.Link)

	redeemClient := jarClient(t)
	rp := apiTestRP()
	status, _, beginBody := jarPost(t, redeemClient, h.srv.URL+"/api/v1/register/begin", map[string]string{"token": token}, "")
	if status != http.StatusOK {
		t.Fatalf("register begin (grant redeem): status = %d, want 200, body=%s", status, beginBody)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)
	finishBody := mergeField(t, mergeField(t, attResp, "token", token), "name", "New Key")

	status, _, finishRespBody := jarPost(t, redeemClient, h.srv.URL+"/api/v1/register/finish", json.RawMessage(finishBody), "")
	if status != http.StatusOK {
		t.Fatalf("register finish (grant redeem): status = %d, want 200, body=%s", status, finishRespBody)
	}
}

// TestBootstrapClaim_RegistersFirstAdminViaRegisterEndpoint drives the
// passkey-based first-admin claim end to end through the shared
// /api/v1/register/begin + /finish pair (design D9): a token+email body at
// begin routes to BootstrapService.BeginClaim (not GrantService), the sealed
// bootstrap-claim cookie round-trips through webauthnMetaMiddleware, and a
// token-less finish body routes to FinishClaim — proving the begin/finish
// discriminator and the bootstrap-AAD cookie both work through the huma
// adapter. This is the ONLY path that mints the first admin, so it is
// covered at the HTTP layer here (abandoned-claim / atomic-gate properties
// are covered at the service layer in bootstrap_test.go).
func TestBootstrapClaim_RegistersFirstAdminViaRegisterEndpoint(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")

	client := jarClient(t)
	rp := apiTestRP()

	status, header, beginBody := jarPost(t, client, h.srv.URL+"/api/v1/register/begin", map[string]string{
		"token": "bootstrap-token-abc", "email": "firstadmin@example.com",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("register begin (bootstrap claim): status = %d, want 200, body=%s", status, beginBody)
	}
	if cookie := findCookie(header, webauthnChallengeCookieName); cookie == nil || cookie.Value == "" {
		t.Fatalf("no bootstrap-claim challenge cookie set; headers=%v", header)
	}

	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)
	// No token merged in — a token-less finish body routes to FinishClaim.
	finishBody := mergeField(t, attResp, "name", "First Admin Key")

	status, _, finishRespBody := jarPost(t, client, h.srv.URL+"/api/v1/register/finish", json.RawMessage(finishBody), "")
	if status != http.StatusOK {
		t.Fatalf("register finish (bootstrap claim): status = %d, want 200, body=%s", status, finishRespBody)
	}

	admin, err := h.st.Users().GetByEmail(t.Context(), "firstadmin@example.com")
	if err != nil {
		t.Fatalf("GetByEmail(firstadmin): %v", err)
	}
	if admin.Role != "admin" {
		t.Errorf("created user role = %q, want admin", admin.Role)
	}
	if admin.PasswordHash != "" {
		t.Errorf("bootstrap-claimed admin has a password hash, want none (passkey-only)")
	}
	count, err := h.st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials: %v", err)
	}
	if count != 1 {
		t.Errorf("admin passkey count = %d, want 1", count)
	}
}

func TestBootstrapClaim_WrongTokenReturns401(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+"/api/v1/register/begin", map[string]string{
		"token": "wrong-token", "email": "firstadmin@example.com",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("bootstrap claim (wrong token): status = %d, want 401, body=%s", status, body)
	}
}

func TestBootstrapClaim_MalformedEmailReturns422(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+"/api/v1/register/begin", map[string]string{
		"token": "bootstrap-token-abc", "email": "not-an-email",
	}, "")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("bootstrap claim (malformed email): status = %d, want 422, body=%s", status, body)
	}
}
