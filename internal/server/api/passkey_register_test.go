package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// The register/begin + register/finish tests replay what static/passkey.js
// sends. The server, not the client, decides which flow a request is in: begin
// classifies the token and tags the challenge cookie, and finish routes on the
// tag (issue #188).

const (
	registerBeginPath  = "/api/v1/register/begin"
	registerFinishPath = "/api/v1/register/finish"

	// errLinkInvalid is the detail of every "this registration link cannot be
	// used" response.
	errLinkInvalid = "registration link invalid, expired, or already used"
)

// attest builds the authenticator's attestation response for a register/begin
// options body, as navigator.credentials.create() would.
func attest(t *testing.T, beginBody []byte) string {
	t.Helper()
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	return virtualwebauthn.CreateAttestationResponse(apiTestRP(), authr, cred, *attOpts)
}

// registerFinishBody is the body passkey.js posts to register/finish: the
// attestation response plus a passkey name, and the token when it sends one.
func registerFinishBody(t *testing.T, beginBody []byte, token string) json.RawMessage {
	t.Helper()
	body := mergeField(t, attest(t, beginBody), "name", "Test Key")
	if token != "" {
		body = mergeField(t, body, "token", token)
	}
	return json.RawMessage(body)
}

// setChallengeCookie replaces client's challenge cookie with value.
func setChallengeCookie(t *testing.T, client *http.Client, h fullHarness, value string) {
	t.Helper()
	su, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client.Jar.SetCookies(su, []*http.Cookie{{Name: webauthnChallengeCookieName, Value: value, Path: "/"}})
}

// seedGrantToken plants a grant for userID and returns its raw token.
// expiresAt and usedAt are unix seconds (usedAt 0 means unconsumed).
func seedGrantToken(t *testing.T, st *store.Store, userID, reason string, expiresAt, usedAt int64) string {
	t.Helper()
	token, err := auth.RandToken(32)
	if err != nil {
		t.Fatalf("RandToken: %v", err)
	}
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: auth.HashToken(token), UserID: userID, Reason: reason, ExpiresAt: expiresAt, UsedAt: usedAt,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return token
}

// adminRecoveryToken has the admin issue a recovery link for the user with
// targetEmail, through the API, and returns the link's token.
func adminRecoveryToken(t *testing.T, h fullHarness, adminEmail, targetEmail string) string {
	t.Helper()
	adminClient := jarClient(t)
	csrf := jarSeedSession(t, adminClient, h, adminEmail)
	id := mustUserID(t, h, targetEmail)
	status, _, body := jarPost(t, adminClient, h.srv.URL+"/api/v1/admin/users/"+id+"/recovery", nil, csrf)
	if status != http.StatusOK {
		t.Fatalf("admin recovery: status = %d, body=%s", status, body)
	}
	var resp struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode recovery response: %v, body=%s", err, body)
	}
	return tokenFromLink(t, resp.Link)
}

func adminCount(t *testing.T, h fullHarness) int {
	t.Helper()
	users, err := h.st.Users().List(t.Context())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	n := 0
	for _, u := range users {
		if u.Role == "admin" {
			n++
		}
	}
	return n
}

// problemDetail returns the "detail" of a huma error body.
func problemDetail(t *testing.T, body []byte) string {
	t.Helper()
	var p struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode error body: %v, body=%s", err, body)
	}
	return p.Detail
}

// passkeyCount is the number of passkeys the user with email has.
func passkeyCount(t *testing.T, h fullHarness, email string) int {
	t.Helper()
	n, err := h.st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), mustUserID(t, h, email))
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials: %v", err)
	}
	return n
}

// beginGrant has client call register/begin for token, with the email an
// autofilling browser would add, and returns the options body.
func beginGrant(t *testing.T, client *http.Client, h fullHarness, token, email string) (http.Header, []byte) {
	t.Helper()
	status, header, body := jarPost(t, client, h.srv.URL+registerBeginPath, map[string]string{"token": token, "email": email}, "")
	if status != http.StatusOK {
		t.Fatalf("register begin: status = %d, want 200, body=%s", status, body)
	}
	return header, body
}

// TestRegister_GrantLinkWithAutofilledEmail is the #188 reproduction: an
// invitee or recovering user whose browser filled in the Email field must
// still redeem their link. Before the fix, begin treated any email as a
// bootstrap claim and answered 410.
func TestRegister_GrantLinkWithAutofilledEmail(t *testing.T) {
	for _, reason := range []string{"recovery", "invite"} {
		t.Run(reason, func(t *testing.T) {
			h := newFullHarness(t)
			seedUser(t, h.st, "admin@example.com", "admin")
			user := seedUser(t, h.st, "target@example.com", "user")
			var token string
			if reason == "recovery" {
				oldKey := jarClient(t)
				registerPasskeyHTTP(t, oldKey, h, jarSeedSession(t, oldKey, h, user.Email), "Old")
				token = adminRecoveryToken(t, h, "admin@example.com", user.Email)
			} else {
				token = seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)
			}

			client := jarClient(t)
			_, beginBody := beginGrant(t, client, h, token, user.Email)
			status, header, body := jarPost(t, client, h.srv.URL+registerFinishPath, registerFinishBody(t, beginBody, token), "")

			if status != http.StatusOK {
				t.Fatalf("register finish: status = %d, want 200, body=%s", status, body)
			}
			if c := findCookie(header, authTestCookieName); c == nil || c.Value == "" {
				t.Errorf("register finish set no session cookie; headers=%v", header)
			}
			if got := passkeyCount(t, h, user.Email); got != 1 {
				t.Errorf("passkeys after redeem = %d, want 1", got)
			}
		})
	}
}

// TestRegister_DeadTokenWithEmailIsUnauthorized: a token that is not a live
// grant, sent with an email while an admin exists, is "link invalid" (401),
// never "bootstrap already completed" (410).
func TestRegister_DeadTokenWithEmailIsUnauthorized(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin@example.com", "admin")
	user := seedUser(t, h.st, "target@example.com", "user")
	now := store.NowUnix()
	tokens := map[string]string{
		"expired": seedGrantToken(t, h.st, user.ID, "invite", now-10, 0),
		"used":    seedGrantToken(t, h.st, user.ID, "invite", now+3600, now-5),
		"unknown": "no-such-token",
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath,
				map[string]string{"token": token, "email": user.Email}, "")

			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (never 410), body=%s", status, body)
			}
			if got := problemDetail(t, body); got != errLinkInvalid {
				t.Errorf("detail = %q, want %q", got, errLinkInvalid)
			}
		})
	}
}

// TestRegister_GrantFinishWithoutTokenIsUnauthorized: a grant redeem needs the
// token on finish, for the atomic Consume. Without it the answer is "link
// invalid", not a bootstrap error.
func TestRegister_GrantFinishWithoutTokenIsUnauthorized(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin@example.com", "admin")
	user := seedUser(t, h.st, "target@example.com", "user")
	token := seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)

	client := jarClient(t)
	_, beginBody := beginGrant(t, client, h, token, "")
	status, _, body := jarPost(t, client, h.srv.URL+registerFinishPath, registerFinishBody(t, beginBody, ""), "")

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != errLinkInvalid {
		t.Errorf("detail = %q, want %q", got, errLinkInvalid)
	}
	if got := passkeyCount(t, h, user.Email); got != 0 {
		t.Errorf("passkeys = %d, want 0", got)
	}
}

// TestRegister_BootstrapClaimFinishWithTokenStillClaims: finish routes on the
// cookie's flow tag, so a claim finish that also carries a token (an older or
// different client) is still a claim. The token-less claim is covered by
// TestBootstrapClaim_RegistersFirstAdminViaRegisterEndpoint.
func TestRegister_BootstrapClaimFinishWithTokenStillClaims(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")
	client := jarClient(t)
	_, beginBody := beginGrant(t, client, h, "bootstrap-token-abc", "firstadmin@example.com")

	status, header, body := jarPost(t, client, h.srv.URL+registerFinishPath,
		registerFinishBody(t, beginBody, "bootstrap-token-abc"), "")

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if c := findCookie(header, authTestCookieName); c == nil || c.Value == "" {
		t.Errorf("no session cookie; headers=%v", header)
	}
	if got := adminCount(t, h); got != 1 {
		t.Errorf("admins = %d, want 1", got)
	}
}

// TestRegister_BeginTagsTheChallengeCookie: the cookie's flow tag is what
// finish routes on, so begin must set it.
func TestRegister_BeginTagsTheChallengeCookie(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, h fullHarness) (token, email string)
		wantPrefix string
	}{
		{"live grant", func(t *testing.T, h fullHarness) (string, string) {
			u := seedUser(t, h.st, "target@example.com", "user")
			return seedGrantToken(t, h.st, u.ID, "invite", store.NowUnix()+3600, 0), ""
		}, "grant."},
		{"bootstrap claim", func(t *testing.T, h fullHarness) (string, string) {
			seedBootstrapToken(t, h.st, "bootstrap-token-abc")
			return "bootstrap-token-abc", "firstadmin@example.com"
		}, "claim."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFullHarness(t)
			token, email := tt.setup(t, h)

			header, _ := beginGrant(t, jarClient(t), h, token, email)

			c := findCookie(header, webauthnChallengeCookieName)
			if c == nil || !strings.HasPrefix(c.Value, tt.wantPrefix) {
				t.Fatalf("challenge cookie = %+v, want a value starting %q", c, tt.wantPrefix)
			}
		})
	}
}

// TestRegister_RetaggedGrantCookie: the flow tag is not authenticated, so a
// client can rewrite it. A grant cookie retagged claim. reaches the claim
// opener, which rejects it (different AAD): 401 with no admin created, or 410
// from FinishClaim's existing admin-exists check when an admin is present.
func TestRegister_RetaggedGrantCookie(t *testing.T) {
	tests := []struct {
		name       string
		adminFirst bool
		wantStatus int
		wantAdmins int
	}{
		{"no admin yet", false, http.StatusUnauthorized, 0},
		{"admin exists", true, http.StatusGone, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFullHarness(t)
			if tt.adminFirst {
				seedUser(t, h.st, "admin@example.com", "admin")
			}
			user := seedUser(t, h.st, "target@example.com", "user")
			token := seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)
			client := jarClient(t)
			header, beginBody := beginGrant(t, client, h, token, "")
			sealed := strings.TrimPrefix(findCookie(header, webauthnChallengeCookieName).Value, "grant.")
			setChallengeCookie(t, client, h, "claim."+sealed)

			status, _, body := jarPost(t, client, h.srv.URL+registerFinishPath, registerFinishBody(t, beginBody, token), "")

			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d, body=%s", status, tt.wantStatus, body)
			}
			if got := adminCount(t, h); got != tt.wantAdmins {
				t.Errorf("admins = %d, want %d", got, tt.wantAdmins)
			}
		})
	}
}

// TestRegister_RetaggedClaimCookieDoesNotRedeemAGrant: a claim cookie retagged
// grant. and finished with another live grant's token must not consume that
// grant.
func TestRegister_RetaggedClaimCookieDoesNotRedeemAGrant(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")
	user := seedUser(t, h.st, "target@example.com", "user")
	token := seedGrantToken(t, h.st, user.ID, "recovery", store.NowUnix()+3600, 0)
	client := jarClient(t)
	header, beginBody := beginGrant(t, client, h, "bootstrap-token-abc", "firstadmin@example.com")
	sealed := strings.TrimPrefix(findCookie(header, webauthnChallengeCookieName).Value, "claim.")
	setChallengeCookie(t, client, h, "grant."+sealed)

	status, _, body := jarPost(t, client, h.srv.URL+registerFinishPath, registerFinishBody(t, beginBody, token), "")

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body=%s", status, body)
	}
	grant, err := h.st.AccountRecovery().Get(t.Context(), auth.HashToken(token))
	if err != nil {
		t.Fatalf("AccountRecovery.Get: %v", err)
	}
	if grant.UsedAt != 0 {
		t.Errorf("grant.UsedAt = %d, want 0: a tampered finish consumed it", grant.UsedAt)
	}
}

// TestRegister_FinishWithoutAUsableFlowTag: an untagged value (every cookie
// issued before this change), an unknown tag, and no cookie at all are the
// uniform ceremony failure, and the log says why.
func TestRegister_FinishWithoutAUsableFlowTag(t *testing.T) {
	tests := []struct {
		name string
		// value derives the cookie to send from the sealed begin cookie;
		// ok is false for "send none".
		value func(sealed string) (value string, ok bool)
	}{
		{"untagged", func(sealed string) (string, bool) { return sealed, true }},
		{"unknown tag", func(sealed string) (string, bool) { return "bogus." + sealed, true }},
		{"no cookie", func(string) (string, bool) { return "", false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, logs := newLoggedHarness(t)
			user := seedUser(t, h.st, "target@example.com", "user")
			token := seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)
			begin := jarClient(t)
			header, beginBody := beginGrant(t, begin, h, token, "")
			sealed := strings.TrimPrefix(findCookie(header, webauthnChallengeCookieName).Value, "grant.")
			value, send := tt.value(sealed)
			finish := jarClient(t)
			if send {
				setChallengeCookie(t, finish, h, value)
			}

			status, _, body := jarPost(t, finish, h.srv.URL+registerFinishPath, registerFinishBody(t, beginBody, token), "")

			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body=%s", status, body)
			}
			if got := problemDetail(t, body); got != errPasskeyVerificationDetail {
				t.Errorf("detail = %q, want %q", got, errPasskeyVerificationDetail)
			}
			lines := withMsg(atLevel(logs.records(t), "INFO"), "register finish: challenge cookie has no flow tag")
			if len(lines) != 1 {
				t.Fatalf("no-flow-tag Info lines = %d, want 1; log: %v", len(lines), logs.records(t))
			}
			if got := lines[0]["sealed_len"]; got != float64(len(value)) {
				t.Errorf("sealed_len = %v, want %d", got, len(value))
			}
			// The line reports only the length: neither cookie nor token is logged.
			logged := logs.String()
			for name, secret := range map[string]string{"sealed cookie": sealed, "sent cookie value": value, "token": token} {
				if len(secret) >= 8 && strings.Contains(logged, secret) {
					t.Errorf("the log contains the %s:\n%s", name, logged)
				}
			}
		})
	}
}

// errPasskeyVerificationDetail is the uniform ceremony-failure detail.
const errPasskeyVerificationDetail = "passkey verification failed"

// TestRegister_BeginOnAClosedStoreIsAServerError: a store failure behind a
// token is a 500 with one Error line, not "link invalid".
func TestRegister_BeginOnAClosedStoreIsAServerError(t *testing.T) {
	h, logs := newLoggedHarness(t)
	seedUser(t, h.st, "admin@example.com", "admin")
	if err := h.st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath,
		map[string]string{"token": "some-token", "email": "someone@example.com"}, "")

	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", status, body)
	}
	if errs := atLevel(logs.records(t), "ERROR"); len(errs) != 1 || errs[0]["msg"] != "begin registration failed" {
		t.Errorf("Error lines = %v, want exactly one %q", errs, "begin registration failed")
	}
}

// TestRegister_BeginClaimStoreFailureIsAServerError: on a fresh install, a
// store failure inside the claim itself (routing succeeded, the token read
// failed) is a 500 with one Error line, not "invalid bootstrap token" (#190).
func TestRegister_BeginClaimStoreFailureIsAServerError(t *testing.T) {
	h, logs := newLoggedHarness(t)
	if _, err := h.st.DB().ExecContext(t.Context(), `DROP TABLE bootstrap`); err != nil {
		t.Fatalf("drop bootstrap: %v", err)
	}

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath,
		map[string]string{"token": "some-token", "email": "admin@example.com"}, "")

	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", status, body)
	}
	if errs := atLevel(logs.records(t), "ERROR"); len(errs) != 1 || errs[0]["msg"] != "begin registration failed" {
		t.Errorf("Error lines = %v, want exactly one %q", errs, "begin registration failed")
	}
}

// TestRegister_BeginFreshInstallWrongTokenKeepsItsMessage: on a fresh install
// a wrong token with an email is still "invalid bootstrap token".
func TestRegister_BeginFreshInstallWrongTokenKeepsItsMessage(t *testing.T) {
	h := newFullHarness(t)
	seedBootstrapToken(t, h.st, "bootstrap-token-abc")

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath,
		map[string]string{"token": "wrong", "email": "a@example.com"}, "")

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != "invalid bootstrap token" {
		t.Errorf("detail = %q, want %q", got, "invalid bootstrap token")
	}
}

// TestRegister_BeginWithNoUsableToken: with an admin present, a begin body
// whose token is empty, or is a live grant's token padded with whitespace, is
// "link invalid" (401). The token is not trimmed, so padding makes it an
// unknown token; it must never crash (500) or reach the claim (410). A body
// with no token property at all never reaches the handler: the schema marks
// token required, so huma answers 422, which this pins as existing behaviour
// (the wire contract is unchanged, D5).
func TestRegister_BeginWithNoUsableToken(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin@example.com", "admin")
	user := seedUser(t, h.st, "target@example.com", "user")
	live := seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)
	tests := []struct {
		name       string
		body       map[string]string
		wantStatus int
		wantDetail string
	}{
		{"empty object", map[string]string{}, http.StatusUnprocessableEntity, "validation failed"},
		{"empty token", map[string]string{"token": ""}, http.StatusUnauthorized, errLinkInvalid},
		{"live token padded with whitespace", map[string]string{"token": " " + live + " ", "email": user.Email}, http.StatusUnauthorized, errLinkInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath, tt.body, "")

			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", status, tt.wantStatus, body)
			}
			if got := problemDetail(t, body); got != tt.wantDetail {
				t.Errorf("detail = %q, want %q", got, tt.wantDetail)
			}
		})
	}
}

// TestRegister_DoubleSubmitRegistersOnePasskey: a second finish with the same
// body, after the first succeeded, is rejected and the account still has one
// passkey. "jar as left" sends what a browser holds after the first response
// (which clears the challenge cookie); "cookie replayed" sends the original
// cookie again, as two overlapping requests would.
func TestRegister_DoubleSubmitRegistersOnePasskey(t *testing.T) {
	tests := []struct {
		name         string
		replayCookie bool
		wantDetail   string
	}{
		{"jar as left", false, errPasskeyVerificationDetail},
		{"cookie replayed", true, errLinkInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFullHarness(t)
			seedUser(t, h.st, "admin@example.com", "admin")
			user := seedUser(t, h.st, "target@example.com", "user")
			token := seedGrantToken(t, h.st, user.ID, "invite", store.NowUnix()+3600, 0)
			client := jarClient(t)
			header, beginBody := beginGrant(t, client, h, token, user.Email)
			cookie := findCookie(header, webauthnChallengeCookieName).Value
			finish := registerFinishBody(t, beginBody, token)
			if status, _, body := jarPost(t, client, h.srv.URL+registerFinishPath, finish, ""); status != http.StatusOK {
				t.Fatalf("first finish: status = %d, want 200, body=%s", status, body)
			}
			if tt.replayCookie {
				setChallengeCookie(t, client, h, cookie)
			}

			status, _, body := jarPost(t, client, h.srv.URL+registerFinishPath, finish, "")

			if status != http.StatusUnauthorized {
				t.Fatalf("second finish: status = %d, want 401, body=%s", status, body)
			}
			if got := problemDetail(t, body); got != tt.wantDetail {
				t.Errorf("detail = %q, want %q", got, tt.wantDetail)
			}
			if got := passkeyCount(t, h, user.Email); got != 1 {
				t.Errorf("passkeys = %d, want 1", got)
			}
		})
	}
}

// errInvalidEmailDetail is the existing 422 text for an address BeginClaim
// refuses.
const errInvalidEmailDetail = "email address must be a plain 7-bit ASCII address in user@host form, with no display name and no surrounding whitespace"

// TestRegister_BeginFreshInstallWithoutEmailIsUnprocessable: on a fresh install
// a begin body with no email reaches BeginClaim, which checks the address
// before the token. Whether the token is right or wrong, the answer is 422 with
// the existing invalid-email text (it used to be 401 "link invalid").
func TestRegister_BeginFreshInstallWithoutEmailIsUnprocessable(t *testing.T) {
	for name, token := range map[string]string{"correct bootstrap token": "bootstrap-token-abc", "wrong token": "wrong"} {
		t.Run(name, func(t *testing.T) {
			h := newFullHarness(t)
			seedBootstrapToken(t, h.st, "bootstrap-token-abc")

			status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath, map[string]string{"token": token}, "")

			if status != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422, body=%s", status, body)
			}
			if got := problemDetail(t, body); got != errInvalidEmailDetail {
				t.Errorf("detail = %q, want %q", got, errInvalidEmailDetail)
			}
		})
	}
}

// TestRegister_BeginForACancelledRequest drives register/begin over HTTP with a
// request context that is already cancelled (see cancelledRequests): the
// client's doing, not a store failure, so 499 with one Info line and no Error
// line, never the 500 an Error-level failure would give.
func TestRegister_BeginForACancelledRequest(t *testing.T) {
	st, deps := buildServerDeps(t)
	logs := &logCapture{}
	deps.Log = logs.logger()
	h := serveWith(t, st, deps, cancelledRequests)

	status, _, body := jarPost(t, jarClient(t), h.srv.URL+registerBeginPath,
		map[string]string{"token": "some-token", "email": "someone@example.com"}, "")

	if status != 499 {
		t.Fatalf("status = %d, want 499, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != "client closed request" {
		t.Errorf("detail = %q, want %q", got, "client closed request")
	}
	recs := logs.records(t)
	if info := withMsg(atLevel(recs, "INFO"), "begin registration cancelled"); len(info) != 1 {
		t.Errorf("Info lines %q = %d, want 1; log: %v", "begin registration cancelled", len(info), recs)
	}
	if errs := atLevel(recs, "ERROR"); len(errs) != 0 {
		t.Errorf("Error lines = %v, want none", errs)
	}
}
