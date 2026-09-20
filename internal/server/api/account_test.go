package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// newEmailChangeHarness builds on buildServerDeps, overriding deps.EmailChange
// with a service backed by mailer instead of buildServerDeps' default
// fakeMailer. Only the no-mailer-configured self-service test (mailer == nil)
// needs this: every other account_test.go test uses newFullHarness directly,
// since EmailChangeService is unconditionally wired there with a working
// mailer (see buildServerDeps).
func newEmailChangeHarness(t *testing.T, mailer email.Mailer) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)
	deps.EmailChange = service.NewEmailChangeService(st, mailer, "http://localhost", discardAgentAudit{}, discardLogger())

	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return fullHarness{srv: srv, st: st}
}

// ---------- POST /api/v1/account/email ----------

func TestAccountEmailRequest_HappyPathWithMailer(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "change-mailer@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-mailer@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "new-mailer@example.com",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Link     string `json:"link"`
		Delivery struct {
			Attempted bool `json:"attempted"`
			Sent      bool `json:"sent"`
		} `json:"delivery"`
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.Link != "" {
		t.Errorf("link = %q, want empty: a configured mailer already carried it (#144)", got.Link)
	}
	if !got.Delivery.Sent {
		t.Errorf("Delivery.Sent = false, want true")
	}
	if got.ExpiresAt == 0 {
		t.Error("expires_at = 0, want the staged change's actual expiry")
	}
}

func TestAccountEmailRequest_HappyPathNoMailer(t *testing.T) {
	h := newEmailChangeHarness(t, nil)
	seedUser(t, h.st, "change-nomailer@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-nomailer@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "new-nomailer@example.com",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Link     string `json:"link"`
		Delivery struct {
			Attempted bool `json:"attempted"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.Link == "" {
		t.Fatal("link = empty, want the shown-once confirmation link (#144)")
	}
	if got.Delivery.Attempted {
		t.Errorf("Delivery.Attempted = true, want false with no mailer configured")
	}
}

func TestAccountEmailRequest_Unchanged(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "change-unchanged@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-unchanged@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "change-unchanged@example.com",
	}, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

func TestAccountEmailRequest_OIDCManaged(t *testing.T) {
	h := newFullHarness(t)
	u, err := h.st.Users().Create(t.Context(), store.User{
		Email: "change-oidc@example.com", Role: "user",
		OIDCProvider: "https://idp.example.com", OIDCSubject: "sub-account-request",
	})
	if err != nil {
		t.Fatalf("seed oidc user: %v", err)
	}
	cookie, csrf := sessionFor(t, h, u.Email)

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "somewhere-else@example.com",
	}, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

func TestAccountEmailRequest_ConflictingAddress(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "change-conflict@example.com", "user")
	seedUser(t, h.st, "taken-request@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-conflict@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "taken-request@example.com",
	}, cookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", status, body)
	}
}

func TestAccountEmailRequest_MailerFails(t *testing.T) {
	h := newEmailChangeHarness(t, failingMailer{})
	seedUser(t, h.st, "change-mailfail@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-mailfail@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "new-mailfail@example.com",
	}, cookie, csrf)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", status, body)
	}

	u, err := h.st.Users().GetByEmail(t.Context(), "change-mailfail@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u.PendingEmail != "" {
		t.Errorf("PendingEmail = %q, want rolled back to empty after a failed send (email_change.go:193-218)", u.PendingEmail)
	}
}

func TestAccountEmailRequest_InvalidEmail(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "change-invalidaddr@example.com", "user")
	cookie, csrf := sessionFor(t, h, "change-invalidaddr@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "not-an-email",
	}, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

func TestAccountEmailRequest_Unauthenticated(t *testing.T) {
	h := newFullHarness(t)

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "whoever@example.com",
	}, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

// ---------- POST /api/v1/account/email/cancel ----------

func TestAccountEmailCancel_WithPending(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "cancel-pending@example.com", "user")
	cookie, csrf := sessionFor(t, h, "cancel-pending@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "cancel-target@example.com",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("stage: status = %d, want 200, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email/cancel", nil, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	u, err := h.st.Users().GetByEmail(t.Context(), "cancel-pending@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u.PendingEmail != "" {
		t.Errorf("PendingEmail = %q, want cleared after cancel", u.PendingEmail)
	}
}

func TestAccountEmailCancel_NothingPending(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "cancel-nothing@example.com", "user")
	cookie, csrf := sessionFor(t, h, "cancel-nothing@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email/cancel", nil, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no-op), body=%s", status, body)
	}
}

// ---------- POST /api/v1/account/email/confirm ----------

func TestAccountEmailConfirm_HappyPath(t *testing.T) {
	// No mailer, so the stage response carries the link (and its token)
	// directly instead of masking it -- see #144.
	h := newEmailChangeHarness(t, nil)
	seedUser(t, h.st, "confirm-happy@example.com", "user")
	cookie, csrf := sessionFor(t, h, "confirm-happy@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email", map[string]string{
		"email": "confirm-target@example.com",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("stage: status = %d, want 200, body=%s", status, body)
	}
	var staged struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &staged); err != nil {
		t.Fatalf("decode stage response: %v, body=%s", err, body)
	}
	token := tokenFromLink(t, staged.Link)

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email/confirm", map[string]string{
		"token": token,
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("confirm: status = %d, want 200, body=%s", status, body)
	}

	u, err := h.st.Users().GetByEmail(t.Context(), "confirm-target@example.com")
	if err != nil {
		t.Fatalf("GetByEmail after confirm: %v", err)
	}
	if u.PendingEmail != "" {
		t.Errorf("PendingEmail = %q, want cleared after confirm", u.PendingEmail)
	}
}

func TestAccountEmailConfirm_InvalidToken(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "confirm-invalid@example.com", "user")
	cookie, csrf := sessionFor(t, h, "confirm-invalid@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/email/confirm", map[string]string{
		"token": "not-a-real-token",
	}, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}
