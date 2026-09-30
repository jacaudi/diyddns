package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestAdminReissueInvite(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-reinvite@example.com", "admin")
	pending := seedUser(t, h.st, "pending@example.com", "user")
	registered := seedUser(t, h.st, "registered@example.com", "user")
	seedCredential(t, h.st, registered)
	cookie, csrf := sessionFor(t, h, "admin-reinvite@example.com")

	// No CSRF -> 403, like every admin write.
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users/"+pending.ID+"/invite", nil, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("no csrf: status = %d, want 403, body=%s", status, body)
	}

	before := store.NowUnix()
	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users/"+pending.ID+"/invite", nil, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("pending: status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Link      string `json:"link"`
		ExpiresAt int64  `json:"expires_at"`
		Delivery  struct {
			Sent bool   `json:"sent"`
			To   string `json:"to"`
		} `json:"delivery"`
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.Link == "" {
		t.Error("response carried no link")
	}
	if got.ExpiresAt <= before {
		t.Errorf("expires_at = %d, want after %d", got.ExpiresAt, before)
	}
	if !got.Delivery.Sent || got.Delivery.To != "pending@example.com" {
		t.Errorf("delivery = %+v, want sent to pending@example.com", got.Delivery)
	}
	if got.User["registration_status"] != "invited" {
		t.Errorf("user.registration_status = %v, want invited", got.User["registration_status"])
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users/"+registered.ID+"/invite", nil, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Errorf("registered: status = %d, want 422, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users/does-not-exist/invite", nil, cookie, csrf)
	if status != http.StatusNotFound {
		t.Errorf("unknown id: status = %d, want 404, body=%s", status, body)
	}
}

// TestAdminReissueInvite_WebAuthnUnavailableIs503 builds the server with a
// GrantService that has no PasskeyService, the one state that makes
// ReissueInvite return ErrWebAuthnUnavailable.
func TestAdminReissueInvite_WebAuthnUnavailableIs503(t *testing.T) {
	st, deps := buildServerDeps(t)
	deps.Grants = service.NewGrantService(st, nil, fakeMailer{}, "http://localhost", discardAgentAudit{}, deps.Log, 15*time.Minute)
	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	h := fullHarness{srv: srv, st: st}

	seedUser(t, st, "admin-503@example.com", "admin")
	target := seedUser(t, st, "target-503@example.com", "user")
	cookie, csrf := sessionFor(t, h, "admin-503@example.com")

	status, _, body := doJSON(t, http.MethodPost, srv.URL+"/api/v1/admin/users/"+target.ID+"/invite", nil, cookie, csrf)
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503, body=%s", status, body)
	}
}
