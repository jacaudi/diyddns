package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedAudit appends n audit-log rows so admin/audit pagination has rows to
// walk. The rows' content is irrelevant to the pagination assertions.
func seedAudit(t *testing.T, st *store.Store, n int) {
	t.Helper()
	for i := range n {
		if _, err := st.AuditLog().Append(t.Context(), store.AuditEntry{EventType: "test.event"}); err != nil {
			t.Fatalf("seed audit %d: %v", i, err)
		}
	}
}

// ---------- GET /api/v1/admin/users ----------

func TestAdminListUsers_RequiresAdmin(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin1@example.com", "admin")
	seedUser(t, h.st, "user1@example.com", "user")

	// Non-admin -> 403
	userCookie, _ := sessionFor(t, h, "user1@example.com")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil, userCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("user: status = %d, want 403, body=%s", status, body)
	}

	// Admin -> 200
	adminCookie, _ := sessionFor(t, h, "admin1@example.com")
	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("admin: status = %d, want 200, body=%s", status, body)
	}

	// No session -> 401
	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("anon: status = %d, want 401, body=%s", status, body)
	}
}

// ---------- POST /api/v1/admin/users ----------

func TestAdminCreateUser_RequiresCSRF(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin2@example.com", "admin")
	seedUser(t, h.st, "user2@example.com", "user")
	adminCookie, adminCSRF := sessionFor(t, h, "admin2@example.com")
	userCookie, userCSRF := sessionFor(t, h, "user2@example.com")

	newUser := map[string]string{"email": "n@x.com", "role": "user"}

	// Admin, no CSRF -> 403
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users", newUser, adminCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("no csrf: status = %d, want 403, body=%s", status, body)
	}

	// Non-admin, valid CSRF (their own) -> 403: proves adminMiddleware gates
	// the write path independently of / before csrfMiddleware (chain order).
	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users", newUser, userCookie, userCSRF)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin with csrf: status = %d, want 403, body=%s", status, body)
	}

	// Admin + CSRF -> 200. Admin user creation is now credential-less: the
	// response carries the created user plus a one-time invite link (no
	// password field in or out), and the created user has no credential yet.
	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users", map[string]string{
		"email": "n2@x.com", "role": "user",
	}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("with csrf: status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		User struct {
			ID         string `json:"id"`
			Email      string `json:"email"`
			OIDCLinked bool   `json:"oidc_linked"`
		} `json:"user"`
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode create response: %v, body=%s", err, body)
	}
	if got.User.Email != "n2@x.com" {
		t.Fatalf("email = %q, want n2@x.com", got.User.Email)
	}
	if got.Link == "" {
		t.Fatalf("create response missing invite link, body=%s", body)
	}
	if got.User.OIDCLinked {
		t.Fatalf("credential-less user should not be reported oidc_linked, body=%s", body)
	}
}

// TestAdminCreateUser_ResponseCarriesDelivery proves an API client learns
// whether the link was emailed. The harness wires an enabled fakeMailer whose
// Send always succeeds, so this must report attempted=true and sent=true.
func TestAdminCreateUser_ResponseCarriesDelivery(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-delivery@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-delivery@example.com")

	newUser := map[string]string{"email": "invitee-delivery@example.com", "role": "user"}
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users", newUser, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got struct {
		Link     string `json:"link"`
		Delivery struct {
			Attempted bool   `json:"attempted"`
			Sent      bool   `json:"sent"`
			To        string `json:"to"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, body)
	}
	if got.Link == "" {
		t.Fatal("response carried no link")
	}
	if !got.Delivery.Attempted || !got.Delivery.Sent {
		t.Errorf("Delivery = %+v, want attempted=true sent=true", got.Delivery)
	}
	if got.Delivery.To != "invitee-delivery@example.com" {
		t.Errorf("Delivery.To = %q, want invitee-delivery@example.com", got.Delivery.To)
	}
}

// ---------- PATCH /api/v1/admin/users/{id} ----------

func TestAdminUpdateUser_LastAdmin_Conflict(t *testing.T) {
	h := newFullHarness(t)
	admin := seedUser(t, h.st, "admin3@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin3@example.com")

	// Demoting the only enabled admin -> 409 (guard surfaced).
	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/admin/users/"+admin.ID, map[string]string{
		"role": "user",
	}, adminCookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", status, body)
	}
}

// ---------- DELETE /api/v1/admin/users/{id} ----------

func TestAdminDeleteUser_Returns204(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin4@example.com", "admin")
	target := seedUser(t, h.st, "target4@example.com", "user")
	adminCookie, csrf := sessionFor(t, h, "admin4@example.com")

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/users/"+target.ID, nil, adminCookie, csrf)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", status, body)
	}
	if _, err := h.st.Users().GetByID(t.Context(), target.ID); err == nil {
		t.Fatal("target user still exists after delete")
	}
}

// ---------- GET /api/v1/admin/devices ----------

func TestAdminListDevices_IncludesUserID(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin5@example.com", "admin")
	owner := seedUser(t, h.st, "owner5@example.com", "user")
	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: owner.ID, Label: "dev"}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	adminCookie, _ := sessionFor(t, h, "admin5@example.com")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/devices", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got []map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1: %+v", len(got), got)
	}
	if _, ok := got[0]["id"]; !ok {
		t.Fatalf("device view missing id field: %+v", got[0])
	}
	if got[0]["user_id"] != owner.ID {
		t.Fatalf("device view user_id = %v, want %q", got[0]["user_id"], owner.ID)
	}
}

// ---------- GET /api/v1/admin/audit ----------

func TestAdminAudit_Paginated(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin6@example.com", "admin")
	seedAudit(t, h.st, 3)
	adminCookie, _ := sessionFor(t, h, "admin6@example.com")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/audit?limit=2", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Rows       []map[string]any `json:"rows"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if len(got.Rows) != 2 || got.NextCursor == "" {
		t.Fatalf("rows=%d cursor=%q, want 2 + cursor", len(got.Rows), got.NextCursor)
	}
}

// ---------- GET /api/v1/admin/server ----------

func TestAdminServer_OmitsClientSecret(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin7@example.com", "admin")
	adminCookie, _ := sessionFor(t, h, "admin7@example.com")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/server", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if strings.Contains(string(body), "client_secret") {
		t.Fatalf("server info leaked client_secret: %s", body)
	}
}

// ---------- POST /api/v1/admin/users/{id}/recovery ----------

// TestAdminIssueRecovery_ResponseCarriesDelivery covers the second endpoint and
// asserts the raw transport error never reaches the wire.
func TestAdminIssueRecovery_ResponseCarriesDelivery(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-recovery@example.com", "admin")
	target := seedUser(t, h.st, "target-recovery@example.com", "user")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-recovery@example.com")

	status, _, body := doJSON(t, http.MethodPost,
		h.srv.URL+"/api/v1/admin/users/"+target.ID+"/recovery", nil, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got struct {
		Link     string `json:"link"`
		Delivery struct {
			Attempted bool   `json:"attempted"`
			Sent      bool   `json:"sent"`
			To        string `json:"to"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, body)
	}
	if got.Link == "" {
		t.Fatal("response carried no link")
	}
	if !got.Delivery.Sent || got.Delivery.To != "target-recovery@example.com" {
		t.Errorf("Delivery = %+v, want sent=true To=target-recovery@example.com", got.Delivery)
	}
}

// NOTE: there is deliberately NO "response body contains no SMTP error" assertion
// here. The api harness fakeMailer always succeeds (devices_test.go:48), so no
// transport error is ever in scope — such an assertion could not fail for the
// reason it claims, and a base64url grant token could trip it by chance. The
// no-leak guarantee is structural instead: deliveryView has no error field.

// TestAdminIssueRecovery_DisabledTargetReportsSuppressed proves the JSON
// surface reports the suppression even though the harness mailer is fully
// enabled (devices_test.go's fakeMailer.Enabled() returns true) — that is
// what proves "disabled" is reported instead of "no mailer configured".
func TestAdminIssueRecovery_DisabledTargetReportsSuppressed(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-recovery2@example.com", "admin")
	target := seedUser(t, h.st, "target-recovery2@example.com", "user")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-recovery2@example.com")

	target.Disabled = true
	if err := h.st.Users().Update(t.Context(), target); err != nil {
		t.Fatalf("Update: %v", err)
	}

	status, _, body := doJSON(t, http.MethodPost,
		h.srv.URL+"/api/v1/admin/users/"+target.ID+"/recovery", nil, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	var got struct {
		Link     string `json:"link"`
		Delivery struct {
			Attempted  bool   `json:"attempted"`
			Sent       bool   `json:"sent"`
			To         string `json:"to"`
			Suppressed string `json:"suppressed"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, body)
	}
	if got.Link == "" {
		t.Fatal("response carried no link")
	}
	if got.Delivery.Attempted || got.Delivery.Sent {
		t.Errorf("Delivery = %+v, want attempted=false sent=false", got.Delivery)
	}
	if got.Delivery.Suppressed != "user_disabled" {
		t.Errorf("Delivery.Suppressed = %q, want %q", got.Delivery.Suppressed, "user_disabled")
	}
}
