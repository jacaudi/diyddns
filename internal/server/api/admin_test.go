package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// seedAdminUser creates a user with role "admin" and an argon2id password
// hash. Mirrors seedAuthUserWithPassword (auth_ops_test.go) but sets
// Role: "admin" — kept as a separate helper rather than adding a role
// parameter to the shared one, since that would force every existing
// non-admin call site to change for a need only this file has.
func seedAdminUser(t *testing.T, st *store.Store, email, password string) store.User {
	t.Helper()
	hash, err := auth.HashPassword(password, auth.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := st.Users().Create(context.Background(), store.User{Email: email, Role: "admin", PasswordHash: hash})
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	return u
}

// seedAudit appends n audit-log rows so admin/audit pagination has rows to
// walk. The rows' content is irrelevant to the pagination assertions.
func seedAudit(t *testing.T, st *store.Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := st.AuditLog().Append(t.Context(), store.AuditEntry{EventType: "test.event"}); err != nil {
			t.Fatalf("seed audit %d: %v", i, err)
		}
	}
}

// ---------- GET /api/v1/admin/users ----------

func TestAdminListUsers_RequiresAdmin(t *testing.T) {
	h := newFullHarness(t)
	seedAdminUser(t, h.st, "admin1@example.com", "correct horse battery staple")
	seedAuthUserWithPassword(t, h.st, "user1@example.com", "correct horse battery staple")

	// Non-admin -> 403
	userCookie, _ := loginAndGetCSRF(t, h, "user1@example.com", "correct horse battery staple")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil, userCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("user: status = %d, want 403, body=%s", status, body)
	}

	// Admin -> 200
	adminCookie, _ := loginAndGetCSRF(t, h, "admin1@example.com", "correct horse battery staple")
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
	seedAdminUser(t, h.st, "admin2@example.com", "correct horse battery staple")
	seedAuthUserWithPassword(t, h.st, "user2@example.com", "correct horse battery staple")
	adminCookie, adminCSRF := loginAndGetCSRF(t, h, "admin2@example.com", "correct horse battery staple")
	userCookie, userCSRF := loginAndGetCSRF(t, h, "user2@example.com", "correct horse battery staple")

	newUser := map[string]string{"email": "n@x.com", "password": "correcthorse12", "role": "user"}

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

	// Admin + CSRF -> 200
	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users", map[string]string{
		"email": "n2@x.com", "password": "correcthorse12", "role": "user",
	}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("with csrf: status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode create response: %v, body=%s", err, body)
	}
	if got.Email != "n2@x.com" {
		t.Fatalf("email = %q, want n2@x.com", got.Email)
	}
}

// ---------- PATCH /api/v1/admin/users/{id} ----------

func TestAdminUpdateUser_LastAdmin_Conflict(t *testing.T) {
	h := newFullHarness(t)
	admin := seedAdminUser(t, h.st, "admin3@example.com", "correct horse battery staple")
	adminCookie, csrf := loginAndGetCSRF(t, h, "admin3@example.com", "correct horse battery staple")

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
	seedAdminUser(t, h.st, "admin4@example.com", "correct horse battery staple")
	target := seedAuthUserWithPassword(t, h.st, "target4@example.com", "correct horse battery staple")
	adminCookie, csrf := loginAndGetCSRF(t, h, "admin4@example.com", "correct horse battery staple")

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
	seedAdminUser(t, h.st, "admin5@example.com", "correct horse battery staple")
	owner := seedAuthUserWithPassword(t, h.st, "owner5@example.com", "correct horse battery staple")
	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: owner.ID, Label: "dev"}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	adminCookie, _ := loginAndGetCSRF(t, h, "admin5@example.com", "correct horse battery staple")

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
	seedAdminUser(t, h.st, "admin6@example.com", "correct horse battery staple")
	seedAudit(t, h.st, 3)
	adminCookie, _ := loginAndGetCSRF(t, h, "admin6@example.com", "correct horse battery staple")

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
	seedAdminUser(t, h.st, "admin7@example.com", "correct horse battery staple")
	adminCookie, _ := loginAndGetCSRF(t, h, "admin7@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/server", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if strings.Contains(string(body), "client_secret") {
		t.Fatalf("server info leaked client_secret: %s", body)
	}
}
