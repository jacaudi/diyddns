package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedCredential gives u a passkey row so the account reads as registered.
func seedCredential(t *testing.T, st *store.Store, u store.User) {
	t.Helper()
	if _, err := st.WebAuthnCredentials().Create(t.Context(), store.WebAuthnCredential{
		CredentialID: []byte("cred-" + u.ID), UserID: u.ID, CredentialJSON: []byte("{}"), Name: "k", CreatedAt: store.NowUnix(),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

// seedGrant gives u a live registration grant.
func seedGrant(t *testing.T, st *store.Store, u store.User, hash, reason string, expiresAt int64) {
	t.Helper()
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: hash, UserID: u.ID, Reason: reason, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// findView returns the JSON object for id from a list response.
func findView(t *testing.T, body []byte, id string) map[string]any {
	t.Helper()
	var views []map[string]any
	if err := json.Unmarshal(body, &views); err != nil {
		t.Fatalf("decode list: %v, body=%s", err, body)
	}
	for _, v := range views {
		if v["id"] == id {
			return v
		}
	}
	t.Fatalf("user %s missing from list: %s", id, body)
	return nil
}

func TestAdminUsers_ReportRegistrationStatus(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-reg@example.com", "admin")
	registered := seedUser(t, h.st, "registered@example.com", "user")
	seedCredential(t, h.st, registered)
	seedGrant(t, h.st, registered, "h-selfservice", "recovery", store.NowUnix()+600)
	invited := seedUser(t, h.st, "invited@example.com", "user")
	exp := store.NowUnix() + 600
	seedGrant(t, h.st, invited, "h-invited", "invite", exp)
	lapsed := seedUser(t, h.st, "lapsed@example.com", "user")
	cookie, _ := sessionFor(t, h, "admin-reg@example.com")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, body=%s", status, body)
	}
	reg := findView(t, body, registered.ID)
	if reg["registration_status"] != "registered" {
		t.Errorf("registered: registration_status = %v", reg["registration_status"])
	}
	if _, ok := reg["registration_link_expires_at"]; ok {
		t.Errorf("registered: registration_link_expires_at present (%v), want omitted (D14)", reg["registration_link_expires_at"])
	}
	inv := findView(t, body, invited.ID)
	if inv["registration_status"] != "invited" {
		t.Errorf("invited: registration_status = %v", inv["registration_status"])
	}
	if got, _ := inv["registration_link_expires_at"].(float64); int64(got) != exp {
		t.Errorf("invited: registration_link_expires_at = %v, want %d", inv["registration_link_expires_at"], exp)
	}
	if lap := findView(t, body, lapsed.ID); lap["registration_status"] != "link_expired" {
		t.Errorf("lapsed: registration_status = %v", lap["registration_status"])
	}
	// Every row carries an in-enum status: huma does not validate responses,
	// so this is the check that D5's "an entry for every user" holds end to end.
	var all []map[string]any
	if err := json.Unmarshal(body, &all); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	valid := map[any]bool{"registered": true, "invited": true, "recovery_pending": true, "link_expired": true}
	for _, v := range all {
		if !valid[v["registration_status"]] {
			t.Errorf("user %v: registration_status = %v, not in the enum", v["id"], v["registration_status"])
		}
	}

	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users/"+invited.ID, nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("get: status = %d, body=%s", status, body)
	}
	var one map[string]any
	if err := json.Unmarshal(body, &one); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if one["registration_status"] != "invited" {
		t.Errorf("get: registration_status = %v, want invited", one["registration_status"])
	}
}

// TestAdminUserMutations_ReportStatusAfterTheChange proves create, update and
// set-email compute status AFTER their mutation (design §4.2).
func TestAdminUserMutations_ReportStatusAfterTheChange(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-mut@example.com", "admin")
	cookie, csrf := sessionFor(t, h, "admin-mut@example.com")

	// Create mints an invite, so the new account reads invited.
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/users",
		map[string]string{"email": "fresh@example.com", "role": "user"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("create: status = %d, body=%s", status, body)
	}
	var created struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.User["registration_status"] != "invited" {
		t.Errorf("create: registration_status = %v, want invited", created.User["registration_status"])
	}
	id, _ := created.User["id"].(string)

	// Update leaves the invite alone.
	status, _, body = doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/admin/users/"+id,
		map[string]string{"role": "admin"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("update: status = %d, body=%s", status, body)
	}
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated["registration_status"] != "invited" {
		t.Errorf("update: registration_status = %v, want invited", updated["registration_status"])
	}

	// Set-email deletes outstanding grants (#131 D8), so the account reads link_expired.
	status, _, body = doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/admin/users/"+id+"/email",
		map[string]string{"email": "moved@example.com"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("set email: status = %d, body=%s", status, body)
	}
	var moved struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(body, &moved); err != nil {
		t.Fatalf("decode set email: %v", err)
	}
	if moved.User["registration_status"] != "link_expired" {
		t.Errorf("set email: registration_status = %v, want link_expired", moved.User["registration_status"])
	}
}
