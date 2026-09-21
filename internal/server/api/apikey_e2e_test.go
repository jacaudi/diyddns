package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestAPIKey_EndToEnd_MintUseCapRevoke walks design §3's full end-to-end
// scenario in one test: mint via REST, use the key on a capped route
// successfully, confirm it 403s against an admin route even when minted by
// an admin, confirm revoke makes it stop working immediately, and confirm
// it can never touch passkeys or email regardless of any of the above.
func TestAPIKey_EndToEnd_MintUseCapRevoke(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "e2e-admin@example.com", "admin")
	cookie, csrf := sessionFor(t, h, "e2e-admin@example.com")

	// 1. Mint via REST.
	status, _, mintBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "e2e-key"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("mint: status = %d, want 200, body=%s", status, mintBody)
	}
	var minted struct {
		Key    struct{ ID string } `json:"key"`
		Secret string              `json:"secret"`
	}
	if err := json.Unmarshal(mintBody, &minted); err != nil {
		t.Fatalf("decode mint: %v, body=%s", err, mintBody)
	}

	// 2. Use it on a capped route successfully.
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/devices", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+minted.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /devices with the key = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// 3. 403 against an admin route, even though the minting user IS an admin.
	req, _ = http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Secret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /admin/users with an admin's own key = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Cannot touch passkeys or email, regardless of any of the above.
	for _, path := range []string{"/api/v1/account/passkeys", "/api/v1/account/email"} {
		method := http.MethodGet
		if path == "/api/v1/account/email" {
			method = http.MethodPost
		}
		req, _ = http.NewRequest(method, h.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+minted.Secret)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with the key = %d, want 401", method, path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 5. Revoke; the key stops working immediately.
	status, _, revokeBody := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/account/keys/"+minted.Key.ID, nil, cookie, csrf)
	if status != http.StatusNoContent {
		t.Fatalf("revoke: status = %d, want 204, body=%s", status, revokeBody)
	}

	req, _ = http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Secret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /devices with a revoked key = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}
