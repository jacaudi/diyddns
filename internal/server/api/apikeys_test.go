package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAPIKeysList_RequiresSession(t *testing.T) {
	h := newFullHarness(t)
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/account/keys", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("anon: status = %d, want 401, body=%s", status, body)
	}
}

func TestAPIKeysMint_RequiresCSRF(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "apikey-mint1@example.com", "user")
	cookie, csrf := sessionFor(t, h, "apikey-mint1@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "laptop"}, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("no csrf: status = %d, want 403, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "laptop"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("with csrf: status = %d, want 200, body=%s", status, body)
	}
}

// TestAPIKeysMint_RevealsSecretOnceThenListNever mirrors
// TestFeedTokensMint_RevealsSecretOnceThenListNever exactly, scoped to a
// single user's own key instead of a global admin list.
func TestAPIKeysMint_RevealsSecretOnceThenListNever(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "apikey-mint2@example.com", "user")
	cookie, csrf := sessionFor(t, h, "apikey-mint2@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "laptop"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("mint: status = %d, want 200, body=%s", status, body)
	}
	var minted struct {
		Key struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"key"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, body)
	}
	if minted.Secret == "" || !strings.HasPrefix(minted.Secret, "dak_") {
		t.Fatalf("mint response secret = %q, want a non-empty dak_-prefixed value", minted.Secret)
	}
	if minted.Key.Label != "laptop" || minted.Key.ID == "" {
		t.Fatalf("mint response = %+v, want non-empty key.id and key.label=laptop", minted)
	}

	status, _, listBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/account/keys", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, want 200, body=%s", status, listBody)
	}
	if strings.Contains(string(listBody), minted.Secret) || strings.Contains(string(listBody), "\"secret\"") {
		t.Fatalf("list response leaked a secret: %s", listBody)
	}
	var rows []map[string]any
	if err := json.Unmarshal(listBody, &rows); err != nil {
		t.Fatalf("decode list: %v, body=%s", err, listBody)
	}
	if len(rows) != 1 || rows[0]["id"] != minted.Key.ID {
		t.Fatalf("list rows = %+v, want one row for the minted key", rows)
	}
}

// TestAPIKeysList_ScopedToCaller: two users, each with their own key --
// each session's list shows only their own, never the other's.
func TestAPIKeysList_ScopedToCaller(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "apikey-alice@example.com", "user")
	seedUser(t, h.st, "apikey-bob@example.com", "user")
	aliceCookie, aliceCSRF := sessionFor(t, h, "apikey-alice@example.com")
	bobCookie, bobCSRF := sessionFor(t, h, "apikey-bob@example.com")

	if status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "alice-key"}, aliceCookie, aliceCSRF); status != http.StatusOK {
		t.Fatalf("mint alice: status = %d, body=%s", status, body)
	}
	if status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "bob-key"}, bobCookie, bobCSRF); status != http.StatusOK {
		t.Fatalf("mint bob: status = %d, body=%s", status, body)
	}

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/account/keys", nil, aliceCookie, "")
	if status != http.StatusOK {
		t.Fatalf("list alice: status = %d, body=%s", status, body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 1 || rows[0]["label"] != "alice-key" {
		t.Fatalf("alice's list = %+v, want exactly her one key, not bob's", rows)
	}
}

// TestAPIKeysRevoke_OwnershipAs404: bob cannot revoke alice's key, and the
// failure is indistinguishable from a nonexistent id (404, not 403) --
// design D8's ownership-as-404 rule.
func TestAPIKeysRevoke_OwnershipAs404(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "apikey-alice2@example.com", "user")
	seedUser(t, h.st, "apikey-bob2@example.com", "user")
	aliceCookie, aliceCSRF := sessionFor(t, h, "apikey-alice2@example.com")
	bobCookie, bobCSRF := sessionFor(t, h, "apikey-bob2@example.com")

	_, _, mintBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "alice-key2"}, aliceCookie, aliceCSRF)
	var minted struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(mintBody, &minted); err != nil {
		t.Fatalf("decode: %v, body=%s", err, mintBody)
	}

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/account/keys/"+minted.Key.ID, nil, bobCookie, bobCSRF)
	if status != http.StatusNotFound {
		t.Fatalf("bob revoking alice's key: status = %d, want 404, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/account/keys/"+minted.Key.ID, nil, aliceCookie, aliceCSRF)
	if status != http.StatusNoContent {
		t.Fatalf("alice revoking her own key: status = %d, want 204, body=%s", status, body)
	}
}

func TestAPIKeysMint_EmptyLabelRejected(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "apikey-empty@example.com", "user")
	cookie, csrf := sessionFor(t, h, "apikey-empty@example.com")

	for _, label := range []string{"", "   "} {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
			map[string]string{"label": label}, cookie, csrf)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("label %q: status = %d, want 422, body=%s", label, status, body)
		}
	}
}
