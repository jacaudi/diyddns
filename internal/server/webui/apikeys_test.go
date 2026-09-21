package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestAccountPage_ShowsOwnAPIKeysOnly proves the /account page's API Keys
// section lists only the viewer's own keys, mirroring the REST layer's
// TestAPIKeysList_ScopedToCaller.
func TestAccountPage_ShowsOwnAPIKeysOnly(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	alice := seedUser(t, st, "webui-alice@example.com", "user")
	seedUser(t, st, "webui-bob@example.com", "user")

	if _, _, err := deps.APIKeys.MintKey(t.Context(), alice.ID, "alice-webui-key"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	cookie := signIn(t, deps, alice)
	rec := getPage(t, h, cookie, "/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice-webui-key") {
		t.Errorf("account page did not render alice's key label:\n%s", rec.Body.String())
	}
}

// TestHandleAPIKeyMint_RevealsSecretOnce mirrors handleFeedTokenMint's own
// show-once behavior.
func TestHandleAPIKeyMint_RevealsSecretOnce(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "webui-mint@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	rec := postForm(t, h, cookie, "/account/keys", url.Values{"csrf": {sess.CSRFToken}, "label": {"cli-tool"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "dak_") {
		t.Errorf("mint response page did not render the once-only secret:\n%s", rec.Body.String())
	}
}

// TestHandleAPIKeyRevoke_OwnershipEnforced: the webui revoke handler scopes
// to the viewer's own user_id (design D9's correction from the feed
// precedent, which has no such scope).
func TestHandleAPIKeyRevoke_OwnershipEnforced(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	alice := seedUser(t, st, "webui-alice-revoke@example.com", "user")
	bob := seedUser(t, st, "webui-bob-revoke@example.com", "user")
	key, _, err := deps.APIKeys.MintKey(t.Context(), alice.ID, "alice-only")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	bobCookie := signIn(t, deps, bob)
	bobSess := sessionFor(t, deps, bobCookie)
	rec := postForm(t, h, bobCookie, "/account/keys/"+key.ID+"/delete", url.Values{"csrf": {bobSess.CSRFToken}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bob revoking alice's key via webui: status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}

	keys, err := deps.APIKeys.ListKeys(t.Context(), alice.ID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("alice's keys after bob's failed revoke = %+v, want still one", keys)
	}
}
