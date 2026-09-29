package webui

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/service"
)

// TestAdminPages_StateTheConfiguredLinkTTL is the web half of the spec's
// "no hard-coded window" test (#179): with a non-default TTL, every admin
// surface that states a registration link's lifetime says "45 minutes" and
// none still says "one hour".
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminPages_StateTheConfiguredLinkTTL(t *testing.T) {
	deps, st := testDeps(t)
	audit := service.NewAuditWriter(st)
	passkeys, err := service.NewPasskeyService(st, deps.Sessions, bytes.Repeat([]byte{0x24}, 32),
		deps.Cfg.Auth.WebAuthn, "localhost", "http://localhost", audit, deps.Log)
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	deps.Grants = service.NewGrantService(st, passkeys, nil, deps.Cfg.Server.BaseURL, audit, deps.Log, 45*time.Minute)
	deps.Admin = service.NewAdminService(st, audit, deps.Grants, service.NopDeviceNotifier{}, nil, deps.Log)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	seedPasskey(t, st, target.ID, "existing key")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	check := func(name, body string) {
		t.Helper()
		if !strings.Contains(body, "45 minutes") {
			t.Errorf("%s does not state the configured window", name)
		}
		if strings.Contains(body, "one hour") {
			t.Errorf("%s still says \"one hour\"", name)
		}
	}

	edit := getPage(t, h, cookie, "/admin/users/"+target.ID)
	if edit.Code != http.StatusOK {
		t.Fatalf("edit page status = %d", edit.Code)
	}
	check("user edit page (danger zone)", edit.Body.String())

	rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/recovery",
		url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {"target@example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery status = %d; body=%s", rec.Code, rec.Body.String())
	}
	check("recovery reveal", rec.Body.String())

	rec = postForm(t, h, cookie, "/admin/users/new",
		url.Values{"csrf": {sess.CSRFToken}, "email": {"newbie@example.com"}, "role": {"user"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("invite status = %d; body=%s", rec.Code, rec.Body.String())
	}
	check("invite reveal", rec.Body.String())
}
