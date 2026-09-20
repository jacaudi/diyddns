package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// adminDeviceFixture seeds an admin, a second user and that user's device
// with one history row, and signs the admin in. Every request goes through
// getPage/postForm (endpoints_test.go), so httptest is not imported here.
func adminDeviceFixture(t *testing.T) (Deps, *store.Store, *http.Cookie, store.Session, store.User, store.Device) {
	t.Helper()
	deps, st := testDeps(t)
	admin := seedUser(t, st, "admin@example.com", "admin")
	owner := seedUser(t, st, "mark@example.com", "user")
	dev := seedDevice(t, st, owner.ID, "marks-pi")
	if err := st.Devices().UpdateIP(t.Context(), dev.ID, "203.0.113.7", "2001:db8::7", "v1", "pi", "linux", store.NowUnix()); err != nil {
		t.Fatalf("update ip: %v", err)
	}
	seedHistory(t, st, dev.ID, "203.0.113.7", "2001:db8::7", "diyddns-client/1.4.0")
	cookie := signIn(t, deps, admin)
	return deps, st, cookie, sessionFor(t, deps, cookie), owner, dev
}

func auditRowCount(t *testing.T, st *store.Store) int {
	t.Helper()
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{}, "", 1000)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	return len(page.Rows)
}

// TestAdminDevice_RendersAForeignDeviceReadOnly is #132's happy path: an
// admin opens someone else's device and sees its state, addresses, owner and
// history, with exactly one action (disable) and none of the owner-only ones.
func TestAdminDevice_RendersAForeignDeviceReadOnly(t *testing.T) {
	deps, st, cookie, _, owner, dev := adminDeviceFixture(t)
	h, _ := New(deps)
	// Six rows in total (the fixture seeded one; DeviceRepo.UpdateIP writes
	// no ip_history row -- only seedHistory does): the preview shows exactly
	// the five newest, as the owner's page does.
	for range 5 {
		seedHistory(t, st, dev.ID, "203.0.113.7", "2001:db8::7", "diyddns-client/1.4.0")
	}
	before := auditRowCount(t, st)

	rec := getPage(t, h, cookie, "/admin/devices/"+dev.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"marks-pi",
		`<a href="/admin/users/` + owner.ID + `">mark@example.com</a>`,
		"203.0.113.7", "2001:db8::7",
		"diyddns-client/1.4.0",
		`href="/admin/devices/` + dev.ID + `/history"`,
		`action="/admin/devices/` + dev.ID + `/enabled"`,
		`name="disabled" value="true"`,
		`<a href="/admin/devices">All Devices</a>`,
		"only available to the device's owner",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"/rename", "/rotate-secret", "/delete",
		"Show the new secret", "credentials.json", "sealed-test-secret",
		`href="/devices/` + dev.ID,
		`href=""`,
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("body must not contain %q", forbidden)
		}
	}
	if n := strings.Count(body, `<form method="post"`); n != 1 {
		t.Errorf("%d POST forms, want exactly 1 (disable)", n)
	}
	if n := strings.Count(body, `data-label="When"`); n != 5 {
		t.Errorf("%d history preview rows, want the five newest", n)
	}
	if after := auditRowCount(t, st); after != before {
		t.Errorf("audit rows %d → %d on an admin READ, want unchanged", before, after)
	}
}

func TestAdminDevice_NonAdminIsForbidden_SignedOutIsRedirected(t *testing.T) {
	deps, st, _, _, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)
	user := seedUser(t, st, "plain@example.com", "user")
	userCookie := signIn(t, deps, user)
	userSess := sessionFor(t, deps, userCookie)

	for _, path := range []string{"/admin/devices/" + dev.ID, "/admin/devices/" + dev.ID + "/history"} {
		if rec := getPage(t, h, userCookie, path); rec.Code != http.StatusForbidden {
			t.Errorf("non-admin GET %s = %d, want 403", path, rec.Code)
		}
		if rec := getPage(t, h, nil, path); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("signed-out GET %s = %d → %q, want 303 → /login", path, rec.Code, rec.Header().Get("Location"))
		}
	}

	// The write boundary (#132 D7): a signed-in non-admin with a VALID CSRF
	// token is refused by the role check, and the device is untouched.
	rec := postForm(t, h, userCookie, "/admin/devices/"+dev.ID+"/enabled", url.Values{"csrf": {userSess.CSRFToken}, "disabled": {"true"}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin POST enabled = %d, want 403", rec.Code)
	}
	if got, _ := st.Devices().GetByID(t.Context(), dev.ID); got.Disabled {
		t.Error("a non-admin disabled the device")
	}
}

func TestAdminDevice_UnknownIs404(t *testing.T) {
	deps, _, cookie, sess, _, _ := adminDeviceFixture(t)
	h, _ := New(deps)
	for _, path := range []string{"/admin/devices/no-such-device", "/admin/devices/no-such-device/history"} {
		rec := getPage(t, h, cookie, path)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "That device does not exist.") {
			t.Errorf("GET %s: status = %d, want 404 with the shared copy", path, rec.Code)
		}
	}
	// The POST maps the service's ErrNotFound itself (it resolves the device
	// once, inside SetDeviceEnabled) and must answer the same 404, not a 500.
	rec := postForm(t, h, cookie, "/admin/devices/no-such-device/enabled", url.Values{"csrf": {sess.CSRFToken}, "disabled": {"true"}})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "That device does not exist.") {
		t.Errorf("POST enabled on an unknown device: status = %d, want 404 with the shared copy", rec.Code)
	}
}

func TestAdminDeviceHistory_StaysUnderTheAdminRoutes(t *testing.T) {
	deps, st, cookie, _, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)
	for range historyPageSize {
		seedHistory(t, st, dev.ID, "203.0.113.7", "", "diyddns-client/1.4.0")
	}
	before := auditRowCount(t, st)

	rec := getPage(t, h, cookie, "/admin/devices/"+dev.ID+"/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The history read is DeviceService.History scoped by the OWNER's id
	// (#132 D6); it must write nothing, exactly like the detail read.
	if after := auditRowCount(t, st); after != before {
		t.Errorf("audit rows %d → %d on an admin history READ, want unchanged", before, after)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<a href="/admin/devices">All Devices</a>`,
		`<a href="/admin/devices/` + dev.ID + `">marks-pi</a>`,
		"IP history",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, `href="/devices/`) {
		t.Error("the admin history page links into the owner's route family")
	}
	next, err := url.Parse(nextPagerURL(t, body))
	if err != nil {
		t.Fatalf("parse Next URL: %v", err)
	}
	if want := "/admin/devices/" + dev.ID + "/history"; next.Path != want {
		t.Errorf("Next path = %q, want %q", next.Path, want)
	}

	bad := getPage(t, h, cookie, "/admin/devices/"+dev.ID+"/history?cursor=not-a-cursor")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor status = %d, want 400", bad.Code)
	}
	if !strings.Contains(bad.Body.String(), `href="/admin/devices/`+dev.ID+`/history"`) {
		t.Error("the bad-cursor page's first-page link does not point at the admin history path")
	}
}

func TestAdminDeviceSetEnabled_DisablesThenEnables(t *testing.T) {
	deps, st, cookie, sess, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)

	rec := postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/enabled", url.Values{"csrf": {sess.CSRFToken}, "disabled": {"true"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/devices/"+dev.ID {
		t.Fatalf("disable = %d → %q, want 303 → /admin/devices/%s", rec.Code, rec.Header().Get("Location"), dev.ID)
	}
	if got, _ := st.Devices().GetByID(t.Context(), dev.ID); !got.Disabled {
		t.Fatal("device not disabled")
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "device.disabled_by_admin"}, "", 10)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].IP != "127.0.0.1" {
		t.Fatalf("device.disabled_by_admin rows = %+v (%v), want one carrying the session IP 127.0.0.1", page.Rows, err)
	}

	after := getPage(t, h, cookie, "/admin/devices/"+dev.ID).Body.String()
	if !strings.Contains(after, `name="disabled" value="false"`) || !strings.Contains(after, ">Enable<") {
		t.Error("after a disable the page must offer Enable")
	}

	rec = postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/enabled", url.Values{"csrf": {sess.CSRFToken}, "disabled": {"false"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("enable = %d, want 303", rec.Code)
	}
	if got, _ := st.Devices().GetByID(t.Context(), dev.ID); got.Disabled {
		t.Fatal("device not re-enabled")
	}
}

// TestAdminDevice_OwnerOnlyActionsAreNotRouted is the enforcement of #132 D3:
// there is no admin rename, rotate-secret or delete route at all, so a
// crafted POST with a valid CSRF token reaches ServeMux's 404, not a handler.
func TestAdminDevice_OwnerOnlyActionsAreNotRouted(t *testing.T) {
	deps, st, cookie, sess, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)
	for _, action := range []string{"rename", "rotate-secret", "delete"} {
		rec := postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/"+action, url.Values{
			"csrf": {sess.CSRFToken}, "label": {"renamed-by-admin"}, "confirm_label": {"marks-pi"},
		})
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST /admin/devices/{id}/%s = %d, want 404 (not routed)", action, rec.Code)
		}
	}
	got, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("the device was deleted: %v", err)
	}
	if got.Label != "marks-pi" || got.SecretHash != "sealed-test-secret" || got.Disabled {
		t.Errorf("the device was modified: %+v", got)
	}
}
