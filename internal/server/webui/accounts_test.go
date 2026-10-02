package webui

import (
	"net/http"
	"strings"
	"testing"
)

// TestAdminUsers_TilesNameWhatTheyCount covers #189: the page is called
// Accounts, and each of its four tiles names what it counts, so a disabled
// account is not read as a disabled device. The four counts are all different
// so a tile wired to the wrong number fails.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUsers_TilesNameWhatTheyCount(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	off := seedUser(t, st, "off@example.com", "user")
	if err := st.Users().SetDisabled(t.Context(), off.ID, true); err != nil {
		t.Fatalf("disable account: %v", err)
	}
	for _, label := range []string{"on-1", "on-2"} {
		seedDevice(t, st, admin.ID, label)
	}
	for _, label := range []string{"off-1", "off-2", "off-3"} {
		d := seedDevice(t, st, admin.ID, label)
		if err := st.Devices().SetDisabled(t.Context(), d.ID, true); err != nil {
			t.Fatalf("disable device %q: %v", label, err)
		}
	}

	rec := getPage(t, h, signIn(t, deps, admin), "/admin/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<div class="grid cols-4 stats">`,
		`<div class="label">Accounts</div><div class="value">2</div>`,
		`<div class="label">Devices</div><div class="value">5</div>`,
		`<div class="label">Disabled accounts</div><div class="value">1</div>`,
		`<div class="label">Disabled devices</div><div class="value">3</div>`,
		`<h1>Accounts</h1>`,
		`<title>Accounts · DIYDDNS</title>`,
		`href="/admin/users">Accounts</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("accounts page missing %q", want)
		}
	}
	for _, gone := range []string{`<div class="label">Disabled</div>`, `>Users<`} {
		if strings.Contains(body, gone) {
			t.Errorf("accounts page still contains %q", gone)
		}
	}
}

// TestAdminUser_BreadcrumbsSayAccounts covers #189 on the two pages below the
// list: their breadcrumb names the list the way the list names itself.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUser_BreadcrumbsSayAccounts(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	cookie := signIn(t, deps, admin)

	for _, path := range []string{"/admin/users/new", "/admin/users/" + target.ID} {
		t.Run(path, func(t *testing.T) {
			rec := getPage(t, h, cookie, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			const want = `<div class="breadcrumb"><a href="/admin/users">Accounts</a>`
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("%s missing %q", path, want)
			}
		})
	}
}
