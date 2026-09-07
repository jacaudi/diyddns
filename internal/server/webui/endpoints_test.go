package webui

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// dataCopyRe extracts the value of a copyValue partial's data-copy attribute,
// so a test can recover exactly what a "Copy" button would put on the
// clipboard without hand-parsing the surrounding markup.
var dataCopyRe = regexp.MustCompile(`data-copy="([^"]*)"`)

// seedEndpoint inserts a server-global notification endpoint, going through
// the store directly rather than NotificationService.Create: these tests care
// about rendering and routing, not about the create ceremony.
func seedEndpoint(t *testing.T, st *store.Store, label, rawURL string, enabled bool) store.NotificationEndpoint {
	t.Helper()
	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		Label:        label,
		URL:          rawURL,
		SecretSealed: "sealed-test-secret",
		Enabled:      enabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := st.NotificationEndpoints().Create(t.Context(), ep); err != nil {
		t.Fatalf("seed endpoint %q: %v", label, err)
	}
	if !enabled {
		if err := st.NotificationEndpoints().SetEnabled(t.Context(), ep.ID, false); err != nil {
			t.Fatalf("seed endpoint %q: disable: %v", label, err)
		}
	}
	ep.Enabled = enabled
	return ep
}

// seedDelivery inserts a notification_deliveries row directly, so a test can
// pin an exact status/failure-class/attempts combination without driving the
// worker.
func seedDelivery(t *testing.T, st *store.Store, endpointID, eventType, status, lastFailure string, attempts int) store.NotificationDelivery {
	t.Helper()
	d := store.NotificationDelivery{
		EndpointID:  endpointID,
		EventType:   eventType,
		EventID:     1,
		Payload:     []byte(`{"type":"` + eventType + `"}`),
		Attempts:    attempts,
		Status:      status,
		LastFailure: lastFailure,
	}
	if err := st.NotificationDeliveries().Enqueue(t.Context(), d); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), endpointID, 100)
	if err != nil {
		t.Fatalf("list seeded deliveries: %v", err)
	}
	return rows[len(rows)-1]
}

// enableNotifications is the one line every endpoint-route test needs:
// testDeps's zero-value config leaves notifications disabled.
func enableNotifications(deps *Deps) {
	deps.Cfg.Notifications.Enabled = true
}

// adminSession seeds an admin and signs them in; every endpoint route is
// admin-only since #106.
func adminSession(t *testing.T, deps Deps, st *store.Store, email string) (*http.Cookie, store.Session) {
	t.Helper()
	admin := seedUser(t, st, email, "admin")
	cookie := signIn(t, deps, admin)
	return cookie, sessionFor(t, deps, cookie)
}

func postForm(t *testing.T, h http.Handler, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getPage(t *testing.T, h http.Handler, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestCreateErrorMessage: specific text ONLY for the two causes proven safe
// (a conflict, or validateTarget's notify.ErrDenied); everything else comes
// back ok=false so the caller falls through to the generic, logged failure.
func TestCreateErrorMessage(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantOK       bool
		wantContains string
	}{
		{"conflict", fmt.Errorf("service.Create: %w", store.ErrConflict), true, "already exists"},
		{"denied target", fmt.Errorf("service.Create: %w", notify.ErrDenied), true, "That target was rejected"},
		{"raw store error", fmt.Errorf("service.Create: %w", errors.New("no such table: notification_endpoints")), false, ""},
		{"generate secret failure", fmt.Errorf("service.Create: %w", errors.New("crypto/rand: read failed")), false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, ok := createErrorMessage(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && !strings.Contains(msg, tc.wantContains) {
				t.Errorf("msg = %q, want it to contain %q", msg, tc.wantContains)
			}
			if !ok && msg != "" {
				t.Errorf("msg = %q, want empty when ok=false (caller must not render it)", msg)
			}
		})
	}
}

// TestDeliveryRows_RedeliverableMatchesStatusConsts: deliveryRows'
// Redeliverable flag and InsertRedelivery's own terminal-status SQL must
// agree on which statuses are redeliverable.
func TestDeliveryRows_RedeliverableMatchesStatusConsts(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{store.DeliveryPending, false},
		{store.DeliveryFailed, true},
		{store.DeliveryDelivered, true},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			rows := deliveryRows([]store.NotificationDelivery{{Status: tc.status}})
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1", len(rows))
			}
			if rows[0].Redeliverable != tc.want {
				t.Errorf("Redeliverable(%q) = %v, want %v", tc.status, rows[0].Redeliverable, tc.want)
			}
		})
	}
}

func TestEndpoints_ListRequiresSession(t *testing.T) {
	deps, _ := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)

	rec := getPage(t, h, nil, "/admin/endpoints")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d Location = %q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
}

// TestEndpoints_NonAdminIsForbidden: every endpoint route is admin-only
// since #106; a signed-in user gets 403, not a redirect and not a page.
func TestEndpoints_NonAdminIsForbidden(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	ep := seedEndpoint(t, st, "hook", "https://example.com/hook", true)
	usr := seedUser(t, st, "plain@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	if rec := getPage(t, h, cookie, "/admin/endpoints"); rec.Code != http.StatusForbidden {
		t.Errorf("GET /admin/endpoints as a user = %d, want 403", rec.Code)
	}
	if rec := getPage(t, h, cookie, "/admin/endpoints/"+ep.ID); rec.Code != http.StatusForbidden {
		t.Errorf("GET /admin/endpoints/{id} as a user = %d, want 403", rec.Code)
	}
	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"x"}, "url": {"https://example.com/x"}}
	if rec := postForm(t, h, cookie, "/admin/endpoints", form); rec.Code != http.StatusForbidden {
		t.Errorf("POST /admin/endpoints as a user = %d, want 403", rec.Code)
	}
}

// TestEndpoints_CreateShowsSecretOnceThenNever asserts the reveal renders in
// the POST response itself, and that the exact same secret value is absent
// from the very next GET of the list.
func TestEndpoints_CreateShowsSecretOnceThenNever(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "endpoints@example.com")

	form := url.Values{
		"csrf":  {sess.CSRFToken},
		"label": {"home-automation"},
		"url":   {"https://example.com/hooks/ddns"},
	}
	rec := postForm(t, h, cookie, "/admin/endpoints", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the reveal renders in the POST response), body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Shown once") || !strings.Contains(body, "home-automation") {
		t.Error("body missing the shown-once warning or the created endpoint's label")
	}
	m := dataCopyRe.FindStringSubmatch(body)
	if m == nil || m[1] == "" {
		t.Fatalf("no data-copy value found in the reveal:\n%s", body)
	}
	secret := m[1]

	rec2 := getPage(t, h, cookie, "/admin/endpoints")
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /admin/endpoints status = %d, want 200", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), secret) {
		t.Error("the secret leaked into a later render of the list")
	}
}

func TestEndpoints_MissingEndpointIsNotFound(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "admin@example.com")

	tests := []struct {
		name   string
		method string
		path   string
		form   url.Values
	}{
		{"detail", http.MethodGet, "/admin/endpoints/no-such-id", nil},
		{"set enabled", http.MethodPost, "/admin/endpoints/no-such-id/enabled", url.Values{"enabled": {"false"}}},
		{"delete", http.MethodPost, "/admin/endpoints/no-such-id/delete", url.Values{"confirm_label": {"x"}}},
		{"test", http.MethodPost, "/admin/endpoints/no-such-id/test", url.Values{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tt.method == http.MethodPost {
				tt.form.Set("csrf", sess.CSRFToken)
				rec = postForm(t, h, cookie, tt.path, tt.form)
			} else {
				rec = getPage(t, h, cookie, tt.path)
			}
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404", tt.method, tt.path, rec.Code)
			}
		})
	}
}

func TestEndpoints_MissingDeliveryRedeliverIsNotFound(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "admin@example.com")

	rec := postForm(t, h, cookie, "/admin/deliveries/999999/redeliver", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (every refusal is the same 404)", rec.Code)
	}
}

// TestEndpoints_RoutesAbsentWhenDisabled asserts the whole route group 404s
// when notifications are disabled — even for an admin.
func TestEndpoints_RoutesAbsentWhenDisabled(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	cookie, _ := adminSession(t, deps, st, "admin@example.com")

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/endpoints"},
		{http.MethodPost, "/admin/endpoints"},
		{http.MethodPost, "/admin/endpoints/some-id/enabled"},
		{http.MethodPost, "/admin/endpoints/some-id/test"},
		{http.MethodPost, "/admin/endpoints/some-id/delete"},
		{http.MethodGet, "/admin/endpoints/some-id"},
		{http.MethodPost, "/admin/deliveries/1/redeliver"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 when notifications.enabled is false", rec.Code)
			}
		})
	}
}

// TestEndpointDetail_RendersFailureClassNotRawError: the detail page renders
// only the fixed, coarse failure class, never anything that could carry raw
// upstream detail (design §5.8/§10.4).
func TestEndpointDetail_RendersFailureClassNotRawError(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, _ := adminSession(t, deps, st, "detail@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)

	classes := map[string]string{
		"blocked":     "Blocked by destination policy",
		"unreachable": "Unreachable",
		"tls":         "TLS error",
		"rejected":    "Rejected by target",
		"gone":        "Target removed (410)",
		"internal":    "Internal error",
	}
	for class := range classes {
		seedDelivery(t, st, ep.ID, "ip.changed", "failed", class, 3)
	}

	rec := getPage(t, h, cookie, "/admin/endpoints/"+ep.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for class, phrase := range classes {
		if !strings.Contains(body, phrase) {
			t.Errorf("body missing the mapped phrase %q for class %q", phrase, class)
		}
		if strings.Contains(body, class) {
			t.Errorf("body contains the raw failure class %q verbatim", class)
		}
	}
}

func TestEndpointDetail_UnknownFailureClassRendersUnknown(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, _ := adminSession(t, deps, st, "detail-unknown@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)
	const unrecognized = "some-future-class-not-in-the-switch"
	seedDelivery(t, st, ep.ID, "ip.changed", "failed", unrecognized, 3)

	rec := getPage(t, h, cookie, "/admin/endpoints/"+ep.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Unknown") || strings.Contains(rec.Body.String(), unrecognized) {
		t.Error("an unrecognised failure class must render as \"Unknown\" and never verbatim")
	}
}

func TestEndpoints_SetEnabledTogglesAndRedirects(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "toggle@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)

	rec := postForm(t, h, cookie, "/admin/endpoints/"+ep.ID+"/enabled", url.Values{"csrf": {sess.CSRFToken}, "enabled": {"false"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/endpoints/"+ep.ID {
		t.Fatalf("status = %d Location = %q", rec.Code, rec.Header().Get("Location"))
	}
	got, err := st.NotificationEndpoints().Get(t.Context(), ep.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Error("endpoint is still enabled after POST .../enabled with enabled=false")
	}
}

func TestEndpoints_DeleteRequiresTypedConfirmation(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "delete@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)

	t.Run("wrong confirmation leaves it in place", func(t *testing.T) {
		rec := postForm(t, h, cookie, "/admin/endpoints/"+ep.ID+"/delete", url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"not-the-label"}})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", rec.Code)
		}
		if _, err := st.NotificationEndpoints().Get(t.Context(), ep.ID); err != nil {
			t.Errorf("endpoint was deleted despite a mismatched confirmation: %v", err)
		}
	})
	t.Run("correct confirmation deletes it", func(t *testing.T) {
		rec := postForm(t, h, cookie, "/admin/endpoints/"+ep.ID+"/delete", url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {ep.Label}})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/endpoints" {
			t.Fatalf("status = %d Location = %q, body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		if _, err := st.NotificationEndpoints().Get(t.Context(), ep.ID); err == nil {
			t.Error("endpoint still exists after a correctly-confirmed delete")
		}
	})
}

func TestEndpoints_SendTest(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "sendtest@example.com")

	t.Run("enqueues one delivery for an enabled endpoint", func(t *testing.T) {
		ep := seedEndpoint(t, st, "enabled-hook", "https://example.com/hook-a", true)
		rec := postForm(t, h, cookie, "/admin/endpoints/"+ep.ID+"/test", url.Values{"csrf": {sess.CSRFToken}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303, body=%s", rec.Code, rec.Body.String())
		}
		rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
		if err != nil {
			t.Fatalf("ListByEndpoint: %v", err)
		}
		if len(rows) != 1 || rows[0].EventType != "endpoint.test" {
			t.Errorf("rows = %+v, want one endpoint.test", rows)
		}
	})
	t.Run("refused for a disabled endpoint, with a generic message", func(t *testing.T) {
		ep := seedEndpoint(t, st, "disabled-hook", "https://example.com/hook-b", false)
		rec := postForm(t, h, cookie, "/admin/endpoints/"+ep.ID+"/test", url.Values{"csrf": {sess.CSRFToken}})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), endpointActionRefusedMessage) {
			t.Fatalf("status = %d, want 422 with the generic refusal, body=%s", rec.Code, rec.Body.String())
		}
		rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
		if err != nil {
			t.Fatalf("ListByEndpoint: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("got %d deliveries for a disabled endpoint, want 0", len(rows))
		}
	})
}

func TestEndpoints_RedeliverSucceedsForTerminalDelivery(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "redeliver@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)
	d := seedDelivery(t, st, ep.ID, "ip.changed", "failed", "unreachable", 8)

	rec := postForm(t, h, cookie, "/admin/deliveries/"+strconv.FormatInt(d.ID, 10)+"/redeliver",
		url.Values{"csrf": {sess.CSRFToken}, "endpoint_id": {ep.ID}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/endpoints/"+ep.ID {
		t.Fatalf("status = %d Location = %q, body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d deliveries, want 2 (the original terminal row plus the redelivered copy)", len(rows))
	}
}

// TestEndpoints_RedeliverIgnoresUnknownEndpointIDForRedirect: the endpoint_id
// form field is attacker-controlled and used only to choose the redirect; a
// value that names no endpoint must not be reflected into Location.
func TestEndpoints_RedeliverIgnoresUnknownEndpointIDForRedirect(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "redeliver-untrusted@example.com")
	ep := seedEndpoint(t, st, "webhook", "https://example.com/hook", true)
	d := seedDelivery(t, st, ep.ID, "ip.changed", "failed", "unreachable", 8)

	rec := postForm(t, h, cookie, "/admin/deliveries/"+strconv.FormatInt(d.ID, 10)+"/redeliver",
		url.Values{"csrf": {sess.CSRFToken}, "endpoint_id": {"../../not-an-endpoint"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/endpoints" {
		t.Fatalf("status = %d Location = %q, want 303 to the list", rec.Code, rec.Header().Get("Location"))
	}
}

// TestAccount_NoLongerLinksToEndpoints: since #106 endpoints are admin-only;
// the account page carries no link to them whether or not notifications are
// on.
func TestAccount_NoLongerLinksToEndpoints(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		deps, st := testDeps(t)
		if enabled {
			enableNotifications(&deps)
		}
		h, _ := New(deps)
		usr := seedUser(t, st, "nav@example.com", "user")
		cookie := signIn(t, deps, usr)
		rec := getPage(t, h, cookie, "/account")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /account status = %d, want 200", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "endpoints") {
			t.Errorf("enabled=%v: /account still mentions endpoints", enabled)
		}
	}
}

// TestNav_AdminEntriesFollowTheSwitches: the Endpoints and Feed nav entries
// appear for an admin exactly when their route groups exist.
func TestNav_AdminEntriesFollowTheSwitches(t *testing.T) {
	cases := []struct {
		notif, feed bool
	}{{false, false}, {true, false}, {false, true}, {true, true}}
	for _, c := range cases {
		deps, st := testDeps(t)
		deps.Cfg.Notifications.Enabled = c.notif
		deps.Cfg.Feed.Enabled = c.feed
		h, _ := New(deps)
		cookie, _ := adminSession(t, deps, st, "nav-admin@example.com")
		body := getPage(t, h, cookie, "/admin/users").Body.String()
		if got := strings.Contains(body, `href="/admin/endpoints"`); got != c.notif {
			t.Errorf("notif=%v feed=%v: Endpoints nav present=%v", c.notif, c.feed, got)
		}
		if got := strings.Contains(body, `href="/admin/feed"`); got != c.feed {
			t.Errorf("notif=%v feed=%v: Feed nav present=%v", c.notif, c.feed, got)
		}
	}
}
