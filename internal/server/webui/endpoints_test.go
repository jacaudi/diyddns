package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// dataCopyRe extracts the value of a copyValue partial's data-copy attribute,
// so a test can recover exactly what a "Copy" button would put on the
// clipboard without hand-parsing the surrounding markup.
var dataCopyRe = regexp.MustCompile(`data-copy="([^"]*)"`)

// seedEndpoint inserts a notification endpoint owned by userID, going
// through the store directly (like seedDevice) rather than
// NotificationService.Create: these tests care about rendering and routing,
// not about the create ceremony's secret-minting.
func seedEndpoint(t *testing.T, st *store.Store, userID, label, rawURL string, enabled bool) store.NotificationEndpoint {
	t.Helper()
	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		UserID:       userID,
		Label:        label,
		URL:          rawURL,
		SecretSealed: "sealed-test-secret",
		Enabled:      enabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := st.NotificationEndpoints().Create(t.Context(), ep, 100); err != nil {
		t.Fatalf("seed endpoint %q: %v", label, err)
	}
	// Create's INSERT always writes enabled=1 literally (a newly created
	// endpoint is always enabled, by design) — disabling one takes a
	// separate SetEnabled call.
	if !enabled {
		if err := st.NotificationEndpoints().SetEnabled(t.Context(), userID, ep.ID, false); err != nil {
			t.Fatalf("seed endpoint %q: disable: %v", label, err)
		}
	}
	ep.Enabled = enabled
	return ep
}

// seedDelivery inserts a notification_deliveries row directly, so a test can
// pin an exact status/failure-class/attempts combination without driving the
// worker or the attempt budget.
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
// testDeps's zero-value config leaves notifications disabled, matching
// config.Server{}'s zero value, so every test exercising the route group
// must opt in explicitly — the same way
// TestHandleLogin_HideLocalLoginUI_OmitsPasskeyButOIDCShown opts into a
// non-default config flag.
func enableNotifications(deps *Deps) {
	deps.Cfg.Notifications.Enabled = true
}

func TestEndpoints_ListRequiresSession(t *testing.T) {
	deps, _ := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/account/endpoints", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want /login", got)
	}
}

// TestEndpoints_CreateShowsSecretOnceThenNever asserts the reveal renders in
// the POST response itself, and that the exact same secret value is absent
// from the very next GET of the list — mirroring
// TestDeviceNew_RevealsCodeAndCommand.
func TestEndpoints_CreateShowsSecretOnceThenNever(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "endpoints@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{
		"csrf":  {sess.CSRFToken},
		"label": {"home-automation"},
		"url":   {"https://example.com/hooks/ddns"},
	}
	req := httptest.NewRequest(http.MethodPost, "/account/endpoints", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the reveal renders in the POST response), body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Shown once") {
		t.Error("body missing the shown-once warning")
	}
	if !strings.Contains(body, "home-automation") {
		t.Error("body missing the created endpoint's label")
	}

	m := dataCopyRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no data-copy value found in the reveal:\n%s", body)
	}
	secret := m[1]
	if secret == "" {
		t.Fatal("revealed secret is empty")
	}

	// A subsequent GET of the list must never carry that value again.
	req2 := httptest.NewRequest(http.MethodGet, "/account/endpoints", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /account/endpoints status = %d, want 200", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), secret) {
		t.Error("the secret leaked into a later render of the list")
	}
}

func TestEndpoints_ForeignEndpointIsNotFound(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)

	owner := seedUser(t, st, "owner@example.com", "user")
	other := seedUser(t, st, "other@example.com", "user")
	ep := seedEndpoint(t, st, owner.ID, "owners-hook", "https://example.com/hook", true)

	cookie := signIn(t, deps, other)
	sess := sessionFor(t, deps, cookie)

	tests := []struct {
		name   string
		method string
		path   string
		form   url.Values
	}{
		{"detail", http.MethodGet, "/account/endpoints/" + ep.ID, nil},
		{"set enabled", http.MethodPost, "/account/endpoints/" + ep.ID + "/enabled", url.Values{"enabled": {"false"}}},
		{"delete", http.MethodPost, "/account/endpoints/" + ep.ID + "/delete", url.Values{"confirm_label": {ep.Label}}},
		{"test", http.MethodPost, "/account/endpoints/" + ep.ID + "/test", url.Values{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodPost {
				tt.form.Set("csrf", sess.CSRFToken)
				req = httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(http.MethodGet, tt.path, nil)
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404 (a foreign endpoint must be indistinguishable from a missing one)",
					tt.method, tt.path, rec.Code)
			}
		})
	}
}

func TestEndpoints_ForeignDeliveryRedeliverIsNotFound(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)

	owner := seedUser(t, st, "delivery-owner@example.com", "user")
	other := seedUser(t, st, "delivery-other@example.com", "user")
	ep := seedEndpoint(t, st, owner.ID, "owners-hook", "https://example.com/hook", true)
	d := seedDelivery(t, st, ep.ID, "endpoint.test", "failed", "unreachable", 1)

	cookie := signIn(t, deps, other)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}}
	req := httptest.NewRequest(http.MethodPost, "/account/deliveries/"+strconv.FormatInt(d.ID, 10)+"/redeliver",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (a foreign delivery must be indistinguishable from every other refusal cause)", rec.Code)
	}
}

// TestEndpoints_RoutesAbsentWhenDisabled asserts the whole route group 404s
// when notifications are disabled — testDeps's zero-value config already
// leaves them disabled, so this test deliberately does NOT call
// enableNotifications.
func TestEndpoints_RoutesAbsentWhenDisabled(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "disabled-notify@example.com", "user")
	cookie := signIn(t, deps, usr)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/account/endpoints"},
		{http.MethodPost, "/account/endpoints"},
		{http.MethodPost, "/account/endpoints/some-id/enabled"},
		{http.MethodPost, "/account/endpoints/some-id/test"},
		{http.MethodPost, "/account/endpoints/some-id/delete"},
		{http.MethodGet, "/account/endpoints/some-id"},
		{http.MethodPost, "/account/deliveries/1/redeliver"},
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

// TestEndpointDetail_RendersFailureClassNotRawError is the security
// assertion design §5.8/§10.4 exists for: the detail page must render only
// the fixed, coarse failure class, never anything that could carry raw
// upstream detail. There is structurally nothing else to leak — the store
// schema has no column for a raw error string, an HTTP status code, or a
// resolved address (design §7.2) — so this proves the one place that COULD
// leak (LastFailure, which IS a plain string column) is always translated
// through failureClassLabel and never rendered verbatim.
func TestEndpointDetail_RendersFailureClassNotRawError(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "detail@example.com", "user")
	ep := seedEndpoint(t, st, usr.ID, "webhook", "https://example.com/hook", true)

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

	cookie := signIn(t, deps, usr)
	req := httptest.NewRequest(http.MethodGet, "/account/endpoints/"+ep.ID, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for class, phrase := range classes {
		if !strings.Contains(body, phrase) {
			t.Errorf("body missing the mapped phrase %q for class %q", phrase, class)
		}
		if strings.Contains(body, class) {
			t.Errorf("body contains the raw failure class %q verbatim; it must only ever render as %q", class, phrase)
		}
	}
}

func TestEndpoints_SetEnabledTogglesAndRedirects(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "toggle@example.com", "user")
	ep := seedEndpoint(t, st, usr.ID, "webhook", "https://example.com/hook", true)
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "enabled": {"false"}}
	req := httptest.NewRequest(http.MethodPost, "/account/endpoints/"+ep.ID+"/enabled", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	got, err := st.NotificationEndpoints().GetOwned(t.Context(), usr.ID, ep.ID)
	if err != nil {
		t.Fatalf("GetOwned: %v", err)
	}
	if got.Enabled {
		t.Error("endpoint is still enabled after POST .../enabled with enabled=false")
	}
}

func TestEndpoints_DeleteRequiresTypedConfirmation(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "delete@example.com", "user")
	ep := seedEndpoint(t, st, usr.ID, "webhook", "https://example.com/hook", true)
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	t.Run("wrong confirmation leaves it in place", func(t *testing.T) {
		form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"not-the-label"}}
		req := httptest.NewRequest(http.MethodPost, "/account/endpoints/"+ep.ID+"/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
		}
		if _, err := st.NotificationEndpoints().GetOwned(t.Context(), usr.ID, ep.ID); err != nil {
			t.Errorf("endpoint was deleted despite a mismatched confirmation: %v", err)
		}
	})

	t.Run("correct confirmation deletes it", func(t *testing.T) {
		form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {ep.Label}}
		req := httptest.NewRequest(http.MethodPost, "/account/endpoints/"+ep.ID+"/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusSeeOther, rec.Body.String())
		}
		if _, err := st.NotificationEndpoints().GetOwned(t.Context(), usr.ID, ep.ID); err == nil {
			t.Error("endpoint still exists after a correctly-confirmed delete")
		}
	})
}

func TestEndpoints_SendTest(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "sendtest@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	t.Run("enqueues one delivery for an enabled endpoint", func(t *testing.T) {
		ep := seedEndpoint(t, st, usr.ID, "enabled-hook", "https://example.com/hook-a", true)
		form := url.Values{"csrf": {sess.CSRFToken}}
		req := httptest.NewRequest(http.MethodPost, "/account/endpoints/"+ep.ID+"/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusSeeOther, rec.Body.String())
		}
		rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
		if err != nil {
			t.Fatalf("ListByEndpoint: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d deliveries, want 1", len(rows))
		}
		if rows[0].EventType != "endpoint.test" {
			t.Errorf("EventType = %q, want endpoint.test", rows[0].EventType)
		}
	})

	t.Run("refused for a disabled endpoint, with a generic message", func(t *testing.T) {
		ep := seedEndpoint(t, st, usr.ID, "disabled-hook", "https://example.com/hook-b", false)
		form := url.Values{"csrf": {sess.CSRFToken}}
		req := httptest.NewRequest(http.MethodPost, "/account/endpoints/"+ep.ID+"/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), endpointActionRefusedMessage) {
			t.Error("body missing the generic refusal message")
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

func TestEndpoints_RedeliverSucceedsForOwnTerminalDelivery(t *testing.T) {
	deps, st := testDeps(t)
	enableNotifications(&deps)
	h, _ := New(deps)
	usr := seedUser(t, st, "redeliver@example.com", "user")
	ep := seedEndpoint(t, st, usr.ID, "webhook", "https://example.com/hook", true)
	d := seedDelivery(t, st, ep.ID, "ip.changed", "failed", "unreachable", 8)
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "endpoint_id": {ep.ID}}
	req := httptest.NewRequest(http.MethodPost, "/account/deliveries/"+strconv.FormatInt(d.ID, 10)+"/redeliver",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/account/endpoints/"+ep.ID {
		t.Errorf("Location = %q, want /account/endpoints/%s", got, ep.ID)
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d deliveries, want 2 (the original terminal row plus the redelivered copy)", len(rows))
	}
}
