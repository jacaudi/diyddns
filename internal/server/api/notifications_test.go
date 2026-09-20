package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// newNotificationHarness builds on buildServerDeps, additionally wiring a
// NotificationService into deps.Notify so api.Build registers the
// notification-endpoint and delivery operations (#152) onto the mux — the
// same nil-tolerant gate Passkey/Grants use (see api.Build): a nil
// deps.Notify (buildServerDeps's default, matching a server with
// notifications.enabled=false) keeps the whole group off the mux, so this
// harness is the one place that opts a test into the feature being on.
func newNotificationHarness(t *testing.T) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)
	// allowed=nil (no private destinations) is an arbitrary test fixture, not
	// policy under test here, matching webui_test.go's own notify fixture.
	deps.Notify = service.NewNotificationService(st, deps.HMACKey, nil, service.NewAuditWriter(st))

	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return fullHarness{srv: srv, st: st}
}

// seedNotificationEndpoint inserts a server-global notification endpoint
// directly through the store, going around NotificationService.Create: these
// tests care about the REST surface, not the create ceremony.
func seedNotificationEndpoint(t *testing.T, st *store.Store, label, rawURL string, enabled bool) store.NotificationEndpoint {
	t.Helper()
	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		Label:        label,
		URL:          rawURL,
		SecretSealed: "sealed-test-secret",
		Enabled:      true,
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

// seedNotificationDelivery inserts one notification_deliveries row for
// endpointID with the given terminal/non-terminal status, returning the
// inserted row.
func seedNotificationDelivery(t *testing.T, st *store.Store, endpointID, status string) store.NotificationDelivery {
	t.Helper()
	d := store.NotificationDelivery{
		EndpointID: endpointID,
		EventType:  "device.created",
		EventID:    1,
		Payload:    []byte(`{"type":"device.created"}`),
		Status:     status,
	}
	if err := st.NotificationDeliveries().Enqueue(t.Context(), d); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), endpointID, 1)
	if err != nil {
		t.Fatalf("list seeded delivery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("seed delivery: got %d rows, want 1", len(rows))
	}
	return rows[0]
}

// ---------- conditional registration (#152) ----------

// TestNotificationRoutes_AbsentWhenDisabled proves the whole feature is
// absent — not just guarded — when notifications are off, mirroring
// webui.go's own conditional route table (webui.go:117-126): the harness's
// default ServerDeps carries a nil Notify, so api.Build must not register
// any of the seven operations, and the admin gate never even gets a chance
// to run.
func TestNotificationRoutes_AbsentWhenDisabled(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-notif-off@example.com", "admin")
	adminCookie, _ := sessionFor(t, h, "admin-notif-off@example.com")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints", nil, adminCookie, "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route absent when notifications disabled), body=%s", status, body)
	}
}

// ---------- GET /api/v1/admin/endpoints ----------

func TestListEndpoints_RequiresAdmin(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-le@example.com", "admin")
	seedUser(t, h.st, "user-le@example.com", "user")
	seedNotificationEndpoint(t, h.st, "hook", "https://example.com/hook", true)

	// No session -> 401.
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("anon: status = %d, want 401, body=%s", status, body)
	}

	// Non-admin -> 403.
	userCookie, _ := sessionFor(t, h, "user-le@example.com")
	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints", nil, userCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("user: status = %d, want 403, body=%s", status, body)
	}

	// Admin -> 200 with the seeded endpoint, secret-free.
	adminCookie, _ := sessionFor(t, h, "admin-le@example.com")
	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("admin: status = %d, want 200, body=%s", status, body)
	}
	var got []map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if len(got) != 1 || got[0]["label"] != "hook" {
		t.Fatalf("got = %+v, want one endpoint labeled hook", got)
	}
	if _, leaked := got[0]["secret_sealed"]; leaked {
		t.Fatalf("list response leaked secret_sealed: %+v", got[0])
	}
}

// ---------- POST /api/v1/admin/endpoints ----------

func TestCreateEndpoint_RevealsSecretOnceAndRequiresCSRF(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-ce@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-ce@example.com")

	newEP := map[string]string{"label": "hook", "url": "https://example.com/hook"}

	// No CSRF -> 403.
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints", newEP, adminCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("no csrf: status = %d, want 403, body=%s", status, body)
	}

	// Admin + CSRF -> 200, with the secret revealed exactly this once.
	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints", newEP, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("with csrf: status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Endpoint struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"endpoint"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.Endpoint.Label != "hook" || got.Endpoint.URL != "https://example.com/hook" {
		t.Fatalf("endpoint = %+v, want label=hook url=https://example.com/hook", got.Endpoint)
	}
	if got.Secret == "" {
		t.Fatal("create response carried no secret")
	}
}

func TestCreateEndpoint_DuplicateURLReturns409(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-dup@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-dup@example.com")
	seedNotificationEndpoint(t, h.st, "existing", "https://example.com/dup", true)

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints", map[string]string{
		"label": "another", "url": "https://example.com/dup",
	}, adminCookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", status, body)
	}
}

func TestCreateEndpoint_RejectedTargetReturns422(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-reject@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-reject@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints", map[string]string{
		"label": "bad-scheme", "url": "ftp://example.com/hook",
	}, adminCookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

func TestCreateEndpoint_EmptyLabelReturns422(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-nolabel@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-nolabel@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints", map[string]string{
		"label": "  ", "url": "https://example.com/hook",
	}, adminCookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

// ---------- GET /api/v1/admin/endpoints/{id} ----------

func TestGetEndpoint_ReturnsViewOrNotFound(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-get@example.com", "admin")
	adminCookie, _ := sessionFor(t, h, "admin-get@example.com")
	ep := seedNotificationEndpoint(t, h.st, "hook", "https://example.com/hook", true)

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints/"+ep.ID, nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.ID != ep.ID || got.Label != "hook" {
		t.Fatalf("got = %+v, want id=%q label=hook", got, ep.ID)
	}

	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/endpoints/does-not-exist", nil, adminCookie, "")
	if status != http.StatusNotFound {
		t.Fatalf("missing id: status = %d, want 404, body=%s", status, body)
	}
}

// ---------- PATCH /api/v1/admin/endpoints/{id} ----------

func TestPatchEndpoint_TogglesEnabled(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-patch@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-patch@example.com")
	ep := seedNotificationEndpoint(t, h.st, "hook", "https://example.com/hook", true)

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/admin/endpoints/"+ep.ID, map[string]any{
		"enabled": false,
	}, adminCookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.Enabled {
		t.Fatalf("Enabled = true, want false after PATCH")
	}

	stored, err := h.st.NotificationEndpoints().Get(t.Context(), ep.ID)
	if err != nil {
		t.Fatalf("Get after patch: %v", err)
	}
	if stored.Enabled {
		t.Fatal("store still reports the endpoint enabled after PATCH")
	}
}

// ---------- DELETE /api/v1/admin/endpoints/{id} ----------

func TestDeleteEndpoint_Returns204AndRemoves(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-del@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-del@example.com")
	ep := seedNotificationEndpoint(t, h.st, "hook", "https://example.com/hook", true)

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/endpoints/"+ep.ID, nil, adminCookie, csrf)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", status, body)
	}
	if _, err := h.st.NotificationEndpoints().Get(t.Context(), ep.ID); err == nil {
		t.Fatal("endpoint still exists after delete")
	}
}

// ---------- POST /api/v1/admin/endpoints/{id}/test ----------

func TestTestEndpoint_SendsAndRefusesWhenDisabled(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-test@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-test@example.com")
	enabledEP := seedNotificationEndpoint(t, h.st, "enabled-hook", "https://example.com/enabled", true)
	disabledEP := seedNotificationEndpoint(t, h.st, "disabled-hook", "https://example.com/disabled", false)

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints/"+enabledEP.ID+"/test", nil, adminCookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("enabled endpoint: status = %d, want 200, body=%s", status, body)
	}
	rows, err := h.st.NotificationDeliveries().ListByEndpoint(t.Context(), enabledEP.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 1 || rows[0].EventType != "endpoint.test" {
		t.Fatalf("deliveries = %+v, want one endpoint.test row", rows)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints/"+disabledEP.ID+"/test", nil, adminCookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("disabled endpoint: status = %d, want 409, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/endpoints/does-not-exist/test", nil, adminCookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("missing endpoint: status = %d, want 404, body=%s", status, body)
	}
}

// ---------- POST /api/v1/admin/deliveries/{id}/redeliver ----------

func TestRedeliverDelivery_SuccessAndRefusalCases(t *testing.T) {
	h := newNotificationHarness(t)
	seedUser(t, h.st, "admin-redeliver@example.com", "admin")
	adminCookie, csrf := sessionFor(t, h, "admin-redeliver@example.com")
	ep := seedNotificationEndpoint(t, h.st, "hook", "https://example.com/hook", true)
	terminal := seedNotificationDelivery(t, h.st, ep.ID, store.DeliveryFailed)
	pending := seedNotificationDelivery(t, h.st, ep.ID, store.DeliveryPending)

	status, _, body := doJSON(t, http.MethodPost,
		h.srv.URL+"/api/v1/admin/deliveries/"+idStr(terminal.ID)+"/redeliver", nil, adminCookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("terminal delivery: status = %d, want 200, body=%s", status, body)
	}
	rows, err := h.st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d delivery rows after redeliver, want 3 (2 seeded + 1 redelivered)", len(rows))
	}

	// A pending (non-terminal) delivery is refused -> 404.
	status, _, body = doJSON(t, http.MethodPost,
		h.srv.URL+"/api/v1/admin/deliveries/"+idStr(pending.ID)+"/redeliver", nil, adminCookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("pending delivery: status = %d, want 404, body=%s", status, body)
	}

	// A delivery id that doesn't exist is refused -> 404.
	status, _, body = doJSON(t, http.MethodPost,
		h.srv.URL+"/api/v1/admin/deliveries/99999/redeliver", nil, adminCookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("missing delivery: status = %d, want 404, body=%s", status, body)
	}
}

// idStr renders an int64 delivery id as a URL path segment.
func idStr(id int64) string {
	return strconv.FormatInt(id, 10)
}
