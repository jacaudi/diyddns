package service

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// newNotificationServiceTest opens a fresh in-memory store, seeds one admin,
// and builds a NotificationService with no operator-configured allow-list.
// Reused by every NotificationService test in this file.
func newNotificationServiceTest(t *testing.T) (*store.Store, string, *NotificationService) {
	t.Helper()
	st := openTestStore(t)
	usr := seedUser(t, st, "admin@b.co", "admin")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), allowed, discardAudit{})
	return st, usr.ID, svc
}

// seedEndpoint inserts a server-global notification endpoint directly via the
// store, bypassing service-level validation so tests can construct scenarios
// the service itself would reject at creation time (e.g. a disabled endpoint).
func seedEndpoint(t *testing.T, st *store.Store, url string, enabled bool) store.NotificationEndpoint {
	t.Helper()
	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		Label:        "ep",
		URL:          url,
		SecretSealed: "sealed",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := st.NotificationEndpoints().Create(t.Context(), ep); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	ep.Enabled = true
	if !enabled {
		if err := st.NotificationEndpoints().SetEnabled(t.Context(), ep.ID, false); err != nil {
			t.Fatalf("seed endpoint disable: %v", err)
		}
		ep.Enabled = false
	}
	return ep
}

// seedTerminalDelivery inserts one notification_deliveries row directly with
// the given status.
func seedTerminalDelivery(t *testing.T, st *store.Store, endpointID, status string) int64 {
	t.Helper()
	now := store.NowUnix()
	res, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, created_at, updated_at)
		 VALUES (?, 'device.ip_changed', 1, ?, 1, NULL, ?, ?, ?)`,
		endpointID, []byte(`{}`), status, now, now,
	)
	if err != nil {
		t.Fatalf("seed terminal delivery: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed terminal delivery: LastInsertId: %v", err)
	}
	return id
}

func TestCreate_RejectsNonHTTPScheme(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)

	if _, _, err := svc.Create(t.Context(), actorID, "bad", "ftp://example.com/hook"); err == nil {
		t.Fatal("expected an error for a non-http(s) scheme")
	}
	eps, err := st.NotificationEndpoints().List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected no endpoint written, got %d", len(eps))
	}
}

func TestCreate_RejectsDeniedIPLiteral(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)

	_, _, err := svc.Create(t.Context(), actorID, "metadata", "https://169.254.169.254/")
	if !errors.Is(err, notify.ErrDenied) {
		t.Fatalf("err = %v, want notify.ErrDenied", err)
	}
	eps, err := st.NotificationEndpoints().List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected no endpoint written, got %d", len(eps))
	}
}

func TestCreate_AcceptsHostnameWithoutResolving(t *testing.T) {
	_, actorID, svc := newNotificationServiceTest(t)

	ep, secret, err := svc.Create(t.Context(), actorID, "consumer", "https://consumer.lan/hook")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ep.URL != "https://consumer.lan/hook" {
		t.Fatalf("URL = %q, want https://consumer.lan/hook", ep.URL)
	}
	if secret == "" {
		t.Fatal("expected a non-empty returned secret")
	}
}

func TestCreate_ReturnsSecretOnceAndSealsIt(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)

	ep, secretB64, err := svc.Create(t.Context(), actorID, "ep", "https://example.com/hook")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatalf("returned secret is not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("decoded secret length = %d, want 32", len(raw))
	}
	stored, err := st.NotificationEndpoints().Get(t.Context(), ep.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.SecretSealed == secretB64 {
		t.Fatal("the stored column must not equal the plaintext secret returned to the caller")
	}
	opened, err := auth.OpenSecret(testKey32(), stored.SecretSealed)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(opened, raw) {
		t.Fatal("the sealed secret must decrypt to the returned plaintext secret")
	}
}

func TestCreate_DuplicateURLIsConflict(t *testing.T) {
	_, actorID, svc := newNotificationServiceTest(t)
	if _, _, err := svc.Create(t.Context(), actorID, "one", "https://one.example.com/"); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, _, err := svc.Create(t.Context(), actorID, "two", "https://one.example.com/"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("create duplicate url: err = %v, want ErrConflict", err)
	}
}

func TestGet_MissingIsNotFound(t *testing.T) {
	_, _, svc := newNotificationServiceTest(t)
	if _, err := svc.Get(t.Context(), "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: err = %v, want store.ErrNotFound", err)
	}
}

func TestRedeliver_RefusedOnDisabledEndpoint(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, "https://example.com/hook", false)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, store.DeliveryFailed)

	ok, err := svc.Redeliver(t.Context(), actorID, deliveryID)
	if err != nil {
		t.Fatalf("Redeliver: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: disabled means no outbound traffic on this endpoint")
	}
}

func TestRedeliver_RefusedOnNonTerminalRow(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, "https://example.com/hook", true)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, store.DeliveryPending)

	ok, err := svc.Redeliver(t.Context(), actorID, deliveryID)
	if err != nil {
		t.Fatalf("Redeliver: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: a pending row is not terminal")
	}
}

func TestRedeliver_CopiesTerminalRow(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, "https://example.com/hook", true)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, store.DeliveryFailed)

	ok, err := svc.Redeliver(t.Context(), actorID, deliveryID)
	if err != nil || !ok {
		t.Fatalf("Redeliver = %v, %v; want true, nil", ok, err)
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (the terminal source and its copy)", len(rows))
	}
}

func TestTest_RefusedOnDisabledEndpoint(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, "https://example.com/hook", false)

	ok, err := svc.Test(t.Context(), actorID, ep.ID)
	if err != nil {
		t.Fatalf("Test: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: disabled means no outbound traffic on this endpoint")
	}
}

// TestTest_AuditsTestSent: a successful Test() must record
// notification.test_sent with the admin as actor, using a real audit writer.
func TestTest_AuditsTestSent(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "admin@b.co", "admin")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), allowed, NewAuditWriter(st))
	ep := seedEndpoint(t, st, "https://example.com/hook", true)

	ok, err := svc.Test(t.Context(), usr.ID, ep.ID)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !ok {
		t.Fatal("Test refused, want allowed")
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "notification.test_sent"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ActorUserID != usr.ID {
		t.Fatalf("notification.test_sent entries = %+v, want one by %s", page.Rows, usr.ID)
	}
	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 1 || rows[0].EventType != notify.EventTest {
		t.Fatalf("rows = %+v, want one endpoint.test row", rows)
	}
}

// TestCreate_AuditsSecretRevealed: a successful Create() must record
// notification.secret_revealed alongside notification.endpoint_created.
func TestCreate_AuditsSecretRevealed(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "admin@b.co", "admin")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), allowed, NewAuditWriter(st))

	if _, _, err := svc.Create(t.Context(), usr.ID, "ep", "https://example.com/hook"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, ev := range []string{"notification.secret_revealed", "notification.endpoint_created"} {
		page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: ev}, "", 10)
		if err != nil {
			t.Fatalf("ListPaginated(%s): %v", ev, err)
		}
		if len(page.Rows) != 1 {
			t.Fatalf("%s entries = %d, want 1", ev, len(page.Rows))
		}
	}
}

func TestSetEnabledAndDelete(t *testing.T) {
	st, actorID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, "https://example.com/hook", true)

	if err := svc.SetEnabled(t.Context(), actorID, ep.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	got, err := svc.Get(t.Context(), ep.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Error("still enabled after SetEnabled(false)")
	}
	if err := svc.Delete(t.Context(), actorID, ep.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(t.Context(), ep.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after delete err = %v, want ErrNotFound", err)
	}
	if err := svc.Delete(t.Context(), actorID, ep.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete(again) err = %v, want ErrNotFound", err)
	}
}
