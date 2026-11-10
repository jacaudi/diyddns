package api_test

import (
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/store"
)

// rotationTrack and rotationState decode the admin rotation response bodies.
// huma adds a $schema field, so tests decode rather than compare raw bytes.
type rotationTrack struct {
	Since  *int64  `json:"since"`
	Status *string `json:"status"`
}

type rotationState struct {
	Secret rotationTrack `json:"secret"`
	Cert   rotationTrack `json:"cert"`
}

// seedRotationDevice creates an owner with one device and returns the device.
func seedRotationDevice(t *testing.T, h fullHarness, ownerEmail string) store.Device {
	t.Helper()
	owner := seedUser(t, h.st, ownerEmail, "user")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: owner.ID, Label: "laptop"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	return dev
}

// getDevice re-reads a device row.
func getDevice(t *testing.T, h fullHarness, id string) store.Device {
	t.Helper()
	d, err := h.st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return d
}

func TestAdminRotation_MarkOne(t *testing.T) {
	var ca *agenttls.CA
	h := newFullHarness(t, withAgentMTLS(t, false, &ca))
	seedUser(t, h.st, "admin-rot@example.com", "admin")
	dev := seedRotationDevice(t, h, "owner-rot@example.com")
	cookie, csrf := sessionFor(t, h, "admin-rot@example.com")
	url := h.srv.URL + "/api/v1/admin/devices/" + dev.ID + "/rotation"

	status, _, body := doJSON(t, http.MethodPost, url, map[string]string{"target": "secret"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	row := getDevice(t, h, dev.ID)
	var got rotationState
	decodeJSON(t, body, &got)
	if row.RotateSecretAt == 0 {
		t.Fatal("RotateSecretAt = 0, want it marked")
	}
	if got.Secret.Since == nil || *got.Secret.Since != row.RotateSecretAt ||
		got.Secret.Status == nil || *got.Secret.Status != "awaiting_upgrade" {
		t.Errorf("secret track = %+v, want since=%d status=awaiting_upgrade", got.Secret, row.RotateSecretAt)
	}
	if got.Cert.Since != nil || got.Cert.Status != nil {
		t.Errorf("cert track = %+v, want {null,null}", got.Cert)
	}

	status, _, body = doJSON(t, http.MethodPost, url, map[string]string{"target": "cert"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("cert status = %d, want 200, body=%s", status, body)
	}
	after := getDevice(t, h, dev.ID)
	var both rotationState
	decodeJSON(t, body, &both)
	if after.RotateSecretAt != row.RotateSecretAt {
		t.Errorf("RotateSecretAt = %d, want unchanged %d", after.RotateSecretAt, row.RotateSecretAt)
	}
	if both.Secret.Since == nil || *both.Secret.Since != row.RotateSecretAt {
		t.Errorf("secret.since = %v, want %d", both.Secret.Since, row.RotateSecretAt)
	}
	if after.RotateCertAt == 0 || both.Cert.Since == nil || *both.Cert.Since != after.RotateCertAt {
		t.Errorf("cert.since = %v, want %d", both.Cert.Since, after.RotateCertAt)
	}
	if both.Cert.Status == nil || *both.Cert.Status != "awaiting_upgrade" {
		t.Errorf("cert.status = %v, want awaiting_upgrade", both.Cert.Status)
	}
}

func TestAdminRotation_Guards(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-guard@example.com", "admin")
	dev := seedRotationDevice(t, h, "owner-guard@example.com")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-guard@example.com")
	userCookie, userCSRF := sessionFor(t, h, "owner-guard@example.com")
	url := h.srv.URL + "/api/v1/admin/devices/" + dev.ID + "/rotation"
	secretBody := map[string]string{"target": "secret"}

	untouched := func(t *testing.T) {
		t.Helper()
		if row := getDevice(t, h, dev.ID); row.RotateSecretAt != 0 || row.RotateCertAt != 0 {
			t.Errorf("row = (%d, %d), want untouched", row.RotateSecretAt, row.RotateCertAt)
		}
	}
	expect := func(t *testing.T, method, url string, body any, cookie *http.Cookie, csrf string, want int) {
		t.Helper()
		status, _, out := doJSON(t, method, url, body, cookie, csrf)
		if status != want {
			t.Fatalf("status = %d, want %d, body=%s", status, want, out)
		}
		untouched(t)
	}

	t.Run("non-admin is 403", func(t *testing.T) {
		expect(t, http.MethodPost, url, secretBody, userCookie, userCSRF, http.StatusForbidden)
	})
	t.Run("missing csrf is 403", func(t *testing.T) {
		expect(t, http.MethodPost, url, secretBody, adminCookie, "", http.StatusForbidden)
	})
	t.Run("unknown id is 404", func(t *testing.T) {
		status, _, out := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/devices/no-such/rotation", secretBody, adminCookie, adminCSRF)
		if status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body=%s", status, out)
		}
	})
	t.Run("unknown target is 422", func(t *testing.T) {
		expect(t, http.MethodPost, url, map[string]string{"target": "foo"}, adminCookie, adminCSRF, http.StatusUnprocessableEntity)
	})
	t.Run("cert without the agent listener is 409", func(t *testing.T) {
		expect(t, http.MethodPost, url, map[string]string{"target": "cert"}, adminCookie, adminCSRF, http.StatusConflict)
	})
	t.Run("disabled device is 409", func(t *testing.T) {
		if err := h.st.Devices().SetDisabled(t.Context(), dev.ID, true); err != nil {
			t.Fatalf("SetDisabled: %v", err)
		}
		defer func() {
			if err := h.st.Devices().SetDisabled(t.Context(), dev.ID, false); err != nil {
				t.Fatalf("re-enable: %v", err)
			}
		}()
		expect(t, http.MethodPost, url, secretBody, adminCookie, adminCSRF, http.StatusConflict)
	})
	t.Run("disabled owner is 409", func(t *testing.T) {
		if err := h.st.Users().SetDisabled(t.Context(), getDevice(t, h, dev.ID).UserID, true); err != nil {
			t.Fatalf("SetDisabled: %v", err)
		}
		expect(t, http.MethodPost, url, secretBody, adminCookie, adminCSRF, http.StatusConflict)
	})
}

func TestAdminRotation_Fleet(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-fleet@example.com", "admin")
	var ids []string
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"} {
		ids = append(ids, seedRotationDevice(t, h, email).ID)
	}
	// ids[0] advertised the rotation capability on a check-in.
	if _, err := h.st.RecordIPChange(t.Context(), store.IPChange{DeviceID: ids[0], IPv4: "203.0.113.5", SupportsRotation: true}); err != nil {
		t.Fatalf("RecordIPChange: %v", err)
	}
	if err := h.st.Devices().SetDisabled(t.Context(), ids[3], true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	cookie, csrf := sessionFor(t, h, "admin-fleet@example.com")
	url := h.srv.URL + "/api/v1/admin/devices/rotation"

	status, _, body := doJSON(t, http.MethodPost, url, map[string]string{"target": "both"}, cookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("both without listener: status = %d, want 409, body=%s", status, body)
	}
	for _, id := range ids {
		if row := getDevice(t, h, id); row.RotateSecretAt != 0 || row.RotateCertAt != 0 {
			t.Errorf("device %s marked after a 409", id)
		}
	}

	status, _, body = doJSON(t, http.MethodPost, url, map[string]string{"target": "secret"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Marked          int `json:"marked"`
		AwaitingUpgrade int `json:"awaiting_upgrade"`
		AwaitingMTLS    int `json:"awaiting_mtls"`
		SkippedDisabled int `json:"skipped_disabled"`
	}
	decodeJSON(t, body, &got)
	if got.Marked != 3 || got.AwaitingUpgrade != 2 || got.AwaitingMTLS != 0 || got.SkippedDisabled != 1 {
		t.Errorf("counts = %+v, want marked=3 awaiting_upgrade=2 awaiting_mtls=0 skipped_disabled=1", got)
	}
}

func TestAdminRotation_Cancel(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "admin-cancel@example.com", "admin")
	dev := seedRotationDevice(t, h, "owner-cancel@example.com")
	adminCookie, adminCSRF := sessionFor(t, h, "admin-cancel@example.com")
	userCookie, userCSRF := sessionFor(t, h, "owner-cancel@example.com")
	url := h.srv.URL + "/api/v1/admin/devices/" + dev.ID + "/rotation"

	if err := h.st.Devices().MarkRotation(t.Context(), dev.ID, true, true, 1000); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
	if err := h.st.Devices().SetPendingCert(t.Context(), dev.ID, "0b"); err != nil {
		t.Fatalf("SetPendingCert: %v", err)
	}

	status, _, body := doJSON(t, http.MethodDelete, url, nil, userCookie, userCSRF)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403, body=%s", status, body)
	}
	if row := getDevice(t, h, dev.ID); row.RotateSecretAt == 0 {
		t.Fatal("non-admin cancel cleared the mark")
	}

	status, _, body = doJSON(t, http.MethodDelete, url, nil, adminCookie, adminCSRF)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", status, body)
	}
	row := getDevice(t, h, dev.ID)
	if row.RotateSecretAt != 0 || row.RotateCertAt != 0 || row.PendingCertSerial != "0b" {
		t.Errorf("row = (%d, %d, %q), want (0, 0, \"0b\")", row.RotateSecretAt, row.RotateCertAt, row.PendingCertSerial)
	}

	status, _, body = doJSON(t, http.MethodDelete, url, nil, adminCookie, adminCSRF)
	if status != http.StatusNoContent {
		t.Errorf("second cancel status = %d, want 204, body=%s", status, body)
	}
	status, _, body = doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/devices/no-such/rotation", nil, adminCookie, adminCSRF)
	if status != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404, body=%s", status, body)
	}
}
