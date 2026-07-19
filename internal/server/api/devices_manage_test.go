package api_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedHistory appends n IPHistory rows for deviceID with distinct ObservedAt
// timestamps, so pagination has a deterministic newest-first order to walk.
func seedHistory(t *testing.T, st *store.Store, deviceID string, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		_, err := st.IPHistory().Append(t.Context(), store.IPHistory{
			DeviceID:   deviceID,
			IPv4:       fmt.Sprintf("10.0.0.%d", i),
			ObservedAt: int64(i * 100),
		})
		if err != nil {
			t.Fatalf("seed history %d: %v", i, err)
		}
	}
}

// ---------- PATCH /api/v1/devices/{id} ----------

func TestPatchDevice_RenamesWithCSRF(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patcha@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "old"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "patcha@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev.ID, map[string]string{
		"label": "new",
	}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if !strings.Contains(string(body), `"label":"new"`) {
		t.Fatalf("body missing new label: %s", body)
	}
}

func TestPatchDevice_MissingCSRF_Forbidden(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patchb@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "old"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, _ := loginAndGetCSRF(t, h, "patchb@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev.ID, map[string]string{
		"label": "new",
	}, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
}

func TestPatchDevice_NoSession_Unauthorized(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patchc@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "old"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev.ID, map[string]string{
		"label": "new",
	}, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestPatchDevice_ForeignDevice_NotFound(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "patchd@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "patche@example.com", "correct horse battery staple")
	other, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-dev"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "patchd@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+other.ID, map[string]string{
		"label": "x",
	}, cookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

func TestPatchDevice_EmptyLabel_UnprocessableEntity(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patchf@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "old"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "patchf@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev.ID, map[string]string{
		"label": "",
	}, cookie, csrf)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", status, body)
	}
}

func TestPatchDevice_DuplicateLabel_Conflict(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patchg@example.com", "correct horse battery staple")
	if _, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "taken"}); err != nil {
		t.Fatalf("seed device 1: %v", err)
	}
	dev2, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "free"})
	if err != nil {
		t.Fatalf("seed device 2: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "patchg@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev2.ID, map[string]string{
		"label": "taken",
	}, cookie, csrf)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", status, body)
	}
}

func TestPatchDevice_EmptyBody_ReturnsCurrentDevice(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "patchh@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "unchanged"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "patchh@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPatch, h.srv.URL+"/api/v1/devices/"+dev.ID, map[string]string{}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if !strings.Contains(string(body), `"label":"unchanged"`) {
		t.Fatalf("body missing unchanged label: %s", body)
	}
}

// ---------- DELETE /api/v1/devices/{id} ----------

func TestDeleteDevice_RemovesDevice(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "deletea@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "deletea@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/devices/"+dev.ID, nil, cookie, csrf)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", status, body)
	}

	if _, err := h.st.Devices().GetByID(t.Context(), dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device still exists after delete, GetByID err=%v", err)
	}
}

func TestDeleteDevice_MissingCSRF_Forbidden(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "deleteb@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, _ := loginAndGetCSRF(t, h, "deleteb@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/devices/"+dev.ID, nil, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
}

func TestDeleteDevice_NoSession_Unauthorized(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "deletec@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/devices/"+dev.ID, nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestDeleteDevice_ForeignDevice_NotFound(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "deleted@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "deletee@example.com", "correct horse battery staple")
	other, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-dev"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "deleted@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/devices/"+other.ID, nil, cookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

// ---------- POST /api/v1/devices/{id}/rotate-secret ----------

func TestRotateSecret_ReturnsSecretOnce(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "rotatea@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "rotatea@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices/"+dev.ID+"/rotate-secret", nil, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	secretBytes, err := base64.StdEncoding.DecodeString(got.Secret)
	if err != nil || len(secretBytes) == 0 {
		t.Fatalf("secret not valid non-empty base64: %q (%v)", got.Secret, err)
	}
}

func TestRotateSecret_MissingCSRF_Forbidden(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "rotateb@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, _ := loginAndGetCSRF(t, h, "rotateb@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices/"+dev.ID+"/rotate-secret", nil, cookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
}

func TestRotateSecret_NoSession_Unauthorized(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "rotatec@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices/"+dev.ID+"/rotate-secret", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestRotateSecret_ForeignDevice_NotFound(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "rotated@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "rotatee@example.com", "correct horse battery staple")
	other, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-dev"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, csrf := loginAndGetCSRF(t, h, "rotated@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices/"+other.ID+"/rotate-secret", nil, cookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

// ---------- GET /api/v1/devices/{id}/history ----------

func TestDeviceHistory_Paginated(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "hista@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	seedHistory(t, h.st, dev.ID, 3)
	cookie, _ := loginAndGetCSRF(t, h, "hista@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+dev.ID+"/history?limit=2", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		Rows       []map[string]any `json:"rows"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rows) != 2 || got.NextCursor == "" {
		t.Fatalf("rows=%d cursor=%q, want 2 + cursor", len(got.Rows), got.NextCursor)
	}
}

func TestDeviceHistory_NoSession_Unauthorized(t *testing.T) {
	h := newFullHarness(t)
	userA := seedAuthUserWithPassword(t, h.st, "histb@example.com", "correct horse battery staple")
	dev, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userA.ID, Label: "d"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+dev.ID+"/history", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestDeviceHistory_ForeignDevice_NotFound(t *testing.T) {
	h := newFullHarness(t)
	seedAuthUserWithPassword(t, h.st, "histc@example.com", "correct horse battery staple")
	userB := seedAuthUserWithPassword(t, h.st, "histd@example.com", "correct horse battery staple")
	other, err := h.st.Devices().Create(t.Context(), store.Device{UserID: userB.ID, Label: "b-dev"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	cookie, _ := loginAndGetCSRF(t, h, "histc@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/devices/"+other.ID+"/history", nil, cookie, "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}
