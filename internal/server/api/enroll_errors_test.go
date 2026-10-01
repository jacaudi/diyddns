package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/service"
)

const (
	enrollCodePath      = "/agent/v1/enroll/code"
	errEnrollDetail     = "invalid enrollment code"
	errLabelTakenDetail = "a device with that label already exists"
)

// newEnrollHarness is newLoggedHarness whose enrollment service ALSO logs into
// the capture: the rejection reasons are logged by the service, the failures by
// the API layer, and these tests assert on both. wrap (nil for none) wraps the
// mux, e.g. with cancelledRequests.
func newEnrollHarness(t *testing.T, wrap func(http.Handler) http.Handler) (fullHarness, *service.EnrollmentService, *logCapture) {
	t.Helper()
	st, deps := buildServerDeps(t)
	logs := &logCapture{}
	deps.Log = logs.logger()
	deps.Enroll = service.NewEnrollmentService(st, deps.HMACKey, 15*time.Minute, discardAgentAudit{}, logs.logger())
	return serveWith(t, st, deps, wrap), deps.Enroll, logs
}

func TestEnrollCode_UnknownCodeIsUnauthorizedWithoutAnErrorLine(t *testing.T) {
	h, _, logs := newEnrollHarness(t, nil)

	status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": "never-issued"})

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != errEnrollDetail {
		t.Errorf("detail = %q, want %q", got, errEnrollDetail)
	}
	if errs := atLevel(logs.records(t), "ERROR"); len(errs) != 0 {
		t.Errorf("Error lines = %v, want none: a bad code is not an infrastructure failure", errs)
	}
}

// TestEnrollCode_LabelClashIs409: two codes minted with one label (the device
// API and the web UI both allow it). The second redeem used to be a silent 401
// that sent the user to mint a code that would fail the same way.
func TestEnrollCode_LabelClashIs409(t *testing.T) {
	h, enroll, logs := newEnrollHarness(t, nil)
	user := seedUser(t, h.st, "bob@example.com", "user")
	first, _, err := enroll.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	second, _, err := enroll.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	if status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": first}); status != http.StatusOK {
		t.Fatalf("first redeem: status = %d, body=%s", status, body)
	}

	status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": second})

	if status != http.StatusConflict {
		t.Fatalf("second redeem: status = %d, want 409, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != errLabelTakenDetail {
		t.Errorf("detail = %q, want %q", got, errLabelTakenDetail)
	}
	recs := logs.records(t)
	if errs := atLevel(recs, "ERROR"); len(errs) != 0 {
		t.Errorf("Error lines = %v, want none", errs)
	}
	rejected := withMsg(atLevel(recs, "INFO"), "enrollment code rejected")
	if len(rejected) != 1 || rejected[0]["reason"] != "label_conflict" || rejected[0]["user_id"] != user.ID {
		t.Errorf("rejection lines = %v, want one label_conflict for %s", rejected, user.ID)
	}
	got, err := h.st.EnrollmentCodes().Get(t.Context(), second)
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}
	if got.UsedAt != 0 {
		t.Errorf("second code UsedAt = %d, want 0: the clash must leave it unconsumed", got.UsedAt)
	}
}

func TestEnrollCode_StoreFailureIsAServerError(t *testing.T) {
	h, _, logs := newEnrollHarness(t, nil)
	if err := h.st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": "any-code"})

	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != "failed to enroll device" {
		t.Errorf("detail = %q, want %q", got, "failed to enroll device")
	}
	if errs := atLevel(logs.records(t), "ERROR"); len(errs) != 1 || errs[0]["msg"] != "enroll device failed" {
		t.Errorf("Error lines = %v, want exactly one %q", errs, "enroll device failed")
	}
}

// TestEnrollCode_FailedCompensatingDeleteIs500: a trigger aborts the code's
// UPDATE and another aborts the device DELETE. The API answers 500 (a trigger
// abort is neither ErrConflict nor ErrNotFound) and the service logs the orphan
// at Error with its device id.
func TestEnrollCode_FailedCompensatingDeleteIs500(t *testing.T) {
	h, enroll, logs := newEnrollHarness(t, nil)
	user := seedUser(t, h.st, "bob@example.com", "user")
	code, _, err := enroll.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	for _, q := range []string{
		`CREATE TRIGGER block_code_update BEFORE UPDATE ON enrollment_codes BEGIN SELECT RAISE(ABORT, 'injected consume failure'); END`,
		`CREATE TRIGGER block_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`,
	} {
		if _, err := h.st.DB().ExecContext(t.Context(), q); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
	}

	status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": code})

	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", status, body)
	}
	devices, err := h.st.Devices().ListByUser(t.Context(), user.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices = %v (err %v), want the 1 orphan", devices, err)
	}
	var orphanLogged bool
	for _, rec := range atLevel(logs.records(t), "ERROR") {
		if rec["device_id"] == devices[0].ID {
			orphanLogged = true
		}
	}
	if !orphanLogged {
		t.Errorf("no Error line names the orphan device %s: %v", devices[0].ID, logs.records(t))
	}
}

// TestEnrollCode_ForACancelledRequest drives enroll/code over HTTP with a
// request context that is already cancelled (see cancelledRequests): the
// client's doing, not a store failure, so 499 with one Info line and no Error
// line, never a 500.
func TestEnrollCode_ForACancelledRequest(t *testing.T) {
	h, _, logs := newEnrollHarness(t, cancelledRequests)

	status, body := postJSON(t, h.srv.URL+enrollCodePath, map[string]string{"code": "any-code"})

	if status != 499 {
		t.Fatalf("status = %d, want 499, body=%s", status, body)
	}
	if got := problemDetail(t, body); got != "client closed request" {
		t.Errorf("detail = %q, want %q", got, "client closed request")
	}
	recs := logs.records(t)
	if info := withMsg(atLevel(recs, "INFO"), "enroll device cancelled"); len(info) != 1 {
		t.Errorf("Info lines %q = %d, want 1; log: %v", "enroll device cancelled", len(info), recs)
	}
	if errs := atLevel(recs, "ERROR"); len(errs) != 0 {
		t.Errorf("Error lines = %v, want none", errs)
	}
}
