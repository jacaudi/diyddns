package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// A failed redeem must not leave an orphan device. These tests pin the three
// error shapes ConsumeCode now distinguishes (#9): a label already in use (a
// state the user created, reason label_conflict, code left unconsumed), a
// compensating delete that must outlive a cancelled request, and one that fails
// and must be logged instead of discarded.

const msgRollbackFailed = "enrollment compensating delete failed"

func TestEnrollmentService_ConsumeCode_LogsALabelConflict(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	first, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	second, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	if _, err := svc.ConsumeCode(t.Context(), first, ClientMeta{}); err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	buf.reset()

	_, err = svc.ConsumeCode(t.Context(), second, ClientMeta{})

	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want it to wrap store.ErrConflict", err)
	}
	wantRejection(t, buf, msgCodeRejected, rejectLabelConflict, user.ID)
	assertNoSecrets(t, buf, first, second)
	got, err := st.EnrollmentCodes().Get(t.Context(), second)
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}
	if got.UsedAt != 0 || got.DeviceID != "" {
		t.Errorf("code = %+v, want it unconsumed: the device insert fails before Consume", got)
	}
	devices, err := st.Devices().ListByUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Devices.ListByUser: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("devices = %d, want 1 (the first redeem's)", len(devices))
	}
}

// TestEnrollmentService_RollbackDevice_SurvivesACancelledContext: a Consume that
// failed on a cancelled request context would make an ordinary delete fail for
// the same reason and leave an orphan device, which the next redeem of the code
// would then meet as a 409. rollbackDevice therefore deletes on a context that
// survives cancellation. It is tested directly: nothing can cancel a context
// between the insert and Consume inside one ConsumeCode call.
func TestEnrollmentService_RollbackDevice_SurvivesACancelledContext(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	dev, _, err := svc.createSealedDevice(t.Context(), user.ID, "laptop", ClientMeta{})
	if err != nil {
		t.Fatalf("createSealedDevice: %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	svc.rollbackDevice(cancelled, dev.ID)

	if _, err := st.Devices().GetByID(t.Context(), dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Devices.GetByID after rollback: err = %v, want ErrNotFound (the device must be gone)", err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("a successful rollback logged:\n%s", got)
	}
}

// TestEnrollmentService_ConsumeCode_LogsAFailedCompensatingDelete: one trigger
// makes Consume fail with a real (non-ErrNotFound) error, a second makes the
// compensating delete fail too. The orphan device stays, and the failure is
// logged at Error with its id instead of being discarded.
func TestEnrollmentService_ConsumeCode_LogsAFailedCompensatingDelete(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	code, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	for _, q := range []string{
		`CREATE TRIGGER block_code_update BEFORE UPDATE ON enrollment_codes BEGIN SELECT RAISE(ABORT, 'injected consume failure'); END`,
		`CREATE TRIGGER block_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`,
	} {
		if _, err := st.DB().ExecContext(t.Context(), q); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
	}

	_, err = svc.ConsumeCode(t.Context(), code, ClientMeta{})

	if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want a plain failure (not ErrNotFound or ErrConflict)", err)
	}
	devices, err := st.Devices().ListByUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Devices.ListByUser: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want the 1 orphan the failed delete left", len(devices))
	}
	rec := onlyRecord(t, buf, "ERROR", msgRollbackFailed)
	if rec["device_id"] != devices[0].ID {
		t.Errorf("device_id = %v, want %s", rec["device_id"], devices[0].ID)
	}
	if got, _ := rec["error"].(string); got == "" {
		t.Errorf("error attribute = %v, want the cause", rec["error"])
	}
	assertNoSecrets(t, buf, code)
}
