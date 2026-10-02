package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// A failed redeem must not leave an orphan device (#9). These tests pin what
// only the service can show: the compensating delete outlives a cancelled
// request, and a conflict is a lost race or a label clash depending on the
// re-read. The label clash and the failed delete are driven end to end in
// api/enroll_errors_test.go.

// TestEnrollmentService_RollbackDevice_SurvivesACancelledContext: a Consume that
// failed on a cancelled request context would make an ordinary delete fail for
// the same reason and leave an orphan device, which the next redeem of the code
// would then meet as a 409. rollbackDevice therefore deletes on a context that
// survives cancellation. It is tested directly: a test cannot inject a
// cancellation between the insert and Consume inside one ConsumeCode call.
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

// TestEnrollmentService_ConflictRejection_UsedCodeIsALostRace: two requests
// redeem one code and both pass the pre-check. The winner's device already
// holds the label, so the loser's insert fails with ErrConflict before it
// reaches Consume. The code now reads as used, so it is a lost race (the
// uniform ErrNotFound), not a label clash.
func TestEnrollmentService_ConflictRejection_UsedCodeIsALostRace(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	code, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	read, err := st.EnrollmentCodes().Get(t.Context(), code) // as the loser read it, before the winner redeemed
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}
	if _, err := svc.ConsumeCode(t.Context(), code, ClientMeta{}); err != nil {
		t.Fatalf("winner ConsumeCode: %v", err)
	}
	buf.reset()

	got := svc.conflictRejection(t.Context(), code, read, fmt.Errorf("devices.Create: %w", store.ErrConflict))

	if !errors.Is(got, store.ErrNotFound) || errors.Is(got, store.ErrConflict) {
		t.Errorf("err = %v, want ErrNotFound and not ErrConflict", got)
	}
	wantRejection(t, buf, msgCodeRejected, rejectLostRace, user.ID)
	assertNoSecrets(t, buf, code)
}

// TestEnrollmentService_ConflictRejection_UnusedCodeIsALabelConflict: the code
// is still unused, so the label is held by some other device: a real clash.
func TestEnrollmentService_ConflictRejection_UnusedCodeIsALabelConflict(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	code, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	read, err := st.EnrollmentCodes().Get(t.Context(), code)
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}

	got := svc.conflictRejection(t.Context(), code, read, fmt.Errorf("devices.Create: %w", store.ErrConflict))

	if !errors.Is(got, store.ErrConflict) || errors.Is(got, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrConflict and not ErrNotFound", got)
	}
	wantRejection(t, buf, msgCodeRejected, rejectLabelConflict, user.ID)
	assertNoSecrets(t, buf, code)
}
