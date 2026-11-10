package service

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

const rotationNow = 1_800_000_000

// rotationFixture is a rotation service over a fresh store with one enabled
// owner and one device whose sealed secret opens to known.
type rotationFixture struct {
	st    *store.Store
	svc   *RotationService
	owner store.User
	dev   store.Device
	known []byte
	actor store.Session
}

func newRotationFixture(t *testing.T, certEnabled bool) rotationFixture {
	t.Helper()
	st := openTestStore(t)
	owner := seedUser(t, st, "owner@example.com", "user")
	known := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := auth.SealSecret(testKey32(), known)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	dev, err := st.Devices().Create(t.Context(), store.Device{UserID: owner.ID, Label: "laptop", SecretHash: sealed})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	svc := NewRotationService(st, testKey32(), NewAuditWriter(st), certEnabled)
	svc.now = func() time.Time { return time.Unix(rotationNow, 0) }
	return rotationFixture{
		st: st, svc: svc, owner: owner, dev: dev, known: known,
		actor: store.Session{UserID: "admin-1", IP: "203.0.113.9"},
	}
}

func (f rotationFixture) row(t *testing.T) store.Device {
	t.Helper()
	d, err := f.st.Devices().GetByID(t.Context(), f.dev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return d
}

func decodeDetails(t *testing.T, e store.AuditEntry) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(e.DetailsJSON), &m); err != nil {
		t.Fatalf("details %q: %v", e.DetailsJSON, err)
	}
	return m
}

func TestRotationStateOf(t *testing.T) {
	cases := []struct {
		name string
		d    store.Device
		want RotationState
	}{
		{"none", store.Device{SupportsRotation: true}, RotationState{}},
		{"old client", store.Device{RotateSecretAt: 5, RotateCertAt: 6},
			RotationState{TrackState{5, StatusAwaitingUpgrade}, TrackState{6, StatusAwaitingUpgrade}}},
		{"main port", store.Device{RotateSecretAt: 5, RotateCertAt: 6, SupportsRotation: true},
			RotationState{TrackState{5, StatusPending}, TrackState{6, StatusAwaitingMTLS}}},
		{"agent", store.Device{RotateCertAt: 6, SupportsRotation: true, LastCheckinMTLS: true},
			RotationState{Cert: TrackState{6, StatusPending}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RotationStateOf(c.d)
			if got != c.want {
				t.Errorf("RotationStateOf = %+v, want %+v", got, c.want)
			}
			if got.Pending() != (c.name != "none") {
				t.Errorf("Pending() = %v for %q", got.Pending(), c.name)
			}
		})
	}
}

func TestRotationService_CertEnabled(t *testing.T) {
	for _, want := range []bool{true, false} {
		f := newRotationFixture(t, want)
		if got := f.svc.CertEnabled(); got != want {
			t.Errorf("CertEnabled() = %v, want %v", got, want)
		}
	}
}

func TestRotationService_MarkErrors(t *testing.T) {
	cases := []struct {
		name        string
		certEnabled bool
		target      RotationTarget
		id          func(f rotationFixture, t *testing.T) string
		want        error
	}{
		{"invalid target", true, "x", func(f rotationFixture, _ *testing.T) string { return f.dev.ID }, ErrInvalidRotationTarget},
		{"cert unavailable", false, RotateCert, func(f rotationFixture, _ *testing.T) string { return f.dev.ID }, ErrCertRotationUnavailable},
		{"both unavailable", false, RotateBoth, func(f rotationFixture, _ *testing.T) string { return f.dev.ID }, ErrCertRotationUnavailable},
		{"disabled device", true, RotateSecret, func(f rotationFixture, t *testing.T) string {
			if err := f.st.Devices().SetDisabled(t.Context(), f.dev.ID, true); err != nil {
				t.Fatalf("SetDisabled: %v", err)
			}
			return f.dev.ID
		}, ErrDeviceDisabled},
		{"disabled owner", true, RotateSecret, func(f rotationFixture, t *testing.T) string {
			if err := f.st.Users().SetDisabled(t.Context(), f.owner.ID, true); err != nil {
				t.Fatalf("SetDisabled owner: %v", err)
			}
			return f.dev.ID
		}, ErrDeviceDisabled},
		{"unknown device", true, RotateSecret, func(rotationFixture, *testing.T) string { return "nope" }, store.ErrNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRotationFixture(t, c.certEnabled)
			id := c.id(f, t)
			before := f.row(t)

			_, err := f.svc.Mark(t.Context(), f.actor, id, c.target)
			if !errors.Is(err, c.want) {
				t.Fatalf("Mark err = %v, want %v", err, c.want)
			}
			after := f.row(t)
			if after.RotateSecretAt != before.RotateSecretAt || after.RotateCertAt != before.RotateCertAt {
				t.Errorf("row changed: before %+v after %+v", before, after)
			}
			if rows := auditRows(t, f.st, "device.rotation.requested"); len(rows) != 0 {
				t.Errorf("audit rows = %d, want 0", len(rows))
			}
		})
	}
}

func TestRotationService_MarkAllErrors(t *testing.T) {
	cases := []struct {
		name        string
		certEnabled bool
		target      RotationTarget
		want        error
	}{
		{"unknown target", true, "x", ErrInvalidRotationTarget},
		{"empty target", true, "", ErrInvalidRotationTarget},
		{"cert unavailable", false, RotateBoth, ErrCertRotationUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRotationFixture(t, c.certEnabled)
			_, err := f.svc.MarkAll(t.Context(), f.actor, c.target)
			if !errors.Is(err, c.want) {
				t.Fatalf("MarkAll err = %v, want %v", err, c.want)
			}
			if d := f.row(t); d.RotateSecretAt != 0 || d.RotateCertAt != 0 {
				t.Errorf("row marked: %+v", d)
			}
			if rows := auditRows(t, f.st, "device.rotation.requested"); len(rows) != 0 {
				t.Errorf("audit rows = %d, want 0", len(rows))
			}
		})
	}
}

func TestRotationService_MarkAudits(t *testing.T) {
	f := newRotationFixture(t, true)

	got, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateBoth)
	if err != nil {
		t.Fatalf("Mark: %v", err)
	}
	want := f.svc.now().Unix()
	if got.RotateSecretAt != want || got.RotateCertAt != want {
		t.Errorf("returned device marks = %d/%d, want %d", got.RotateSecretAt, got.RotateCertAt, want)
	}
	if row := f.row(t); row.RotateSecretAt != want || row.RotateCertAt != want {
		t.Errorf("row marks = %d/%d, want %d", row.RotateSecretAt, row.RotateCertAt, want)
	}

	rows := auditRows(t, f.st, "device.rotation.requested")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.ActorUserID != f.actor.UserID || e.IP != f.actor.IP || e.TargetType != "device" || e.TargetID != f.dev.ID {
		t.Errorf("audit entry = %+v", e)
	}
	d := decodeDetails(t, e)
	if d["target"] != "both" || d["owner_user_id"] != f.owner.ID {
		t.Errorf("details = %v", d)
	}
}

func TestRotationService_MarkAllAudits(t *testing.T) {
	f := newRotationFixture(t, true)
	// A second device of a disabled owner is skipped and counted.
	off := seedUserWithDisabled(t, t.Context(), f.st, true)
	seedDeviceWith(t, t.Context(), f.st, off.ID, "off", "", "", false)

	got, err := f.svc.MarkAll(t.Context(), f.actor, RotateSecret)
	if err != nil {
		t.Fatalf("MarkAll: %v", err)
	}
	if want := (store.RotationCounts{Marked: 1, AwaitingUpgrade: 1, SkippedDisabled: 1}); got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}

	rows := auditRows(t, f.st, "device.rotation.requested")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.TargetType != "device" || e.TargetID != "" || e.ActorUserID != f.actor.UserID || e.IP != f.actor.IP {
		t.Errorf("audit entry = %+v", e)
	}
	d := decodeDetails(t, e)
	for k, want := range map[string]float64{"marked": 1, "awaiting_upgrade": 1, "awaiting_mtls": 0, "skipped_disabled": 1} {
		if d[k] != want {
			t.Errorf("details[%q] = %v, want %v", k, d[k], want)
		}
	}
	if d["target"] != "secret" {
		t.Errorf("details[target] = %v", d["target"])
	}
}

func TestRotationService_CancelAuditsOnlyWhenCleared(t *testing.T) {
	f := newRotationFixture(t, true)
	if _, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateSecret); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	for range 2 {
		if err := f.svc.Cancel(t.Context(), f.actor, f.dev.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
	}
	rows := auditRows(t, f.st, "device.rotation.cancelled")
	if len(rows) != 1 {
		t.Fatalf("cancelled rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.ActorUserID != f.actor.UserID || e.IP != f.actor.IP || e.TargetType != "device" || e.TargetID != f.dev.ID {
		t.Errorf("audit entry = %+v", e)
	}
	if d := decodeDetails(t, e); d["owner_user_id"] != f.owner.ID {
		t.Errorf("details = %v", d)
	}
	if err := f.svc.Cancel(t.Context(), f.actor, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Cancel unknown = %v, want ErrNotFound", err)
	}
}

func TestRotationService_StorePendingSecret(t *testing.T) {
	t.Run("unmarked", func(t *testing.T) {
		f := newRotationFixture(t, true)
		err := f.svc.StorePendingSecret(t.Context(), f.dev.ID, []byte("fedcba9876543210fedcba9876543210"))
		if !errors.Is(err, ErrNoSecretRotationPending) {
			t.Fatalf("err = %v, want ErrNoSecretRotationPending", err)
		}
	})
	t.Run("stores sealed", func(t *testing.T) {
		f := newRotationFixture(t, true)
		if _, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateSecret); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		next := []byte("fedcba9876543210fedcba9876543210")
		if err := f.svc.StorePendingSecret(t.Context(), f.dev.ID, next); err != nil {
			t.Fatalf("StorePendingSecret: %v", err)
		}
		got, err := auth.OpenSecret(testKey32(), f.row(t).PendingSecretHash)
		if err != nil {
			t.Fatalf("OpenSecret: %v", err)
		}
		if string(got) != string(next) {
			t.Errorf("pending secret = %x, want %x", got, next)
		}
	})
	t.Run("equal to current is a no-op", func(t *testing.T) {
		f := newRotationFixture(t, true)
		if _, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateSecret); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		if err := f.svc.StorePendingSecret(t.Context(), f.dev.ID, f.known); err != nil {
			t.Fatalf("StorePendingSecret: %v", err)
		}
		if got := f.row(t).PendingSecretHash; got != "" {
			t.Errorf("PendingSecretHash = %q, want empty", got)
		}
	})
	t.Run("current secret does not open", func(t *testing.T) {
		f := newRotationFixture(t, true)
		bad := seedDevice(t, f.st, f.owner.ID, "unopenable") // "sealed-secret" is not a sealed value
		err := f.svc.StorePendingSecret(t.Context(), bad.ID, []byte("fedcba9876543210fedcba9876543210"))
		if err == nil || errors.Is(err, ErrNoSecretRotationPending) {
			t.Fatalf("err = %v, want a wrapped open failure", err)
		}
	})
	t.Run("unknown device", func(t *testing.T) {
		f := newRotationFixture(t, true)
		err := f.svc.StorePendingSecret(t.Context(), "nope", []byte("x"))
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestRotationService_PromoteSecretAuditsOnce(t *testing.T) {
	f := newRotationFixture(t, true)
	if _, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateSecret); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if err := f.svc.StorePendingSecret(t.Context(), f.dev.ID, []byte("fedcba9876543210fedcba9876543210")); err != nil {
		t.Fatalf("StorePendingSecret: %v", err)
	}
	sealed := f.row(t).PendingSecretHash

	for i := range 2 {
		ok, err := f.svc.PromoteSecret(t.Context(), f.dev.ID, sealed)
		if err != nil || !ok {
			t.Fatalf("PromoteSecret #%d = %v, %v; want true, nil", i, ok, err)
		}
	}
	rows := auditRows(t, f.st, "device.rotation.completed")
	if len(rows) != 1 {
		t.Fatalf("completed rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.ActorUserID != "" || e.TargetType != "device" || e.TargetID != f.dev.ID {
		t.Errorf("audit entry = %+v", e)
	}
	if d := decodeDetails(t, e); d["track"] != "secret" || len(d) != 1 {
		t.Errorf("details = %v", d)
	}

	ok, err := f.svc.PromoteSecret(t.Context(), f.dev.ID, "some-other-sealed-value")
	if err != nil || ok {
		t.Errorf("PromoteSecret(other) = %v, %v; want false, nil", ok, err)
	}
}

func TestRotationService_PromoteCert(t *testing.T) {
	f := newRotationFixture(t, true)
	if _, err := f.svc.Mark(t.Context(), f.actor, f.dev.ID, RotateCert); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if err := f.st.Devices().SetPendingCert(t.Context(), f.dev.ID, "0b"); err != nil {
		t.Fatalf("SetPendingCert: %v", err)
	}
	ok, err := f.svc.PromoteCert(t.Context(), f.dev.ID, "0b", rotationNow+3600, true)
	if err != nil || !ok {
		t.Fatalf("PromoteCert = %v, %v; want true, nil", ok, err)
	}
	if row := f.row(t); row.CertSerial != "0b" || row.PendingCertSerial != "" || row.RotateCertAt != 0 {
		t.Errorf("row = %+v", row)
	}
	rows := auditRows(t, f.st, "device.rotation.completed")
	if len(rows) != 1 {
		t.Fatalf("completed rows = %d, want 1", len(rows))
	}
	e := rows[0]
	if e.ActorUserID != "" || e.TargetType != "device" || e.TargetID != f.dev.ID {
		t.Errorf("audit entry = %+v", e)
	}
	if d := decodeDetails(t, e); d["track"] != "cert" || d["serial"] != "0b" {
		t.Errorf("details = %v", d)
	}
}

func TestRotationService_PromoteCertRoutineRenewalSilent(t *testing.T) {
	f := newRotationFixture(t, true)
	if err := f.st.Devices().SetPendingCert(t.Context(), f.dev.ID, "0c"); err != nil {
		t.Fatalf("SetPendingCert: %v", err)
	}
	ok, err := f.svc.PromoteCert(t.Context(), f.dev.ID, "0c", rotationNow+3600, false)
	if err != nil || !ok {
		t.Fatalf("PromoteCert = %v, %v; want true, nil", ok, err)
	}
	if row := f.row(t); row.CertSerial != "0c" || row.PendingCertSerial != "" {
		t.Errorf("row not promoted: %+v", row)
	}
	if rows := auditRows(t, f.st, "device.rotation.completed"); len(rows) != 0 {
		t.Errorf("completed rows = %d, want 0", len(rows))
	}
}
