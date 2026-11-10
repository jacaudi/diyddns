package store

import (
	"errors"
	"testing"
)

func TestMigration012_Shape(t *testing.T) {
	s, _ := newTestStore(t)
	_, dev := tableColumns(t, s, "devices")
	want := map[string]colInfo{
		"rotate_secret_at":    {typ: "INTEGER"},
		"rotate_cert_at":      {typ: "INTEGER"},
		"pending_secret_hash": {typ: "TEXT"},
		"pending_cert_serial": {typ: "TEXT"},
		"supports_rotation":   {typ: "INTEGER", notNull: true},
		"last_checkin_mtls":   {typ: "INTEGER", notNull: true},
	}
	for col, w := range want {
		if got, ok := dev[col]; !ok || got != w {
			t.Errorf("devices.%s = %+v (present %v), want %+v", col, got, ok, w)
		}
	}
	if _, ok := dev["pending_cert_not_after"]; ok {
		t.Error("pending_cert_not_after exists; P5 dropped it")
	}
}

func TestDevice_RotationFieldsDefaultZero(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "z@example.com", "home")
	d, err := s.Devices().GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if d.RotateSecretAt != 0 || d.RotateCertAt != 0 || d.PendingSecretHash != "" ||
		d.PendingCertSerial != "" || d.SupportsRotation || d.LastCheckinMTLS {
		t.Errorf("fresh device rotation fields = %+v, want zero", d)
	}
}

// checkin records one check-in for id through the production path.
func checkin(t *testing.T, s *Store, id, ipv4 string, supports, viaAgent bool) {
	t.Helper()
	if _, err := s.RecordIPChange(t.Context(), IPChange{
		DeviceID: id, IPv4: ipv4, SupportsRotation: supports, ViaAgent: viaAgent,
	}); err != nil {
		t.Fatalf("RecordIPChange: %v", err)
	}
}

func mustNo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkRotation_UnionNeverRestarts(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "m@example.com", "home")
	r := s.Devices()
	mustNo(t, r.MarkRotation(ctx, id, true, false, 100))
	mustNo(t, r.MarkRotation(ctx, id, false, true, 200))
	mustNo(t, r.MarkRotation(ctx, id, true, true, 300))
	d, _ := r.GetByID(ctx, id)
	if d.RotateSecretAt != 100 || d.RotateCertAt != 200 {
		t.Errorf("at = (%d,%d), want (100,200)", d.RotateSecretAt, d.RotateCertAt)
	}
	if err := r.MarkRotation(ctx, "nope", true, false, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v, want ErrNotFound", err)
	}
}

func TestMarkAllRotation_Counts(t *testing.T) {
	s, ctx := newTestStore(t)
	r := s.Devices()
	d1 := seedCertDevice(t, ctx, s, "1@example.com", "one")
	d2 := seedCertDevice(t, ctx, s, "2@example.com", "two")
	d3 := seedCertDevice(t, ctx, s, "3@example.com", "three")
	d4 := seedCertDevice(t, ctx, s, "4@example.com", "four")
	d5 := seedCertDevice(t, ctx, s, "5@example.com", "five")
	checkin(t, s, d1, "203.0.113.9", true, true)
	checkin(t, s, d2, "203.0.113.9", false, false)
	checkin(t, s, d3, "203.0.113.9", true, false)
	mustNo(t, r.SetDisabled(ctx, d4, true))
	dev5, err := r.GetByID(ctx, d5)
	mustNo(t, err)
	mustNo(t, s.Users().SetDisabled(ctx, dev5.UserID, true))

	got, err := r.MarkAllRotation(ctx, false, true, 500)
	mustNo(t, err)
	want := RotationCounts{Marked: 3, AwaitingUpgrade: 1, AwaitingMTLS: 1, SkippedDisabled: 2}
	if got != want {
		t.Errorf("cert track counts = %+v, want %+v", got, want)
	}
	for id, wantAt := range map[string]int64{d1: 500, d2: 500, d3: 500, d4: 0, d5: 0} {
		d, err := r.GetByID(ctx, id)
		mustNo(t, err)
		if d.RotateCertAt != wantAt {
			t.Errorf("device %s RotateCertAt = %d, want %d", id, d.RotateCertAt, wantAt)
		}
	}

	got, err = r.MarkAllRotation(ctx, true, false, 600)
	mustNo(t, err)
	want = RotationCounts{Marked: 3, AwaitingUpgrade: 1, AwaitingMTLS: 0, SkippedDisabled: 2}
	if got != want {
		t.Errorf("secret track counts = %+v, want %+v", got, want)
	}

	t.Run("empty table", func(t *testing.T) {
		empty, _ := newTestStore(t)
		got, err := empty.Devices().MarkAllRotation(t.Context(), true, true, 1)
		mustNo(t, err)
		if got != (RotationCounts{}) {
			t.Errorf("counts = %+v, want zero", got)
		}
	})
}

func TestCancelRotation_KeepsPendingCert(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "c@example.com", "home")
	r := s.Devices()
	mustNo(t, r.MarkRotation(ctx, id, true, true, 100))
	stored, err := r.SetPendingSecret(ctx, id, "sealedX", "h")
	mustNo(t, err)
	if !stored {
		t.Fatal("SetPendingSecret stored = false, want true")
	}
	mustNo(t, r.SetPendingCert(ctx, id, "0b0b"))

	cleared, err := r.CancelRotation(ctx, id)
	mustNo(t, err)
	if !cleared {
		t.Error("CancelRotation cleared = false, want true")
	}
	d, _ := r.GetByID(ctx, id)
	if d.RotateSecretAt != 0 || d.RotateCertAt != 0 || d.PendingSecretHash != "" || d.PendingCertSerial != "0b0b" {
		t.Errorf("row = %+v, want marks and pending secret cleared, pending cert kept", d)
	}

	cleared, err = r.CancelRotation(ctx, id)
	if err != nil || cleared {
		t.Errorf("second CancelRotation = (%v, %v), want (false, nil)", cleared, err)
	}
	if _, err := r.CancelRotation(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v, want ErrNotFound", err)
	}
}

func TestSetPendingSecret_RequiresMarkAndCurrent(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "p@example.com", "home")
	r := s.Devices()

	stored, err := r.SetPendingSecret(ctx, id, "sealedX", "h")
	mustNo(t, err)
	if stored {
		t.Error("unmarked: stored = true, want false")
	}
	if d, _ := r.GetByID(ctx, id); d.PendingSecretHash != "" {
		t.Errorf("unmarked: PendingSecretHash = %q, want empty", d.PendingSecretHash)
	}

	mustNo(t, r.MarkRotation(ctx, id, true, false, 100))
	stored, err = r.SetPendingSecret(ctx, id, "sealedX", "h")
	mustNo(t, err)
	if !stored {
		t.Error("marked: stored = false, want true")
	}
	if d, _ := r.GetByID(ctx, id); d.PendingSecretHash != "sealedX" {
		t.Errorf("marked: PendingSecretHash = %q, want sealedX", d.PendingSecretHash)
	}

	stored, err = r.SetPendingSecret(ctx, id, "sealedY", "other")
	mustNo(t, err)
	if stored {
		t.Error("stale current: stored = true, want false")
	}
	if d, _ := r.GetByID(ctx, id); d.PendingSecretHash != "sealedX" {
		t.Errorf("stale current: PendingSecretHash = %q, want sealedX", d.PendingSecretHash)
	}
}

func TestPromoteSecret_Outcomes(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "ps@example.com", "home")
	r := s.Devices()
	mustNo(t, r.MarkRotation(ctx, id, true, false, 100))
	_, err := r.SetPendingSecret(ctx, id, "p1", "h")
	mustNo(t, err)

	promoted, accepted, err := r.PromoteSecret(ctx, id, "p1")
	mustNo(t, err)
	if !promoted || !accepted {
		t.Errorf("promotes = (%v, %v), want (true, true)", promoted, accepted)
	}
	d, _ := r.GetByID(ctx, id)
	if d.SecretHash != "p1" || d.PendingSecretHash != "" || d.RotateSecretAt != 0 {
		t.Errorf("after promote row = %+v", d)
	}

	promoted, accepted, err = r.PromoteSecret(ctx, id, "p1")
	mustNo(t, err)
	if promoted || !accepted {
		t.Errorf("already current = (%v, %v), want (false, true)", promoted, accepted)
	}

	mustNo(t, r.MarkRotation(ctx, id, true, false, 200))
	_, err = r.SetPendingSecret(ctx, id, "p2", "p1")
	mustNo(t, err)
	promoted, accepted, err = r.PromoteSecret(ctx, id, "p3")
	mustNo(t, err)
	if promoted || accepted {
		t.Errorf("superseded = (%v, %v), want (false, false)", promoted, accepted)
	}

	_, err = r.SetPendingSecret(ctx, id, "p4", "p1")
	mustNo(t, err)
	mustNo(t, r.RotateSecret(ctx, id, "owner"))
	promoted, accepted, err = r.PromoteSecret(ctx, id, "p4")
	mustNo(t, err)
	if promoted || accepted {
		t.Errorf("owner rotate raced = (%v, %v), want (false, false)", promoted, accepted)
	}
	if d, _ := r.GetByID(ctx, id); d.SecretHash != "owner" {
		t.Errorf("SecretHash = %q, want owner", d.SecretHash)
	}
}

func TestPromoteCert_Outcomes(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "pc@example.com", "home")
	r := s.Devices()
	mustNo(t, r.SetCert(ctx, id, "0a", 1000))
	mustNo(t, r.MarkRotation(ctx, id, false, true, 100))
	mustNo(t, r.SetPendingCert(ctx, id, "0b"))

	promoted, accepted, err := r.PromoteCert(ctx, id, "0b", 2000)
	mustNo(t, err)
	if !promoted || !accepted {
		t.Errorf("promotes = (%v, %v), want (true, true)", promoted, accepted)
	}
	d, _ := r.GetByID(ctx, id)
	if d.CertSerial != "0b" || d.CertNotAfter != 2000 || d.PendingCertSerial != "" || d.RotateCertAt != 0 {
		t.Errorf("after promote row = %+v", d)
	}

	promoted, accepted, err = r.PromoteCert(ctx, id, "0b", 2000)
	mustNo(t, err)
	if promoted || !accepted {
		t.Errorf("already current = (%v, %v), want (false, true)", promoted, accepted)
	}

	promoted, accepted, err = r.PromoteCert(ctx, id, "0c", 3000)
	mustNo(t, err)
	if promoted || accepted {
		t.Errorf("unknown serial = (%v, %v), want (false, false)", promoted, accepted)
	}
}

func TestRotateSecret_ClearsPending(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "rs@example.com", "home")
	r := s.Devices()
	mustNo(t, r.MarkRotation(ctx, id, true, false, 100))
	_, err := r.SetPendingSecret(ctx, id, "p", "h")
	mustNo(t, err)
	mustNo(t, r.RotateSecret(ctx, id, "owner"))
	d, _ := r.GetByID(ctx, id)
	if d.SecretHash != "owner" || d.PendingSecretHash != "" || d.RotateSecretAt != 0 {
		t.Errorf("row = %+v, want owner secret with pending and mark cleared", d)
	}
}

func TestRecordIPChange_WritesRotationFlags(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "f@example.com", "home")
	get := func() Device {
		t.Helper()
		d, err := s.Devices().GetByID(ctx, id)
		mustNo(t, err)
		return d
	}

	checkin(t, s, id, "203.0.113.9", true, true)
	checkin(t, s, id, "203.0.113.9", true, true) // unchanged IP: touch path
	if d := get(); !d.SupportsRotation || !d.LastCheckinMTLS {
		t.Errorf("touch path flags = (%v, %v), want (true, true)", d.SupportsRotation, d.LastCheckinMTLS)
	}

	checkin(t, s, id, "203.0.113.10", false, false) // changed IP: update path
	if d := get(); d.SupportsRotation || d.LastCheckinMTLS {
		t.Errorf("update path flags = (%v, %v), want (false, false)", d.SupportsRotation, d.LastCheckinMTLS)
	}

	checkin(t, s, id, "203.0.113.10", true, true) // touch path again
	if d := get(); !d.SupportsRotation || !d.LastCheckinMTLS {
		t.Errorf("touch path flags = (%v, %v), want (true, true)", d.SupportsRotation, d.LastCheckinMTLS)
	}
}
