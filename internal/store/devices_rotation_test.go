package store

import "testing"

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
