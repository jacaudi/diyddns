package store

import (
	"context"
	"errors"
	"testing"
)

// seedCertDevice creates a user and one device and returns the device ID.
func seedCertDevice(t *testing.T, ctx context.Context, s *Store, email, label string) string {
	t.Helper()
	u, err := s.Users().Create(ctx, User{Email: email, Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: label, SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	return d.ID
}

func TestSetCert_RoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "a@example.com", "home")

	if err := s.Devices().SetCert(ctx, id, "0a1b", 1900000000); err != nil {
		t.Fatalf("SetCert: %v", err)
	}

	got, err := s.Devices().GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CertSerial != "0a1b" || got.CertNotAfter != 1900000000 {
		t.Errorf("GetByID cert = (%q, %d), want (%q, %d)", got.CertSerial, got.CertNotAfter, "0a1b", 1900000000)
	}

	byUser, err := s.Devices().ListByUser(ctx, got.UserID)
	if err != nil || len(byUser) != 1 {
		t.Fatalf("ListByUser = %v, %v; want 1 device", byUser, err)
	}
	if byUser[0].CertSerial != "0a1b" || byUser[0].CertNotAfter != 1900000000 {
		t.Errorf("ListByUser cert = (%q, %d)", byUser[0].CertSerial, byUser[0].CertNotAfter)
	}

	all, err := s.Devices().ListAll(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListAll = %v, %v; want 1 device", all, err)
	}
	if all[0].CertSerial != "0a1b" || all[0].CertNotAfter != 1900000000 {
		t.Errorf("ListAll cert = (%q, %d)", all[0].CertSerial, all[0].CertNotAfter)
	}
}

func TestSetCert_UnknownDeviceNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.Devices().SetCert(ctx, "nope", "01", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetCert unknown: err = %v, want ErrNotFound", err)
	}
}

func TestSetCertIfNoLive_SecondCallConflicts(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "a@example.com", "home")
	repo := s.Devices()

	if err := repo.SetCertIfNoLive(ctx, id, "aa", 5000, 1000); err != nil {
		t.Fatalf("first SetCertIfNoLive: %v", err)
	}
	if err := repo.SetCertIfNoLive(ctx, id, "bb", 6000, 1001); !errors.Is(err, ErrConflict) {
		t.Fatalf("second SetCertIfNoLive: err = %v, want ErrConflict", err)
	}
	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CertSerial != "aa" {
		t.Errorf("CertSerial after conflict = %q, want %q", got.CertSerial, "aa")
	}

	// cert_not_after <= now means the recorded cert is expired, so it is replaced.
	if err := repo.SetCertIfNoLive(ctx, id, "cc", 9000, 5000); err != nil {
		t.Fatalf("SetCertIfNoLive over expired cert: %v", err)
	}
	got, err = repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CertSerial != "cc" || got.CertNotAfter != 9000 {
		t.Errorf("cert after replace = (%q, %d), want (%q, %d)", got.CertSerial, got.CertNotAfter, "cc", 9000)
	}
}

func TestSetCertIfNoLive_UnknownDeviceNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.Devices().SetCertIfNoLive(ctx, "nope", "01", 5000, 1000); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestClearCert(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "a@example.com", "home")
	repo := s.Devices()

	if err := repo.SetCert(ctx, id, "0a1b", 1900000000); err != nil {
		t.Fatalf("SetCert: %v", err)
	}

	cleared, err := repo.ClearCert(ctx, id)
	if err != nil || !cleared {
		t.Fatalf("ClearCert = (%v, %v), want (true, nil)", cleared, err)
	}
	var serial, notAfter any
	if err := s.DB().QueryRowContext(ctx,
		`SELECT cert_serial, cert_not_after FROM devices WHERE id = ?`, id,
	).Scan(&serial, &notAfter); err != nil {
		t.Fatalf("select: %v", err)
	}
	if serial != nil || notAfter != nil {
		t.Errorf("columns after clear = (%v, %v), want both NULL", serial, notAfter)
	}

	cleared, err = repo.ClearCert(ctx, id)
	if err != nil || cleared {
		t.Fatalf("second ClearCert = (%v, %v), want (false, nil)", cleared, err)
	}

	if _, err := repo.ClearCert(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ClearCert unknown: err = %v, want ErrNotFound", err)
	}
}
