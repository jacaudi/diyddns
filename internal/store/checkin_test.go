package store

import (
	"errors"
	"testing"
)

func TestRecordIPChangeWritesBothRowsWithOneTimestamp(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "grace@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "router", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	row, err := s.RecordIPChange(ctx, IPChange{
		DeviceID:      d.ID,
		IPv4:          "203.0.113.9",
		IPv6:          "2001:db8::9",
		ClientVersion: "v1.2.3",
		Hostname:      "rtr",
		OS:            "linux",
	})
	if err != nil {
		t.Fatalf("RecordIPChange: %v", err)
	}
	if row.ID == 0 {
		t.Error("RecordIPChange: returned history row has ID 0, want the inserted rowid")
	}

	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CurrentIPv4 != "203.0.113.9" || got.CurrentIPv6 != "2001:db8::9" {
		t.Errorf("device addresses = %q/%q, want 203.0.113.9/2001:db8::9", got.CurrentIPv4, got.CurrentIPv6)
	}
	if got.Hostname != "rtr" || got.OS != "linux" || got.ClientVersion != "v1.2.3" {
		t.Errorf("device metadata = %q/%q/%q, want rtr/linux/v1.2.3", got.Hostname, got.OS, got.ClientVersion)
	}

	// The device row and its history row describe one event, so they must
	// carry the same second — not two NowUnix() calls that can straddle one.
	if got.LastSeenAt != row.ObservedAt {
		t.Errorf("device LastSeenAt = %d, ip_history ObservedAt = %d, want the same instant", got.LastSeenAt, row.ObservedAt)
	}
	if got.UpdatedAt != row.ObservedAt {
		t.Errorf("device UpdatedAt = %d, ip_history ObservedAt = %d, want the same instant", got.UpdatedAt, row.ObservedAt)
	}

	latest, err := s.IPHistory().Latest(ctx, d.ID)
	if err != nil {
		t.Fatalf("IPHistory.Latest: %v", err)
	}
	if latest.ID != row.ID || latest.IPv4 != "203.0.113.9" {
		t.Errorf("latest history row = %+v, want the row RecordIPChange returned", latest)
	}
}

func TestRecordIPChangeUnknownDeviceWritesNothing(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.RecordIPChange(ctx, IPChange{DeviceID: "nonexistent-id", IPv4: "203.0.113.9"})
	if err == nil {
		t.Fatal("RecordIPChange: error = nil, want ErrNotFound")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RecordIPChange: got %v, want ErrNotFound", err)
	}

	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_history`).Scan(&n); err != nil {
		t.Fatalf("count ip_history: %v", err)
	}
	if n != 0 {
		t.Errorf("ip_history rows = %d, want 0 — the failed update must roll back before any insert", n)
	}
}
