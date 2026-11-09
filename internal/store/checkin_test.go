package store

import (
	"errors"
	"sync"
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

	out, err := s.RecordIPChange(ctx, IPChange{
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
	row := out.Row
	if !out.Changed {
		t.Error("RecordIPChange: Changed = false, want true for a first report")
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

// seedDeviceWithIPs gives a fresh device recorded addresses via the pool-side
// UpdateIP, so a test starts from a device that already holds both families.
func seedDeviceWithIPs(t *testing.T, s *Store, v4, v6 string) Device {
	t.Helper()
	d := seedDevice(t, s, seedUser(t, s).ID)
	if err := s.Devices().UpdateIP(t.Context(), d.ID, v4, v6, "", "", "", NowUnix()); err != nil {
		t.Fatalf("seed addresses: %v", err)
	}
	return d
}

func countHistory(t *testing.T, s *Store, deviceID string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM ip_history WHERE device_id = ?`, deviceID).Scan(&n); err != nil {
		t.Fatalf("count ip_history: %v", err)
	}
	return n
}

func TestRecordIPChangeMergesOmittedFamily(t *testing.T) {
	s, ctx := newTestStore(t)
	d := seedDeviceWithIPs(t, s, "1.1.1.1", "2606:4700::1")

	out, err := s.RecordIPChange(ctx, IPChange{DeviceID: d.ID, IPv4: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if out.CurrIPv4 != "8.8.8.8" || out.CurrIPv6 != "2606:4700::1" {
		t.Errorf("Curr = %q/%q, want 8.8.8.8/2606:4700::1", out.CurrIPv4, out.CurrIPv6)
	}
	if !out.Changed {
		t.Error("Changed = false, want true")
	}
	if out.Prev.CurrentIPv4 != "1.1.1.1" || out.Prev.CurrentIPv6 != "2606:4700::1" {
		t.Errorf("Prev = %q/%q, want the pre-change 1.1.1.1/2606:4700::1", out.Prev.CurrentIPv4, out.Prev.CurrentIPv6)
	}
	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentIPv4 != "8.8.8.8" || got.CurrentIPv6 != "2606:4700::1" {
		t.Errorf("stored = %q/%q, want 8.8.8.8/2606:4700::1: the omitted family must survive", got.CurrentIPv4, got.CurrentIPv6)
	}
}

func TestRecordIPChangeUnchangedTouches(t *testing.T) {
	s, ctx := newTestStore(t)
	d := seedDeviceWithIPs(t, s, "1.1.1.1", "2606:4700::1")
	setConfirmed(t, s, d.ID, 100, 100)
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at = 100 WHERE id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	before := countHistory(t, s, d.ID)

	out, err := s.RecordIPChange(ctx, IPChange{DeviceID: d.ID, IPv4: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Changed {
		t.Error("Changed = true, want false for identical addresses")
	}
	if out.Row != (IPHistory{}) {
		t.Errorf("Row = %+v, want zero: nothing was appended", out.Row)
	}
	if out.CurrIPv4 != "1.1.1.1" || out.CurrIPv6 != "2606:4700::1" {
		t.Errorf("Curr = %q/%q, want 1.1.1.1/2606:4700::1", out.CurrIPv4, out.CurrIPv6)
	}
	if n := countHistory(t, s, d.ID); n != before {
		t.Errorf("ip_history rows = %d, want %d: an unchanged check-in appends none", n, before)
	}
	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSeenAt <= 100 {
		t.Errorf("LastSeenAt = %d, want > 100: contact advances liveness", got.LastSeenAt)
	}
	if got.V4ConfirmedAt <= 100 {
		t.Errorf("V4ConfirmedAt = %d, want > 100: the asserted family advances", got.V4ConfirmedAt)
	}
	if got.V6ConfirmedAt != 100 {
		t.Errorf("V6ConfirmedAt = %d, want 100: the omitted family must not advance", got.V6ConfirmedAt)
	}
}

// Two per-family check-ins for one device race. The read, the merge and the
// write share one transaction, so neither may revert the other's family.
func TestRecordIPChangeConcurrentFamiliesBothSurvive(t *testing.T) {
	s, ctx := newTestStore(t)
	user := seedUser(t, s)

	for i := range 50 {
		d := seedDevice(t, s, user.ID)

		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, c := range []IPChange{
			{DeviceID: d.ID, IPv4: "8.8.8.8"},
			{DeviceID: d.ID, IPv6: "2606:4700::1"},
		} {
			wg.Go(func() {
				<-start
				if _, err := s.RecordIPChange(ctx, c); err != nil {
					t.Errorf("iteration %d: RecordIPChange: %v", i, err)
				}
			})
		}
		close(start)
		wg.Wait()

		got, err := s.Devices().GetByID(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.CurrentIPv4 != "8.8.8.8" || got.CurrentIPv6 != "2606:4700::1" {
			t.Fatalf("iteration %d: stored = %q/%q, want both families to survive", i, got.CurrentIPv4, got.CurrentIPv6)
		}
	}
}
