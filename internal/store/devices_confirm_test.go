package store

import (
	"fmt"
	"testing"
)

// seedUser creates a user with a unique email, for the tests in this file
// that need a device owner but don't care who it is.
func seedUser(t *testing.T, s *Store) User {
	t.Helper()
	u, err := s.Users().Create(t.Context(), User{
		Email: fmt.Sprintf("%s@example.com", NewID()),
		Role:  "user",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// seedDevice creates a device for userID with a unique label, for the tests
// in this file that need a device but don't care about its identity.
func seedDevice(t *testing.T, s *Store, userID string) Device {
	t.Helper()
	d, err := s.Devices().Create(t.Context(), Device{
		UserID:     userID,
		Label:      NewID(),
		SecretHash: "h",
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d
}

// setConfirmed sets v4_confirmed_at and v6_confirmed_at directly, bypassing
// Touch/updateDeviceIP so a test can establish a starting instant independent
// of the code under test.
func setConfirmed(t *testing.T, s *Store, deviceID string, v4, v6 int64) {
	t.Helper()
	if _, err := s.DB().ExecContext(t.Context(),
		`UPDATE devices SET v4_confirmed_at = ?, v6_confirmed_at = ? WHERE id = ?`,
		v4, v6, deviceID,
	); err != nil {
		t.Fatalf("setConfirmed: %v", err)
	}
}

// setWarnLevels sets v4_warn_level and v6_warn_level directly, bypassing
// Touch/updateDeviceIP so a test can establish a starting level independent
// of the code under test.
func setWarnLevels(t *testing.T, s *Store, deviceID string, v4, v6 int) {
	t.Helper()
	if _, err := s.DB().ExecContext(t.Context(),
		`UPDATE devices SET v4_warn_level = ?, v6_warn_level = ? WHERE id = ?`,
		v4, v6, deviceID,
	); err != nil {
		t.Fatalf("setWarnLevels: %v", err)
	}
}

func TestDevice_NewColumnsRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	u := seedUser(t, s)

	d := Device{
		ID: NewID(), UserID: u.ID, Label: "dev", SecretHash: "h",
		CurrentIPv4: "1.2.3.4", CurrentIPv6: "2001:db8::1",
		V4ConfirmedAt: 1000, V6ConfirmedAt: 2000,
		V4WarnLevel: 3, V6WarnLevel: 1,
	}
	if _, err := s.Devices().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"V4ConfirmedAt", got.V4ConfirmedAt, int64(1000)},
		{"V6ConfirmedAt", got.V6ConfirmedAt, int64(2000)},
		{"V4WarnLevel", got.V4WarnLevel, 3},
		{"V6WarnLevel", got.V6WarnLevel, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// D6: an omitted family is NOT asserted, and its instant must not advance.
// This is the whole basis of per-family expiry -- a host whose IPv6 tunnel
// died keeps reporting IPv4 every five minutes and is never silent.
func TestTouch_AdvancesOnlyAssertedInstants(t *testing.T) {
	s, ctx := newTestStore(t)
	d := seedDevice(t, s, seedUser(t, s).ID)
	setConfirmed(t, s, d.ID, 100, 100)

	if err := s.Devices().Touch(ctx, d.ID, true, false, 9000); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Devices().GetByID(ctx, d.ID)
	if got.V4ConfirmedAt != 9000 {
		t.Errorf("V4ConfirmedAt = %d, want 9000", got.V4ConfirmedAt)
	}
	if got.V6ConfirmedAt != 100 {
		t.Errorf("V6ConfirmedAt = %d, want 100: an omitted family must not advance", got.V6ConfirmedAt)
	}
}

// D12, and the defect that broke revision 8: the reset must reach a device
// that is NOT expired. A device that went quiet, collected rungs 1 and 2, and
// came back before its window elapsed must land at level 0 -- otherwise it
// keeps a stale level and fires nothing before removal.
func TestTouch_ResetsWarnLevelPerAssertedFamily(t *testing.T) {
	s, ctx := newTestStore(t)
	for _, tc := range []struct {
		name                   string
		v4Asserted, v6Asserted bool
		wantV4, wantV6         int
	}{
		{"both asserted", true, true, 0, 0},
		{"only v4 asserted", true, false, 0, 2},
		{"only v6 asserted", false, true, 2, 0},
		{"neither asserted", false, false, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := seedDevice(t, s, seedUser(t, s).ID)
			setWarnLevels(t, s, d.ID, 2, 2)

			if err := s.Devices().Touch(ctx, d.ID, tc.v4Asserted, tc.v6Asserted, 5000); err != nil {
				t.Fatal(err)
			}
			got, _ := s.Devices().GetByID(ctx, d.ID)
			if got.V4WarnLevel != tc.wantV4 || got.V6WarnLevel != tc.wantV6 {
				t.Errorf("levels = (%d,%d), want (%d,%d)",
					got.V4WarnLevel, got.V6WarnLevel, tc.wantV4, tc.wantV6)
			}
		})
	}
}

// The change branch carries the same obligation as the Touch branch.
func TestRecordIPChange_AdvancesInstantsAndResetsLevels(t *testing.T) {
	s, ctx := newTestStore(t)
	d := seedDevice(t, s, seedUser(t, s).ID)
	setConfirmed(t, s, d.ID, 100, 100)
	setWarnLevels(t, s, d.ID, 3, 3)

	// IPv6 here is the MERGED effective value production actually sends —
	// non-empty even though the family is unasserted (the merge preserves
	// the stored value rather than clearing it; see service.Checkin). If
	// RecordIPChange were ever "simplified" to derive assertion from
	// c.IPv6 != "" instead of taking V6Asserted from the caller, this would
	// wrongly treat IPv6 as asserted, advance V6ConfirmedAt, and reset
	// V6WarnLevel — exactly what the two assertions below catch.
	if _, err := s.RecordIPChange(ctx, IPChange{
		DeviceID: d.ID, IPv4: "5.6.7.8", IPv6: "2001:db8::1",
		V4Asserted: true, V6Asserted: false,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Devices().GetByID(ctx, d.ID)
	if got.V4WarnLevel != 0 || got.V6WarnLevel != 3 {
		t.Errorf("levels = (%d,%d), want (0,3)", got.V4WarnLevel, got.V6WarnLevel)
	}
	if got.V6ConfirmedAt != 100 {
		t.Errorf("V6ConfirmedAt = %d, want 100", got.V6ConfirmedAt)
	}
	// RecordIPChange stamps store.NowUnix() internally, so the exact value
	// isn't predictable -- assert it moved off the seeded 100. Without this,
	// a wrong THEN bind on the v4 instant in updateDeviceIP that left it at
	// 100 would still pass every other assertion in this test.
	if got.V4ConfirmedAt <= 100 {
		t.Errorf("V4ConfirmedAt = %d, want > 100: an asserted family must advance", got.V4ConfirmedAt)
	}
}
