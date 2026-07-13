package service

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedDevice creates and returns a device for usr with an empty initial
// IP/metadata state (mirrors a freshly-enrolled device before its first
// checkin). Reused by later service test files in this package.
func seedDevice(t *testing.T, st *store.Store, userID, label string) store.Device {
	t.Helper()
	d, err := st.Devices().Create(t.Context(), store.Device{
		UserID:     userID,
		Label:      label,
		SecretHash: "sealed-secret",
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d
}

func TestCheckin_FirstReport_StoresAndAppendsHistory(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, discardAudit{})

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{
		IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Checkin: Stored = false, want true on first report")
	}
	if res.DeviceID != dev.ID || res.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("Checkin result = %+v, want DeviceID=%q CurrentIPv4=1.2.3.4", res, dev.ID)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].IPv4 != "1.2.3.4" {
		t.Fatalf("ip_history row IPv4 = %q, want 1.2.3.4", page.Rows[0].IPv4)
	}

	updated, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if updated.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("device CurrentIPv4 = %q, want 1.2.3.4", updated.CurrentIPv4)
	}
	if updated.LastSeenAt == 0 {
		t.Fatal("device LastSeenAt = 0, want set after IP change")
	}
}

func TestCheckin_IdenticalReport_DoesNotStoreOrWrite(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, discardAudit{})

	report := CheckinReport{IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0"}
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}
	beforeSecond, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, report)
	if err != nil {
		t.Fatalf("second Checkin: %v", err)
	}
	if res.Stored {
		t.Fatal("Checkin: Stored = true, want false for an unchanged report")
	}
	if res.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 1.2.3.4", res.CurrentIPv4)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1 (no new row on unchanged checkin)", len(page.Rows))
	}

	after, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if after.LastSeenAt != beforeSecond.LastSeenAt {
		t.Fatalf("device LastSeenAt changed on unchanged checkin: before=%d after=%d", beforeSecond.LastSeenAt, after.LastSeenAt)
	}
	if after.UpdatedAt != beforeSecond.UpdatedAt {
		t.Fatalf("device UpdatedAt changed on unchanged checkin: before=%d after=%d", beforeSecond.UpdatedAt, after.UpdatedAt)
	}
}

func TestCheckin_ChangedIP_AppendsNewHistoryRow(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, discardAudit{})

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4"}); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "5.6.7.8"})
	if err != nil {
		t.Fatalf("second Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Checkin: Stored = false, want true for a changed IP")
	}
	if res.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 5.6.7.8", res.CurrentIPv4)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ip_history rows = %d, want 2 (append on IP change)", len(page.Rows))
	}
}

func TestCheckinService_Self_ReturnsDevice(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, discardAudit{})

	got, err := svc.Self(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Self: %v", err)
	}
	if got.ID != dev.ID {
		t.Fatalf("Self: ID = %q, want %q", got.ID, dev.ID)
	}
}
