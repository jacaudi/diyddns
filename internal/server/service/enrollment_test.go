package service

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// discardAudit is a no-op AuditSink for tests that don't assert on audit
// entries. Reused by later service test files in this package.
type discardAudit struct{}

func (discardAudit) Log(context.Context, store.AuditEntry) {}

// testKey32 returns a fixed 32-byte AEAD key for tests. Reused by later
// service test files in this package.
func testKey32() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

// testArgon2Params returns cheap argon2id params so password tests run fast.
// Reused by later service test files in this package.
func testArgon2Params() auth.Argon2Params {
	return auth.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
}

// openTestStore returns a Store backed by a fresh in-memory SQLite database
// with migrations applied, closed automatically at test cleanup. Reused by
// later service test files in this package.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

// seedUser creates and returns a user with the given email and role and no
// password hash. Reused by later service test files in this package.
func seedUser(t *testing.T, st *store.Store, email, role string) store.User {
	t.Helper()
	u, err := st.Users().Create(t.Context(), store.User{Email: email, Role: role})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// seedUserWithPassword creates and returns a user with an argon2id password
// hash for the given plaintext password. Reused by later service test files
// in this package.
func seedUserWithPassword(t *testing.T, st *store.Store, email, role, password string) store.User {
	t.Helper()
	hash, err := auth.HashPassword(password, testArgon2Params())
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := st.Users().Create(t.Context(), store.User{Email: email, Role: role, PasswordHash: hash})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestCreateCode_InsertsCode(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	code, expiresAt, err := svc.CreateCode(t.Context(), usr.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	if code == "" {
		t.Fatal("CreateCode returned empty code")
	}

	got, err := st.EnrollmentCodes().Get(t.Context(), code)
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}
	if got.UserID != usr.ID || got.Label != "laptop" {
		t.Fatalf("stored code = %+v, want UserID=%q Label=laptop", got, usr.ID)
	}
	if got.ExpiresAt != expiresAt {
		t.Fatalf("stored ExpiresAt = %d, want %d (returned value)", got.ExpiresAt, expiresAt)
	}
}

func TestConsumeCode_HappyPath(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	code, _, err := svc.CreateCode(t.Context(), usr.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	res, err := svc.ConsumeCode(t.Context(), code, ClientMeta{Hostname: "lp", OS: "linux"})
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if res.DeviceID == "" {
		t.Fatal("ConsumeCode returned empty DeviceID")
	}
	if len(res.Secret) == 0 {
		t.Fatal("ConsumeCode returned empty Secret")
	}

	dev, err := st.Devices().GetByID(t.Context(), res.DeviceID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if dev.UserID != usr.ID || dev.Label != "laptop" {
		t.Fatalf("stored device = %+v, want UserID=%q Label=laptop", dev, usr.ID)
	}
	if dev.Hostname != "lp" || dev.OS != "linux" {
		t.Fatalf("stored device meta = %+v, want Hostname=lp OS=linux", dev)
	}

	got, err := auth.OpenSecret(testKey32(), dev.SecretHash)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(got, res.Secret) {
		t.Fatal("stored sealed secret must decrypt to the returned secret")
	}

	consumed, err := st.EnrollmentCodes().Get(t.Context(), code)
	if err != nil {
		t.Fatalf("EnrollmentCodes.Get: %v", err)
	}
	if consumed.UsedAt == 0 || consumed.DeviceID != res.DeviceID {
		t.Fatalf("code not marked consumed: %+v", consumed)
	}
}

func TestConsumeCode_InvalidLeavesNoDevice(t *testing.T) {
	tests := []struct {
		name string
		// seed prepares the invalid-code scenario and returns the code to
		// consume plus the device count that must exist BEFORE the failing
		// ConsumeCode call (0, except "already used" which legitimately
		// created one device on its priming consume).
		seed func(t *testing.T, st *store.Store, usr store.User) (code string, wantDevicesBefore int)
	}{
		{
			name: "expired",
			seed: func(t *testing.T, st *store.Store, usr store.User) (string, int) {
				t.Helper()
				if _, err := st.EnrollmentCodes().Create(t.Context(), store.EnrollmentCode{
					Code: "expired-code", UserID: usr.ID, Label: "x", ExpiresAt: 1,
				}); err != nil {
					t.Fatalf("seed expired code: %v", err)
				}
				return "expired-code", 0
			},
		},
		{
			name: "already used",
			seed: func(t *testing.T, st *store.Store, usr store.User) (string, int) {
				t.Helper()
				svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})
				code, _, err := svc.CreateCode(t.Context(), usr.ID, "x")
				if err != nil {
					t.Fatalf("CreateCode: %v", err)
				}
				if _, err := svc.ConsumeCode(t.Context(), code, ClientMeta{}); err != nil {
					t.Fatalf("prime consume: %v", err)
				}
				return code, 1 // the priming consume legitimately created one device
			},
		},
		{
			name: "nonexistent",
			seed: func(t *testing.T, st *store.Store, usr store.User) (string, int) {
				t.Helper()
				return "never-issued", 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openTestStore(t)
			usr := seedUser(t, st, "a@b.co", "user")
			code, wantDevicesBefore := tt.seed(t, st, usr)

			svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})
			if _, err := svc.ConsumeCode(t.Context(), code, ClientMeta{}); err == nil {
				t.Fatal("expected error consuming invalid code")
			}

			ds, err := st.Devices().ListByUser(t.Context(), usr.ID)
			if err != nil {
				t.Fatalf("Devices.ListByUser: %v", err)
			}
			if len(ds) != wantDevicesBefore {
				t.Fatalf("compensating-delete failed: %d devices for user, want %d", len(ds), wantDevicesBefore)
			}
		})
	}
}

func TestEnrollCredentials_GoodPassword(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	res, err := svc.EnrollCredentials(t.Context(), "a@b.co", "correct horse battery staple", ClientMeta{Hostname: "lp", OS: "linux"})
	if err != nil {
		t.Fatalf("EnrollCredentials: %v", err)
	}
	if res.DeviceID == "" || len(res.Secret) == 0 {
		t.Fatalf("EnrollCredentials returned incomplete result: %+v", res)
	}

	dev, err := st.Devices().GetByID(t.Context(), res.DeviceID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if dev.UserID != usr.ID || dev.Label != "lp" {
		t.Fatalf("stored device = %+v, want UserID=%q Label=lp", dev, usr.ID)
	}

	got, err := auth.OpenSecret(testKey32(), dev.SecretHash)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(got, res.Secret) {
		t.Fatal("stored sealed secret must decrypt to the returned secret")
	}
}

func TestEnrollCredentials_DefaultLabelWhenNoHostname(t *testing.T) {
	st := openTestStore(t)
	seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	res, err := svc.EnrollCredentials(t.Context(), "a@b.co", "correct horse battery staple", ClientMeta{})
	if err != nil {
		t.Fatalf("EnrollCredentials: %v", err)
	}
	dev, err := st.Devices().GetByID(t.Context(), res.DeviceID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if dev.Label != "device" {
		t.Fatalf("Label = %q, want default %q", dev.Label, "device")
	}
}

func TestEnrollCredentials_WrongPasswordErrors(t *testing.T) {
	st := openTestStore(t)
	seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	if _, err := svc.EnrollCredentials(t.Context(), "a@b.co", "wrong-password", ClientMeta{}); err == nil {
		t.Fatal("expected error for wrong password")
	}

	ds, err := st.Devices().ListByUser(t.Context(), "nonexistent-user-id")
	if err != nil {
		t.Fatalf("Devices.ListByUser: %v", err)
	}
	if len(ds) != 0 {
		t.Fatalf("expected no devices, got %d", len(ds))
	}
}

func TestEnrollCredentials_UnknownEmailErrors(t *testing.T) {
	st := openTestStore(t)
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	if _, err := svc.EnrollCredentials(t.Context(), "nobody@b.co", "whatever", ClientMeta{}); err == nil {
		t.Fatal("expected error for unknown email")
	}
}

func TestEnrollCredentials_DisabledUserErrors(t *testing.T) {
	st := openTestStore(t)
	usr := seedUserWithPassword(t, st, "a@b.co", "user", "correct horse battery staple")
	if err := st.Users().SetDisabled(t.Context(), usr.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})

	if _, err := svc.EnrollCredentials(t.Context(), "a@b.co", "correct horse battery staple", ClientMeta{}); err == nil {
		t.Fatal("expected error for disabled user")
	}
}
