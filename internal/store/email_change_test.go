package store

import (
	"database/sql"
	"errors"
	"slices"
	"testing"
)

// TestMigration009_PendingEmailColumns pins the three columns 00009 adds and
// that a freshly created row reads them back as zero values.
func TestMigration009_PendingEmailColumns(t *testing.T) {
	s, ctx := newTestStore(t)

	rows, err := s.DB().QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	for _, want := range []string{"pending_email", "pending_email_token_hash", "pending_email_expires_at"} {
		if !slices.Contains(names, want) {
			t.Errorf("users table missing column %q after migrations; have %v", want, names)
		}
	}

	u, err := s.Users().Create(ctx, User{Email: "fresh@example.com", Role: roleUser})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Users().GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("fresh row pending = (%q, %d), want (\"\", 0)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
}

func TestUsers_SetPendingEmail_RoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
	before, _ := s.Users().GetByID(ctx, u.ID)

	if err := s.Users().SetPendingEmail(ctx, u.ID, "new@example.com", "hash-1", 4000); err != nil {
		t.Fatalf("SetPendingEmail: %v", err)
	}
	got, err := s.Users().GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.PendingEmail != "new@example.com" || got.PendingEmailExpiresAt != 4000 {
		t.Errorf("pending = (%q, %d), want (new@example.com, 4000)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
	if got.Email != "old@example.com" {
		t.Errorf("Email = %q, want old@example.com — staging must not change the address", got.Email)
	}
	if got.UpdatedAt != before.UpdatedAt {
		t.Errorf("UpdatedAt changed from %d to %d — staging must not bump updated_at", before.UpdatedAt, got.UpdatedAt)
	}
	if err := s.Users().SetPendingEmail(ctx, "no-such-id", "x@example.com", "h", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPendingEmail unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestUsers_ClearPendingEmail(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})

	// Nothing pending: the row still matches, so this is nil, not ErrNotFound
	// (SQLite counts rows matched by an UPDATE, not rows whose values differed).
	if err := s.Users().ClearPendingEmail(ctx, u.ID); err != nil {
		t.Fatalf("ClearPendingEmail with nothing pending: %v, want nil", err)
	}
	if err := s.Users().SetPendingEmail(ctx, u.ID, "new@example.com", "hash-1", 4000); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().ClearPendingEmail(ctx, u.ID); err != nil {
		t.Fatalf("ClearPendingEmail: %v", err)
	}
	got, _ := s.Users().GetByID(ctx, u.ID)
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("after clear pending = (%q, %d), want zero", got.PendingEmail, got.PendingEmailExpiresAt)
	}
	if err := s.Users().ClearPendingEmail(ctx, "no-such-id"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestUsers_ConfirmPendingEmail_AppliesAndClears(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
	if err := s.Users().SetPendingEmail(ctx, u.ID, "new@example.com", "hash-1", 4000); err != nil {
		t.Fatal(err)
	}

	if err := s.Users().ConfirmPendingEmail(ctx, u.ID, "hash-1", 3000); err != nil {
		t.Fatalf("ConfirmPendingEmail: %v", err)
	}
	got, _ := s.Users().GetByID(ctx, u.ID)
	if got.Email != "new@example.com" {
		t.Errorf("Email = %q, want new@example.com", got.Email)
	}
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("pending not cleared: (%q, %d)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
	if got.UpdatedAt != 3000 {
		t.Errorf("UpdatedAt = %d, want 3000 (the now the statement was given)", got.UpdatedAt)
	}
	// Single use: the same token cannot confirm twice.
	if err := s.Users().ConfirmPendingEmail(ctx, u.ID, "hash-1", 3001); !errors.Is(err, ErrNotFound) {
		t.Errorf("second confirm: err = %v, want ErrNotFound", err)
	}
}

func TestUsers_ConfirmPendingEmail_Rejects(t *testing.T) {
	cases := []struct {
		name      string
		stage     bool  // whether a pending change exists at all
		expiresAt int64 // when it does
		token     string
		now       int64
	}{
		{name: "wrong token", stage: true, expiresAt: 4000, token: "wrong", now: 3000},
		{name: "expired", stage: true, expiresAt: 2000, token: "hash-1", now: 3000},
		{name: "expires exactly now", stage: true, expiresAt: 3000, token: "hash-1", now: 3000},
		{name: "nothing pending", stage: false, token: "hash-1", now: 3000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx := newTestStore(t)
			u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
			if tc.stage {
				if err := s.Users().SetPendingEmail(ctx, u.ID, "new@example.com", "hash-1", tc.expiresAt); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := s.Users().GetByID(ctx, u.ID)

			err := s.Users().ConfirmPendingEmail(ctx, u.ID, tc.token, tc.now)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
			after, _ := s.Users().GetByID(ctx, u.ID)
			if after != before {
				t.Errorf("row changed on a rejected confirm:\n before %+v\n after  %+v", before, after)
			}
		})
	}
}

func TestUsers_ConfirmPendingEmail_ConflictKeepsPending(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
	if _, err := s.Users().Create(ctx, User{Email: "taken@example.com", Role: roleUser}); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().SetPendingEmail(ctx, u.ID, "taken@example.com", "hash-1", 4000); err != nil {
		t.Fatal(err)
	}

	err := s.Users().ConfirmPendingEmail(ctx, u.ID, "hash-1", 3000)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	got, _ := s.Users().GetByID(ctx, u.ID)
	if got.Email != "old@example.com" || got.PendingEmail != "taken@example.com" {
		t.Errorf("after conflict: Email = %q, PendingEmail = %q; the statement must not have partially applied", got.Email, got.PendingEmail)
	}
}

func TestUsers_SetEmail(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
	if err := s.Users().SetPendingEmail(ctx, u.ID, "pending@example.com", "hash-1", 4000); err != nil {
		t.Fatal(err)
	}

	if err := s.Users().SetEmail(ctx, u.ID, "admin-set@example.com", 5000); err != nil {
		t.Fatalf("SetEmail: %v", err)
	}
	got, _ := s.Users().GetByID(ctx, u.ID)
	if got.Email != "admin-set@example.com" {
		t.Errorf("Email = %q, want admin-set@example.com", got.Email)
	}
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("SetEmail must clear a pending change; got (%q, %d)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
	if got.UpdatedAt != 5000 {
		t.Errorf("UpdatedAt = %d, want 5000", got.UpdatedAt)
	}

	if _, err := s.Users().Create(ctx, User{Email: "taken@example.com", Role: roleUser}); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().SetEmail(ctx, u.ID, "taken@example.com", 5001); !errors.Is(err, ErrConflict) {
		t.Errorf("SetEmail to a taken address: err = %v, want ErrConflict", err)
	}
	if err := s.Users().SetEmail(ctx, "no-such-id", "x@example.com", 5002); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEmail unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestUsers_ClearExpiredPendingEmails(t *testing.T) {
	s, ctx := newTestStore(t)
	expired, _ := s.Users().Create(ctx, User{Email: "a@example.com", Role: roleUser})
	live, _ := s.Users().Create(ctx, User{Email: "b@example.com", Role: roleUser})
	none, _ := s.Users().Create(ctx, User{Email: "c@example.com", Role: roleUser})
	if err := s.Users().SetPendingEmail(ctx, expired.ID, "a2@example.com", "h-a", 1000); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().SetPendingEmail(ctx, live.ID, "b2@example.com", "h-b", 9000); err != nil {
		t.Fatal(err)
	}

	n, err := s.Users().ClearExpiredPendingEmails(ctx, 5000)
	if err != nil {
		t.Fatalf("ClearExpiredPendingEmails: %v", err)
	}
	if n != 1 {
		t.Errorf("cleared = %d, want 1", n)
	}
	gotExpired, _ := s.Users().GetByID(ctx, expired.ID)
	gotLive, _ := s.Users().GetByID(ctx, live.ID)
	gotNone, _ := s.Users().GetByID(ctx, none.ID)
	if gotExpired.PendingEmail != "" {
		t.Errorf("expired pending survived: %q", gotExpired.PendingEmail)
	}
	if gotLive.PendingEmail != "b2@example.com" {
		t.Errorf("live pending was cleared: %q", gotLive.PendingEmail)
	}
	if gotNone.PendingEmail != "" {
		t.Errorf("row with nothing pending changed: %q", gotNone.PendingEmail)
	}
}

// TestUsers_Update_LeavesPendingColumnsAlone pins that the pre-existing Update
// (which names its columns) does not clobber a staged change.
func TestUsers_Update_LeavesPendingColumnsAlone(t *testing.T) {
	s, ctx := newTestStore(t)
	u, _ := s.Users().Create(ctx, User{Email: "old@example.com", Role: roleUser})
	if err := s.Users().SetPendingEmail(ctx, u.ID, "new@example.com", "hash-1", 4000); err != nil {
		t.Fatal(err)
	}
	u.Role = roleAdmin
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.Users().GetByID(ctx, u.ID)
	if got.PendingEmail != "new@example.com" || got.PendingEmailExpiresAt != 4000 {
		t.Errorf("Update clobbered pending: (%q, %d)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
}

func TestAccountRecovery_DeleteUnusedByUser(t *testing.T) {
	s, ctx := newTestStore(t)
	a, _ := s.Users().Create(ctx, User{Email: "a@example.com", Role: roleUser})
	b, _ := s.Users().Create(ctx, User{Email: "b@example.com", Role: roleUser})
	future := NowUnix() + 3600
	seed := func(hash, userID string, used int64) {
		t.Helper()
		if err := s.AccountRecovery().Create(ctx, RecoveryToken{TokenHash: hash, UserID: userID, Reason: "recovery", ExpiresAt: future, UsedAt: used}); err != nil {
			t.Fatalf("seed %s: %v", hash, err)
		}
	}
	seed("a-unused-1", a.ID, 0)
	seed("a-unused-2", a.ID, 0)
	seed("a-used", a.ID, 100)
	seed("b-unused", b.ID, 0)

	n, err := s.AccountRecovery().DeleteUnusedByUser(ctx, a.ID)
	if err != nil {
		t.Fatalf("DeleteUnusedByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	for hash, wantGone := range map[string]bool{"a-unused-1": true, "a-unused-2": true, "a-used": false, "b-unused": false} {
		_, err := s.AccountRecovery().Get(ctx, hash)
		gone := errors.Is(err, ErrNotFound)
		if gone != wantGone {
			t.Errorf("%s: gone = %v, want %v (err %v)", hash, gone, wantGone, err)
		}
	}
	if n, err := s.AccountRecovery().DeleteUnusedByUser(ctx, "no-such-id"); err != nil || n != 0 {
		t.Errorf("unknown user: n = %d, err = %v; want 0, nil", n, err)
	}
}
