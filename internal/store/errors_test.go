package store

import (
	"errors"
	"testing"

	sqlite "modernc.org/sqlite"
)

// TestIsUniqueViolationDetectsDuplicateKey drives isUniqueViolation from a
// real duplicate-key error produced by modernc.org/sqlite against the users
// table's UNIQUE(email) constraint. It also logs the raw extended result
// code so the actual driver behavior (2067 vs 19) is recorded, rather than
// assumed.
func TestIsUniqueViolationDetectsDuplicateKey(t *testing.T) {
	s, ctx := newTestStore(t)

	const insert = `INSERT INTO users (id, email, role, disabled, created_at, updated_at) VALUES (?, ?, ?, 0, 1, 1)`
	if _, err := s.DB().ExecContext(ctx, insert, "id-1", "dup@example.com", "user"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	_, err := s.DB().ExecContext(ctx, insert, "id-2", "dup@example.com", "user")
	if err == nil {
		t.Fatal("duplicate email insert: got nil error, want a UNIQUE constraint violation")
	}

	var sErr *sqlite.Error
	if errors.As(err, &sErr) {
		t.Logf("observed sqlite extended result code: %d", sErr.Code())
	} else {
		t.Logf("error did not unwrap to *sqlite.Error: %T: %v", err, err)
	}

	if !isUniqueViolation(err) {
		t.Fatalf("isUniqueViolation(%v) = false, want true", err)
	}
}

// TestIsUniqueViolationDetectsDuplicatePrimaryKey drives isUniqueViolation
// from a real duplicate-key error against a TEXT PRIMARY KEY column
// (enrollment_codes.code), as opposed to a separate UNIQUE index (users.email
// in the sibling test above). SQLite reports these via a different extended
// result code (SQLITE_CONSTRAINT_PRIMARYKEY, 1555, vs
// SQLITE_CONSTRAINT_UNIQUE, 2067) even though both mean "this key already
// exists" from the repository's point of view.
func TestIsUniqueViolationDetectsDuplicatePrimaryKey(t *testing.T) {
	s, ctx := newTestStore(t)

	user, err := s.Users().Create(ctx, User{Email: "pk-conflict@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	const insert = `INSERT INTO enrollment_codes (code, user_id, label, expires_at) VALUES (?, ?, ?, ?)`
	if _, err := s.DB().ExecContext(ctx, insert, "dup-pk-code", user.ID, "a", NowUnix()+3600); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	_, err = s.DB().ExecContext(ctx, insert, "dup-pk-code", user.ID, "b", NowUnix()+3600)
	if err == nil {
		t.Fatal("duplicate primary key insert: got nil error, want a PRIMARY KEY constraint violation")
	}

	var sErr *sqlite.Error
	if errors.As(err, &sErr) {
		t.Logf("observed sqlite extended result code: %d", sErr.Code())
	} else {
		t.Logf("error did not unwrap to *sqlite.Error: %T: %v", err, err)
	}

	if !isUniqueViolation(err) {
		t.Fatalf("isUniqueViolation(%v) = false, want true", err)
	}
}

// TestIsUniqueViolationIgnoresOtherErrors proves the helper does not
// misclassify an unrelated error (e.g. a CHECK constraint violation on the
// role column) as a UNIQUE violation.
func TestIsUniqueViolationIgnoresOtherErrors(t *testing.T) {
	s, ctx := newTestStore(t)

	const insert = `INSERT INTO users (id, email, role, disabled, created_at, updated_at) VALUES (?, ?, ?, 0, 1, 1)`
	_, err := s.DB().ExecContext(ctx, insert, "id-1", "check@example.com", "not-a-real-role")
	if err == nil {
		t.Fatal("invalid role insert: got nil error, want a CHECK constraint violation")
	}

	if isUniqueViolation(err) {
		t.Fatalf("isUniqueViolation(%v) = true, want false (CHECK violation, not UNIQUE)", err)
	}
}
