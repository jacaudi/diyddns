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
