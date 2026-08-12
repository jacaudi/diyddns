package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewIDIsValidUUIDv7(t *testing.T) {
	for range 32 {
		got := NewID()
		parsed, err := uuid.Parse(got)
		if err != nil {
			t.Fatalf("NewID()=%q is not a valid UUID: %v", got, err)
		}
		if parsed.Version() != 7 {
			t.Fatalf("NewID()=%q is UUIDv%d, want v7", got, parsed.Version())
		}
	}
}

func TestNewIDsAreDistinct(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := range n {
		id := NewID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}
