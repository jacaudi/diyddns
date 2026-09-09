package store

import (
	"testing"
	"uuid"
)

func TestNewIDIsValidUUIDv7(t *testing.T) {
	for range 32 {
		got := NewID()
		parsed, err := uuid.Parse(got)
		if err != nil {
			t.Fatalf("NewID()=%q is not a valid UUID: %v", got, err)
		}
		// RFC 9562 §4.2: the version is the high nibble of octet 6.
		if v := parsed[6] >> 4; v != 7 {
			t.Fatalf("NewID()=%q is UUIDv%d, want v7", got, v)
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
