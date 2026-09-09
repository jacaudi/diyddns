package store

import "uuid"

// NewID returns a fresh UUIDv7 as a lowercase hex-with-dashes string.
// UUIDv7 sorts lexicographically by creation time, which makes it a good
// fit for primary keys that are also natural ordering keys.
func NewID() string {
	return uuid.NewV7().String()
}
