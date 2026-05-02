package store

import (
	"fmt"

	"github.com/google/uuid"
)

// NewID returns a fresh UUIDv7 as a lowercase hex-with-dashes string.
// UUIDv7 sorts lexicographically by creation time, which makes it a good
// fit for primary keys that are also natural ordering keys.
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// uuid.NewV7 only fails on extreme clock issues; if it does we want
		// to know immediately rather than persisting a zero UUID.
		panic(fmt.Sprintf("store.NewID: uuid.NewV7 failed: %v", err))
	}
	return id.String()
}
