package store

import (
	"context"
	"database/sql"
	"fmt"
)

// applyPragmas runs the per-connection setup that the SQLite driver
// requires for the project's runtime guarantees:
//   - WAL mode (concurrent reads with single writer; safe for the
//     typical small-scale deployment described in the design spec).
//   - foreign_keys=ON (referential integrity is not on by default in SQLite).
//   - synchronous=NORMAL (a fsync compromise that is safe under WAL).
//   - busy_timeout=5000 (block up to 5 s when the writer is locked
//     instead of returning SQLITE_BUSY immediately).
func applyPragmas(ctx context.Context, conn *sql.Conn) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA busy_timeout = 5000",
	}
	for _, p := range pragmas {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("store: %s: %w", p, err)
		}
	}
	return nil
}
