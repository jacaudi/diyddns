package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jacaudi/diyddns/migrations"
	"github.com/pressly/goose/v3"
)

// Migrate applies every embedded SQL migration to db, in version order. It
// is idempotent: re-running on an already-current schema is a no-op. Goose
// records its version in a goose_db_version table created on first run.
func Migrate(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("store: goose set dialect: %w", err)
	}
	// "." tells goose to read from the registered base FS (embed.FS).
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("store: goose up: %w", err)
	}
	return nil
}
