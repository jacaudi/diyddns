package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: sql.Open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: db.Conn: %w", err)
	}
	if err := applyPragmas(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}
	if err := conn.Close(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: conn close: %w", err)
	}

	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
