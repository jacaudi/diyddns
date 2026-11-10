package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AgentCA is the pair of agent CA certificates (DER, public material only;
// private keys never enter the database, #173). ActiveDER signs device
// certificates; BackupDER is the standby promoted on rotation.
type AgentCA struct {
	ActiveDER, BackupDER []byte
}

// AgentCARepo persists the singleton agent_ca row.
type AgentCARepo struct{ db *sql.DB }

// AgentCA returns an AgentCARepo bound to this Store's database.
func (s *Store) AgentCA() *AgentCARepo { return &AgentCARepo{db: s.db} }

// clearDeviceCerts is the statement Promote and Reset share: a new or removed
// CA invalidates every certificate it signed, pending ones included.
const clearDeviceCerts = `UPDATE devices SET cert_serial = NULL, cert_not_after = NULL, pending_cert_serial = NULL`

// Get returns the CA pair. Returns ErrNotFound if none is recorded.
func (r *AgentCARepo) Get(ctx context.Context) (AgentCA, error) {
	var ca AgentCA
	err := r.db.QueryRowContext(ctx,
		`SELECT active_der, backup_der FROM agent_ca WHERE id = 1`,
	).Scan(&ca.ActiveDER, &ca.BackupDER)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentCA{}, fmt.Errorf("agent_ca.Get: %w", ErrNotFound)
		}
		return AgentCA{}, fmt.Errorf("agent_ca.Get: %w", err)
	}
	return ca, nil
}

// Insert records the first CA pair. Returns ErrConflict if one already exists.
func (r *AgentCARepo) Insert(ctx context.Context, ca AgentCA) error {
	now := NowUnix()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO agent_ca (id, active_der, backup_der, created_at, updated_at)
		 VALUES (1, ?, ?, ?, ?)`,
		ca.ActiveDER, ca.BackupDER, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("agent_ca.Insert: %w", ErrConflict)
		}
		return fmt.Errorf("agent_ca.Insert: %w", err)
	}
	return nil
}

// Promote replaces the CA pair and clears every device's recorded
// certificate in one transaction: the old certificates no longer chain to
// the active CA. Returns ErrNotFound if no pair is recorded.
func (r *AgentCARepo) Promote(ctx context.Context, ca AgentCA) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("agent_ca.Promote: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE agent_ca SET active_der = ?, backup_der = ?, updated_at = ? WHERE id = 1`,
		ca.ActiveDER, ca.BackupDER, NowUnix(),
	)
	if err != nil {
		return fmt.Errorf("agent_ca.Promote: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("agent_ca.Promote: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("agent_ca.Promote: %w", ErrNotFound)
	}
	if _, err := tx.ExecContext(ctx, clearDeviceCerts); err != nil {
		return fmt.Errorf("agent_ca.Promote: clear device certs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("agent_ca.Promote: commit: %w", err)
	}
	return nil
}

// Reset deletes the CA pair and clears every device's recorded certificate in
// one transaction. It is idempotent: with no pair recorded it still clears.
func (r *AgentCARepo) Reset(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("agent_ca.Reset: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_ca WHERE id = 1`); err != nil {
		return fmt.Errorf("agent_ca.Reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, clearDeviceCerts); err != nil {
		return fmt.Errorf("agent_ca.Reset: clear device certs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("agent_ca.Reset: commit: %w", err)
	}
	return nil
}
