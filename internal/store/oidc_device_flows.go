package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// OIDCDeviceFlow is a pending RFC 8628 device-code enrollment: the mapping
// between the opaque flow_id handed to the agent and the IdP's device_code,
// which never leaves the server.
type OIDCDeviceFlow struct {
	FlowID       string
	DeviceCode   string
	Interval     int64
	ExpiresAt    int64
	LastPolledAt int64
	CreatedAt    int64
}

// OIDCDeviceFlowRepo provides persistence for pending device-code flows.
type OIDCDeviceFlowRepo struct{ db *sql.DB }

// OIDCDeviceFlows returns a repo bound to this Store's database.
func (s *Store) OIDCDeviceFlows() *OIDCDeviceFlowRepo { return &OIDCDeviceFlowRepo{db: s.db} }

const oidcDeviceFlowColumns = `flow_id, device_code, interval, expires_at, last_polled_at, created_at`

func scanOIDCDeviceFlow(row interface {
	Scan(dest ...any) error
}) (OIDCDeviceFlow, error) {
	var f OIDCDeviceFlow
	if err := row.Scan(&f.FlowID, &f.DeviceCode, &f.Interval, &f.ExpiresAt, &f.LastPolledAt, &f.CreatedAt); err != nil {
		return OIDCDeviceFlow{}, err
	}
	return f, nil
}

// Create inserts a pending device flow. Returns ErrConflict if flow_id exists.
func (r *OIDCDeviceFlowRepo) Create(ctx context.Context, f OIDCDeviceFlow) (OIDCDeviceFlow, error) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO oidc_device_flows (flow_id, device_code, interval, expires_at, last_polled_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		f.FlowID, f.DeviceCode, f.Interval, f.ExpiresAt, f.LastPolledAt, f.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return OIDCDeviceFlow{}, fmt.Errorf("oidc_device_flows.Create: %w", ErrConflict)
		}
		return OIDCDeviceFlow{}, fmt.Errorf("oidc_device_flows.Create: %w", err)
	}
	return f, nil
}

// Get fetches a flow by flow_id. Returns ErrNotFound if absent.
func (r *OIDCDeviceFlowRepo) Get(ctx context.Context, flowID string) (OIDCDeviceFlow, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+oidcDeviceFlowColumns+` FROM oidc_device_flows WHERE flow_id = ?`, flowID)
	f, err := scanOIDCDeviceFlow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OIDCDeviceFlow{}, fmt.Errorf("oidc_device_flows.Get: %w", ErrNotFound)
		}
		return OIDCDeviceFlow{}, fmt.Errorf("oidc_device_flows.Get: %w", err)
	}
	return f, nil
}

// TryPoll atomically stamps last_polled_at=now iff the flow exists, is not
// expired, and has been idle at least `interval` seconds. It returns:
//   - (row, true, nil)  when the poll is allowed (caller may hit the IdP)
//   - (row, false, nil) when the poll is too soon (slow_down / paced)
//   - ErrNotFound       when the flow is absent or expired
//
// The stamp is the gate, so two concurrent polls for the same flow cannot both
// be allowed.
func (r *OIDCDeviceFlowRepo) TryPoll(ctx context.Context, flowID string, now int64) (OIDCDeviceFlow, bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE oidc_device_flows
		    SET last_polled_at = ?
		  WHERE flow_id = ?
		    AND expires_at > ?
		    AND ? - last_polled_at >= interval`,
		now, flowID, now, now,
	)
	if err != nil {
		return OIDCDeviceFlow{}, false, fmt.Errorf("oidc_device_flows.TryPoll: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return OIDCDeviceFlow{}, false, fmt.Errorf("oidc_device_flows.TryPoll: RowsAffected: %w", err)
	}
	// Re-read to distinguish "paced" (row exists, unexpired) from "gone/expired".
	f, err := r.Get(ctx, flowID)
	if err != nil {
		return OIDCDeviceFlow{}, false, err // ErrNotFound flows up
	}
	if f.ExpiresAt <= now {
		return OIDCDeviceFlow{}, false, fmt.Errorf("oidc_device_flows.TryPoll: %w", ErrNotFound)
	}
	return f, n == 1, nil
}

// BumpInterval increases a flow's stored interval by delta seconds (RFC 8628
// §3.5 slow_down handling). A missing row is not an error.
func (r *OIDCDeviceFlowRepo) BumpInterval(ctx context.Context, flowID string, delta int64) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE oidc_device_flows SET interval = interval + ? WHERE flow_id = ?`, delta, flowID,
	); err != nil {
		return fmt.Errorf("oidc_device_flows.BumpInterval: %w", err)
	}
	return nil
}

// Delete removes a flow. A missing row is not an error.
func (r *OIDCDeviceFlowRepo) Delete(ctx context.Context, flowID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM oidc_device_flows WHERE flow_id = ?`, flowID); err != nil {
		return fmt.Errorf("oidc_device_flows.Delete: %w", err)
	}
	return nil
}

// PruneExpired deletes flows past their expiry. Returns rows deleted.
func (r *OIDCDeviceFlowRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM oidc_device_flows WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("oidc_device_flows.PruneExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("oidc_device_flows.PruneExpired: RowsAffected: %w", err)
	}
	return int(n), nil
}
