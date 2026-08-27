package store

import (
	"context"
	"database/sql"
	"fmt"
)

// NotificationEndpoint is a user-configured HTTPS (or loopback HTTP) webhook
// destination for IP-change events.
type NotificationEndpoint struct {
	ID           string
	UserID       string
	Label        string
	URL          string
	SecretSealed string
	Enabled      bool
	CreatedAt    int64
	UpdatedAt    int64
}

// NotificationDelivery is one outbox row: an event rendered for one endpoint,
// tracked through delivery attempts.
type NotificationDelivery struct {
	ID              int64
	EndpointID      string
	EventType       string
	EventID         int64
	Payload         []byte
	Attempts        int
	NextAttemptAt   int64 // 0 when NULL/terminal
	Status          string
	LastFailure     string
	UserInitiatedAt int64 // 0 when NULL
	CreatedAt       int64
	UpdatedAt       int64
}

// NotificationEndpointRepo provides persistence operations for
// NotificationEndpoint records.
type NotificationEndpointRepo struct{ db *sql.DB }

// NotificationEndpoints returns a NotificationEndpointRepo bound to this
// Store's database.
func (s *Store) NotificationEndpoints() *NotificationEndpointRepo {
	return &NotificationEndpointRepo{db: s.db}
}

const notificationEndpointColumns = `id, user_id, label, url, secret_sealed, enabled, created_at, updated_at`

func scanNotificationEndpoint(row interface {
	Scan(dest ...any) error
}) (NotificationEndpoint, error) {
	var e NotificationEndpoint
	var enabled int64
	err := row.Scan(
		&e.ID,
		&e.UserID,
		&e.Label,
		&e.URL,
		&e.SecretSealed,
		&enabled,
		&e.CreatedAt,
		&e.UpdatedAt,
	)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	e.Enabled = enabled != 0
	return e, nil
}

// ListEnabledByUser returns the enabled notification endpoints owned by
// userID. A user with no enabled endpoints gets an empty (nil) slice, not an
// error.
func (r *NotificationEndpointRepo) ListEnabledByUser(ctx context.Context, userID string) ([]NotificationEndpoint, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints
		 WHERE user_id = ? AND enabled = 1
		 ORDER BY created_at, id`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListEnabledByUser: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []NotificationEndpoint
	for rows.Next() {
		e, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("notification_endpoints.ListEnabledByUser: scan: %w", err)
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListEnabledByUser: rows: %w", err)
	}
	return result, nil
}

// NotificationDeliveryRepo provides persistence operations for
// NotificationDelivery records.
type NotificationDeliveryRepo struct{ db *sql.DB }

// NotificationDeliveries returns a NotificationDeliveryRepo bound to this
// Store's database.
func (s *Store) NotificationDeliveries() *NotificationDeliveryRepo {
	return &NotificationDeliveryRepo{db: s.db}
}

// Enqueue inserts a new outbox row. d.UserInitiatedAt must be left zero for
// server-initiated deliveries (a real IP change) — stamping it here would
// silently spend the user's manual-retry budget on ordinary traffic.
func (r *NotificationDeliveryRepo) Enqueue(ctx context.Context, d NotificationDelivery) error {
	now := NowUnix()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, last_failure, user_initiated_at,
		    created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.EndpointID,
		d.EventType,
		d.EventID,
		d.Payload,
		d.Attempts,
		nullIfZero(d.NextAttemptAt),
		d.Status,
		nullIfEmpty(d.LastFailure),
		nullIfZero(d.UserInitiatedAt),
		now,
		now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("notification_deliveries.Enqueue: %w", ErrConflict)
		}
		return fmt.Errorf("notification_deliveries.Enqueue: %w", err)
	}
	return nil
}

// DueDelivery is one sweep-selected delivery joined with the endpoint fields
// the worker needs to attempt it, so a second query per row is never needed.
type DueDelivery struct {
	NotificationDelivery
	EndpointURL  string
	SecretSealed string
}

// DueForAttempt selects up to limit deliveries whose next_attempt_at has
// passed, ordered oldest-due-first. The join against notification_endpoints
// and its `e.enabled = 1` filter are load-bearing, not an optimization:
// disabling an endpoint must stop deliveries already in flight, not just new
// ones, so a row whose endpoint was disabled after being scheduled is
// excluded here rather than only at enqueue time.
func (r *NotificationDeliveryRepo) DueForAttempt(ctx context.Context, before int64, limit int) ([]DueDelivery, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT d.id, d.endpoint_id, d.event_type, d.event_id, d.payload, d.attempts,
		        d.next_attempt_at, d.status, d.last_failure, d.user_initiated_at,
		        d.created_at, d.updated_at, e.url, e.secret_sealed
		   FROM notification_deliveries d
		   JOIN notification_endpoints e ON e.id = d.endpoint_id
		  WHERE d.next_attempt_at IS NOT NULL AND d.next_attempt_at <= ?
		    AND e.enabled = 1
		  ORDER BY d.next_attempt_at
		  LIMIT ?`,
		before, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("notification_deliveries.DueForAttempt: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []DueDelivery
	for rows.Next() {
		var d DueDelivery
		var nextAttemptAt, userInitiatedAt sql.NullInt64
		var lastFailure sql.NullString
		if err := rows.Scan(
			&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload, &d.Attempts,
			&nextAttemptAt, &d.Status, &lastFailure, &userInitiatedAt,
			&d.CreatedAt, &d.UpdatedAt, &d.EndpointURL, &d.SecretSealed,
		); err != nil {
			return nil, fmt.Errorf("notification_deliveries.DueForAttempt: scan: %w", err)
		}
		d.NextAttemptAt = nextAttemptAt.Int64
		d.LastFailure = lastFailure.String
		d.UserInitiatedAt = userInitiatedAt.Int64
		result = append(result, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_deliveries.DueForAttempt: rows: %w", err)
	}
	return result, nil
}

// UpdateAfterAttempt writes back the outcome of one delivery attempt: the new
// attempts count, resulting status, next retry time (0 means NULL, i.e. no
// further attempt is scheduled), and last_failure class (empty means NULL,
// i.e. delivered). This is the only write for an attempt, issued once the
// HTTP call has already completed — see notify.Worker's sweep for why there
// is no separate claim step.
func (r *NotificationDeliveryRepo) UpdateAfterAttempt(ctx context.Context, id int64, attempts int, status string, nextAttemptAt int64, lastFailure string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_deliveries
		    SET attempts = ?, status = ?, next_attempt_at = ?, last_failure = ?, updated_at = ?
		  WHERE id = ?`,
		attempts, status, nullIfZero(nextAttemptAt), nullIfEmpty(lastFailure), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("notification_deliveries.UpdateAfterAttempt: %w", err)
	}
	return nil
}
