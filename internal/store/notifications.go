package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// NotificationEndpoint is an admin-configured HTTPS (or loopback HTTP)
// webhook destination for device events. Endpoints are server-global (#106):
// every enabled endpoint receives every user's events.
type NotificationEndpoint struct {
	ID           string
	Label        string
	URL          string
	SecretSealed string
	Enabled      bool
	CreatedAt    int64
	UpdatedAt    int64
}

// Delivery status values — the fixed vocabulary of NotificationDelivery.Status.
// Named the same way worker.go's six fixed failure classes are, so the
// vocabulary has one authoritative source instead of a bare-literal contract
// repeated at every site that sets or compares it (internal/server/notify's
// enqueue.go and worker.go, this file's own InsertUserTest/InsertRedelivery
// SQL, and internal/server/webui/endpoints.go's Redeliverable check).
const (
	// DeliveryPending marks a row not yet attempted, or awaiting its next
	// retry after a non-terminal failure.
	DeliveryPending = "pending"
	// DeliveryDelivered marks a row whose attempt received a 2xx response.
	DeliveryDelivered = "delivered"
	// DeliveryFailed marks a row that will not be retried again: attempts
	// exhausted, or a 410 Gone response (terminal regardless of attempts
	// remaining).
	DeliveryFailed = "failed"
)

// deliveryTerminalStatuses is the SQL fragment naming the statuses
// InsertRedelivery accepts as a redelivery source, built from the same
// constants webui's Redeliverable check compares against — so the two
// cannot silently diverge the way a hand-typed IN (...) literal could.
var deliveryTerminalStatuses = fmt.Sprintf("'%s', '%s'", DeliveryFailed, DeliveryDelivered)

// pruneDeliveriesQuery is NotificationDeliveryRepo.Prune's query, built from
// deliveryTerminalStatuses rather than a hand-typed IN (...) literal — the same
// reason insertRedeliveryQuery is. Assembled here at package level rather than
// inline at the ExecContext call so the statement is a constant expression: the
// interpolated fragment is built from constants only and never from input, and
// hoisting it says so structurally instead of asking a reader (or gosec) to
// take it on trust.
var pruneDeliveriesQuery = fmt.Sprintf(`DELETE FROM notification_deliveries
		 WHERE id IN (SELECT id FROM notification_deliveries
		               WHERE created_at < ? AND status IN (%s)
		               LIMIT ?)`, deliveryTerminalStatuses)

// insertUserTestQuery is InsertUserTest's query, built from DeliveryPending
// rather than a bare 'pending' literal. The EXISTS clause carries the
// enabled predicate: a disabled endpoint gets no outbound traffic, on demand
// or otherwise.
var insertUserTestQuery = fmt.Sprintf(`INSERT INTO notification_deliveries
		       (endpoint_id, event_type, event_id, payload, attempts,
		        next_attempt_at, status, created_at, updated_at)
		 SELECT ?, 'endpoint.test', 0, ?, 0,
		        ?, '%s', ?, ?
		  WHERE EXISTS (SELECT 1 FROM notification_endpoints
		                 WHERE id = ? AND enabled = 1)`, DeliveryPending)

// insertRedeliveryQuery is InsertRedelivery's query, built from
// DeliveryPending and deliveryTerminalStatuses rather than bare literals.
var insertRedeliveryQuery = fmt.Sprintf(`INSERT INTO notification_deliveries
		       (endpoint_id, event_type, event_id, payload, attempts,
		        next_attempt_at, status, created_at, updated_at)
		 SELECT src.endpoint_id, src.event_type, src.event_id, src.payload, 0,
		        ?, '%s', ?, ?
		   FROM notification_deliveries src
		   JOIN notification_endpoints e ON e.id = src.endpoint_id
		  WHERE src.id = ?
		    AND src.status IN (%s)
		    AND e.enabled = 1`, DeliveryPending, deliveryTerminalStatuses)

// NotificationDelivery is one outbox row: an event rendered for one endpoint,
// tracked through delivery attempts.
type NotificationDelivery struct {
	ID            int64
	EndpointID    string
	EventType     string
	EventID       int64
	Payload       []byte
	Attempts      int
	NextAttemptAt int64 // 0 when NULL/terminal
	Status        string
	LastFailure   string
	CreatedAt     int64
	UpdatedAt     int64
}

// NotificationEndpointRepo provides persistence operations for
// NotificationEndpoint records.
type NotificationEndpointRepo struct{ db *sql.DB }

// NotificationEndpoints returns a NotificationEndpointRepo bound to this
// Store's database.
func (s *Store) NotificationEndpoints() *NotificationEndpointRepo {
	return &NotificationEndpointRepo{db: s.db}
}

const notificationEndpointColumns = `id, label, url, secret_sealed, enabled, created_at, updated_at`

func scanNotificationEndpoint(row interface {
	Scan(dest ...any) error
}) (NotificationEndpoint, error) {
	var e NotificationEndpoint
	var enabled int64
	err := row.Scan(
		&e.ID,
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

// Create inserts e. e.ID, e.CreatedAt and e.UpdatedAt must already be set by
// the caller; enabled is always 1 for a newly created endpoint. Returns
// ErrConflict when the url already exists (UNIQUE).
func (r *NotificationEndpointRepo) Create(ctx context.Context, e NotificationEndpoint) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO notification_endpoints (id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 1, ?, ?)`,
		e.ID, e.Label, e.URL, e.SecretSealed, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("notification_endpoints.Create: %w", ErrConflict)
		}
		return fmt.Errorf("notification_endpoints.Create: %w", err)
	}
	return nil
}

// Get fetches the endpoint identified by id. Returns ErrNotFound if it does
// not exist.
func (r *NotificationEndpointRepo) Get(ctx context.Context, id string) (NotificationEndpoint, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints WHERE id = ?`, id)
	e, err := scanNotificationEndpoint(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationEndpoint{}, fmt.Errorf("notification_endpoints.Get: %w", ErrNotFound)
		}
		return NotificationEndpoint{}, fmt.Errorf("notification_endpoints.Get: %w", err)
	}
	return e, nil
}

// List returns every endpoint regardless of enabled state, oldest first. An
// empty table yields an empty (nil) slice, not an error.
//
// List and ListEnabled below are two literal queries, as HEAD keeps them,
// sharing only the column-list constant. A helper parameterised by a raw SQL
// fragment (`where string`) would be shared SHAPE, not shared knowledge — the
// two statements have no reason to change together — and gosec rejects it as
// G202 (SQL string concatenation) at every build.
func (r *NotificationEndpointRepo) List(ctx context.Context) ([]NotificationEndpoint, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints
		 ORDER BY created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("notification_endpoints.List: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []NotificationEndpoint
	for rows.Next() {
		e, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("notification_endpoints.List: scan: %w", err)
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_endpoints.List: rows: %w", err)
	}
	return result, nil
}

// ListEnabled returns every enabled endpoint, oldest first — the fan-out set
// for a new event.
func (r *NotificationEndpointRepo) ListEnabled(ctx context.Context) ([]NotificationEndpoint, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints
		 WHERE enabled = 1
		 ORDER BY created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListEnabled: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []NotificationEndpoint
	for rows.Next() {
		e, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("notification_endpoints.ListEnabled: scan: %w", err)
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListEnabled: rows: %w", err)
	}
	return result, nil
}

// SetEnabled toggles enabled for the endpoint identified by id. Returns
// ErrNotFound if no row matched.
func (r *NotificationEndpointRepo) SetEnabled(ctx context.Context, id string, enabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE notification_endpoints SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("notification_endpoints.SetEnabled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("notification_endpoints.SetEnabled: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("notification_endpoints.SetEnabled: %w", ErrNotFound)
	}
	return nil
}

// Delete removes the endpoint identified by id; its deliveries cascade per
// the schema FK. Returns ErrNotFound if no row matched.
func (r *NotificationEndpointRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM notification_endpoints WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("notification_endpoints.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("notification_endpoints.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("notification_endpoints.Delete: %w", ErrNotFound)
	}
	return nil
}

// NotificationDeliveryRepo provides persistence operations for
// NotificationDelivery records.
type NotificationDeliveryRepo struct{ db *sql.DB }

// NotificationDeliveries returns a NotificationDeliveryRepo bound to this
// Store's database.
func (s *Store) NotificationDeliveries() *NotificationDeliveryRepo {
	return &NotificationDeliveryRepo{db: s.db}
}

// Enqueue inserts a new outbox row.
func (r *NotificationDeliveryRepo) Enqueue(ctx context.Context, d NotificationDelivery) error {
	now := NowUnix()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, last_failure, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.EndpointID,
		d.EventType,
		d.EventID,
		d.Payload,
		d.Attempts,
		nullIfZero(d.NextAttemptAt),
		d.Status,
		nullIfEmpty(d.LastFailure),
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
		        d.next_attempt_at, d.status, d.last_failure,
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
		var nextAttemptAt sql.NullInt64
		var lastFailure sql.NullString
		if err := rows.Scan(
			&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload, &d.Attempts,
			&nextAttemptAt, &d.Status, &lastFailure,
			&d.CreatedAt, &d.UpdatedAt, &d.EndpointURL, &d.SecretSealed,
		); err != nil {
			return nil, fmt.Errorf("notification_deliveries.DueForAttempt: scan: %w", err)
		}
		d.NextAttemptAt = nextAttemptAt.Int64
		d.LastFailure = lastFailure.String
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

// InsertUserTest inserts one endpoint.test delivery row for endpointID. The
// enabled predicate is carried by the single statement (a preceding SELECT
// would let a concurrent disable slip through: internal/store has no
// transactions and SetMaxOpenConns(1) serialises statements, not sequences).
//
// Returns (false, nil) — refused — when RowsAffected()==0: the endpoint does
// not exist or is disabled. Callers report one generic message for both.
func (r *NotificationDeliveryRepo) InsertUserTest(ctx context.Context, endpointID string, payload []byte, now int64) (bool, error) {
	res, err := r.db.ExecContext(ctx, insertUserTestQuery,
		endpointID, // 1: endpoint_id
		payload,    // 2: payload
		now,        // 3: next_attempt_at
		now,        // 4: created_at
		now,        // 5: updated_at
		endpointID, // 6: EXISTS id
	)
	if err != nil {
		return false, fmt.Errorf("notification_deliveries.InsertUserTest: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("notification_deliveries.InsertUserTest: RowsAffected: %w", err)
	}
	return n != 0, nil
}

// InsertRedelivery inserts a COPY of the terminal delivery row identified by
// deliveryID — it does not re-arm the existing row in place, so the source
// row's history (status/attempts/last_failure) is preserved. The single
// statement carries the terminal-status and enabled predicates. Returns
// (false, nil) — refused — when RowsAffected()==0: deliveryID does not
// exist, its endpoint is disabled, or the source row is not terminal.
func (r *NotificationDeliveryRepo) InsertRedelivery(ctx context.Context, deliveryID int64, now int64) (bool, error) {
	res, err := r.db.ExecContext(ctx, insertRedeliveryQuery,
		now,        // 1: next_attempt_at
		now,        // 2: created_at
		now,        // 3: updated_at
		deliveryID, // 4: src.id
	)
	if err != nil {
		return false, fmt.Errorf("notification_deliveries.InsertRedelivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("notification_deliveries.InsertRedelivery: RowsAffected: %w", err)
	}
	return n != 0, nil
}

// listByEndpointQuery is ListByEndpoint's query, named so
// TestListByEndpoint_UsesIndexNoTempBTree can EXPLAIN QUERY PLAN the exact
// SQL this method runs, rather than a copy that could silently drift from it.
//
// Ordering by id DESC alone (rather than created_at DESC, id DESC) is
// deliberate: id is INTEGER PRIMARY KEY AUTOINCREMENT and created_at is set
// once at insert, so the two orderings are equivalent, and id DESC lets
// SQLite walk the (endpoint_id, id) index directly instead of materialising
// and sorting every row for the endpoint before LIMIT — confirmed via
// EXPLAIN QUERY PLAN (see migrations/00005_notification_deliveries_id_index.sql).
const listByEndpointQuery = `SELECT id, endpoint_id, event_type, event_id, payload, attempts,
		        next_attempt_at, status, last_failure,
		        created_at, updated_at
		   FROM notification_deliveries
		  WHERE endpoint_id = ?
		  ORDER BY id DESC
		  LIMIT ?`

// ListByEndpoint returns up to limit deliveries for endpointID, most recent
// first, for the endpoint detail page's delivery history.
func (r *NotificationDeliveryRepo) ListByEndpoint(ctx context.Context, endpointID string, limit int) ([]NotificationDelivery, error) {
	rows, err := r.db.QueryContext(ctx, listByEndpointQuery, endpointID, limit)
	if err != nil {
		return nil, fmt.Errorf("notification_deliveries.ListByEndpoint: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []NotificationDelivery
	for rows.Next() {
		var d NotificationDelivery
		var nextAttemptAt sql.NullInt64
		var lastFailure sql.NullString
		if err := rows.Scan(
			&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload, &d.Attempts,
			&nextAttemptAt, &d.Status, &lastFailure,
			&d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("notification_deliveries.ListByEndpoint: scan: %w", err)
		}
		d.NextAttemptAt = nextAttemptAt.Int64
		d.LastFailure = lastFailure.String
		result = append(result, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_deliveries.ListByEndpoint: rows: %w", err)
	}
	return result, nil
}

// Prune deletes at most batch TERMINAL delivery rows created before olderThan,
// returning the number removed. Callers drain in a loop until it returns 0.
//
// INVARIANT: a pending row is never eligible, however old it is. A pending row
// is work the sweeper still owes; deleting one silently drops a delivery with
// nothing left to retry it and no record that it vanished. Age alone must
// never make owed work disappear — hence the status filter rather than a bare
// created_at cutoff.
//
// Batched for the same reason audit_log.Prune is: store.Open sets
// SetMaxOpenConns(1), so one long DELETE blocks every database access in the
// process, not just writes.
func (r *NotificationDeliveryRepo) Prune(ctx context.Context, olderThan int64, batch int) (int, error) {
	res, err := r.db.ExecContext(ctx, pruneDeliveriesQuery, olderThan, batch)
	if err != nil {
		return 0, fmt.Errorf("notification_deliveries.Prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("notification_deliveries.Prune: RowsAffected: %w", err)
	}
	return int(n), nil
}
