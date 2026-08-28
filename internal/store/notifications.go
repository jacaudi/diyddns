package store

import (
	"context"
	"database/sql"
	"errors"
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
// rather than a bare 'pending' literal.
var insertUserTestQuery = fmt.Sprintf(`INSERT INTO notification_deliveries
		       (endpoint_id, event_type, event_id, payload, attempts,
		        next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 SELECT ?, 'endpoint.test', 0, ?, 0,
		        ?, '%s', ?, ?, ?
		  WHERE EXISTS (SELECT 1 FROM notification_endpoints
		                 WHERE id = ? AND user_id = ? AND enabled = 1)`, DeliveryPending)

// insertRedeliveryQuery is InsertRedelivery's query, built from
// DeliveryPending and deliveryTerminalStatuses rather than bare literals.
var insertRedeliveryQuery = fmt.Sprintf(`INSERT INTO notification_deliveries
		       (endpoint_id, event_type, event_id, payload, attempts,
		        next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 SELECT src.endpoint_id, src.event_type, src.event_id, src.payload, 0,
		        ?, '%s', ?, ?, ?
		   FROM notification_deliveries src
		   JOIN notification_endpoints e ON e.id = src.endpoint_id
		  WHERE src.id = ?
		    AND src.status IN (%s)
		    AND e.user_id = ? AND e.enabled = 1`, DeliveryPending, deliveryTerminalStatuses)

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

// Create inserts e via a single statement that also enforces maxPerUser —
// design §10.1/§10.3's single-statement discipline: a preceding
// `SELECT count(*)` is not acceptable because internal/store has no
// transactions and SetMaxOpenConns(1) serialises statements, not sequences,
// so N concurrent creates would all read "under the cap" and all insert.
// e.ID, e.CreatedAt and e.UpdatedAt must already be set by the caller;
// enabled is always 1 for a newly created endpoint. Returns ErrConflict when
// the cap is exceeded (RowsAffected()==0) or (user_id, url) already exists
// (UNIQUE violation) — both are reported identically, since Create does not
// promise to distinguish them.
func (r *NotificationEndpointRepo) Create(ctx context.Context, e NotificationEndpoint, maxPerUser int) error {
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO notification_endpoints (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 SELECT ?, ?, ?, ?, ?, 1, ?, ?
		  WHERE (SELECT count(*) FROM notification_endpoints WHERE user_id = ?) < ?`,
		e.ID,           // 1: id
		e.UserID,       // 2: user_id
		e.Label,        // 3: label
		e.URL,          // 4: url
		e.SecretSealed, // 5: secret_sealed
		e.CreatedAt,    // 6: created_at
		e.UpdatedAt,    // 7: updated_at
		e.UserID,       // 8: cap subquery user_id
		maxPerUser,     // 9: cap subquery bound
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("notification_endpoints.Create: %w", ErrConflict)
		}
		return fmt.Errorf("notification_endpoints.Create: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("notification_endpoints.Create: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("notification_endpoints.Create: %w", ErrConflict)
	}
	return nil
}

// GetOwned fetches the endpoint identified by id, but only if it belongs to
// userID. Returns ErrNotFound if it does not exist or is owned by someone
// else — the two cases are indistinguishable by design, so ids stay
// unenumerable.
func (r *NotificationEndpointRepo) GetOwned(ctx context.Context, userID, id string) (NotificationEndpoint, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints WHERE id = ? AND user_id = ?`,
		id, userID,
	)
	e, err := scanNotificationEndpoint(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationEndpoint{}, fmt.Errorf("notification_endpoints.GetOwned: %w", ErrNotFound)
		}
		return NotificationEndpoint{}, fmt.Errorf("notification_endpoints.GetOwned: %w", err)
	}
	return e, nil
}

// ListByUser returns all notification endpoints owned by userID, regardless
// of enabled state. A user with none gets an empty (nil) slice, not an error.
func (r *NotificationEndpointRepo) ListByUser(ctx context.Context, userID string) ([]NotificationEndpoint, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+notificationEndpointColumns+` FROM notification_endpoints
		 WHERE user_id = ?
		 ORDER BY created_at, id`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListByUser: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []NotificationEndpoint
	for rows.Next() {
		e, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("notification_endpoints.ListByUser: scan: %w", err)
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_endpoints.ListByUser: rows: %w", err)
	}
	return result, nil
}

// SetEnabled toggles enabled for the endpoint identified by (id, userID).
// Returns ErrNotFound if no row matched — foreign or missing are
// indistinguishable.
func (r *NotificationEndpointRepo) SetEnabled(ctx context.Context, userID, id string, enabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE notification_endpoints SET enabled = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		boolToInt(enabled), NowUnix(), id, userID,
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

// Delete removes the endpoint identified by (id, userID); its deliveries
// cascade per the schema FK. Returns ErrNotFound if no row matched.
func (r *NotificationEndpointRepo) Delete(ctx context.Context, userID, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM notification_endpoints WHERE id = ? AND user_id = ?`,
		id, userID,
	)
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

// InsertUserTest inserts one endpoint.test delivery row for endpointID,
// budgeted against design §10.3's shared outbound-attempt budget. The
// ownership check (endpoint owned by userID and enabled), and the budget
// check (fewer than budget rows already stamped with user_initiated_at
// after windowStart), are both carried by this single statement — a
// preceding SELECT is not acceptable, per §10.3, because internal/store has
// no transactions and SetMaxOpenConns(1) serialises statements, not
// sequences: N concurrent callers would otherwise all read "under budget"
// and all insert.
//
// Returns (false, nil) — refused — when RowsAffected()==0, for any of:
// the endpoint does not exist, is owned by someone else, is disabled, or
// the budget is exhausted. Callers must report one generic message for all
// of these; the row count alone cannot distinguish them, by design.
func (r *NotificationDeliveryRepo) InsertUserTest(ctx context.Context, endpointID, userID string, payload []byte, now int64) (bool, error) {
	res, err := r.db.ExecContext(ctx, insertUserTestQuery,
		endpointID, // 1: endpoint_id
		payload,    // 2: payload
		now,        // 3: next_attempt_at
		now,        // 4: user_initiated_at
		now,        // 5: created_at
		now,        // 6: updated_at
		endpointID, // 7: EXISTS id
		userID,     // 8: EXISTS user_id
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
// deliveryID — it does not re-arm the existing row in place. A redelivery is
// another user-initiated attempt, so it must become another row stamped
// with user_initiated_at; an UPDATE that moved the stamp onto the existing
// row would not increase the budget-window row count and would not debit
// anything (design §10.3, §21). This also preserves the source row's
// history: its status/attempts/last_failure are untouched.
//
// The single statement carries ownership (via the join to
// notification_endpoints), the terminal-status and enabled predicates, and
// the same shared budget check as InsertUserTest — for the same atomicity
// reason. Returns (false, nil) — refused — when RowsAffected()==0, for any
// of: deliveryID does not exist, belongs to an endpoint not owned by
// userID, its endpoint is disabled, the source row is not terminal
// (status not in 'failed'/'delivered'), or the budget is exhausted.
func (r *NotificationDeliveryRepo) InsertRedelivery(ctx context.Context, deliveryID int64, userID string, now int64) (bool, error) {
	res, err := r.db.ExecContext(ctx, insertRedeliveryQuery,
		now,        // 1: next_attempt_at
		now,        // 2: user_initiated_at
		now,        // 3: created_at
		now,        // 4: updated_at
		deliveryID, // 5: src.id
		userID,     // 6: e.user_id
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
		        next_attempt_at, status, last_failure, user_initiated_at,
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
		var nextAttemptAt, userInitiatedAt sql.NullInt64
		var lastFailure sql.NullString
		if err := rows.Scan(
			&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload, &d.Attempts,
			&nextAttemptAt, &d.Status, &lastFailure, &userInitiatedAt,
			&d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("notification_deliveries.ListByEndpoint: scan: %w", err)
		}
		d.NextAttemptAt = nextAttemptAt.Int64
		d.LastFailure = lastFailure.String
		d.UserInitiatedAt = userInitiatedAt.Int64
		result = append(result, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notification_deliveries.ListByEndpoint: rows: %w", err)
	}
	return result, nil
}

// NotificationAttemptRepo provides the user-initiated outbound-attempt budget
// (design §10.3).
type NotificationAttemptRepo struct{ db *sql.DB }

// NotificationAttempts returns a NotificationAttemptRepo bound to this Store's
// database.
func (s *Store) NotificationAttempts() *NotificationAttemptRepo {
	return &NotificationAttemptRepo{db: s.db}
}

// claimAttemptQuery debits one user-initiated attempt if the user is under
// budget. It is ONE statement on purpose: internal/store has no transactions
// and SetMaxOpenConns(1) serialises statements, not sequences, so a
// SELECT-then-INSERT pair would let N concurrent requests all read "under
// budget" and all proceed.
const claimAttemptQuery = `INSERT INTO notification_attempts (user_id, at)
		 SELECT ?, ?
		  WHERE (SELECT count(*) FROM notification_attempts
		          WHERE user_id = ? AND at > ?) < ?`

// Claim debits one user-initiated outbound attempt against userID's rolling
// window, reporting whether it was allowed. windowStart is the exclusive lower
// bound on `at`; budget is the cap.
//
// Callers claim BEFORE performing the work. A claim spent on a request that is
// then refused for some other reason (endpoint disabled, not owned, source row
// not terminal) is the safe direction: over-counting attempts throttles a user
// slightly early, whereas claiming afterwards would let concurrent requests
// race past the cap before any of them recorded anything.
//
// This ledger deliberately does not reference notification_endpoints. Counting
// stamped notification_deliveries rows instead let a user reset the window by
// deleting and recreating an endpoint, because those rows cascade — verified,
// 5 stamped rows before the delete and 0 after.
func (r *NotificationAttemptRepo) Claim(ctx context.Context, userID string, now, windowStart int64, budget int) (bool, error) {
	res, err := r.db.ExecContext(ctx, claimAttemptQuery, userID, now, userID, windowStart, budget)
	if err != nil {
		return false, fmt.Errorf("notification_attempts.Claim: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("notification_attempts.Claim: RowsAffected: %w", err)
	}
	return n != 0, nil
}

// PruneExpired deletes attempt-ledger rows stamped before olderThan, returning
// the number removed.
//
// This is expiry-gated, not retention-gated, and deliberately has no
// retention.* key: a ledger row's only purpose is to be counted by Claim
// inside a live budget window, so once it falls outside the widest window the
// server can ask about it carries no information an operator could have a
// policy about — the same reasoning that gates replay_nonces and sessions.
//
// Unbatched, unlike the retention sweeps: the table is bounded by
// budget x users x window (at most a few dozen rows per user between hourly
// sweeps), so there is no backlog for a LIMIT to protect the single
// process-wide SQLite connection from.
func (r *NotificationAttemptRepo) PruneExpired(ctx context.Context, olderThan int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM notification_attempts WHERE at < ?`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("notification_attempts.PruneExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("notification_attempts.PruneExpired: RowsAffected: %w", err)
	}
	return int(n), nil
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
