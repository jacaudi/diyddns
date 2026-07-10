package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// AuditEntry is the persisted shape of a single auth/lifecycle audit event
// (matches the audit_log table columns 1:1; null-safe). ActorUserID is
// empty for system events with no actor; TargetType, TargetID, DetailsJSON,
// IP, and UserAgent are empty when unset. Empty Go strings map to SQL NULL
// on write (see nullOrString). ID is assigned by SQLite on Append.
type AuditEntry struct {
	ID          int64
	ActorUserID string
	EventType   string
	TargetType  string
	TargetID    string
	DetailsJSON string
	IP          string
	UserAgent   string
	CreatedAt   int64
}

// AuditFilter narrows the result set ListPaginated returns. A zero value in
// any field means "no filter" for that dimension: ActorUserID/EventType
// match exactly when non-empty; Since/Until bound created_at (inclusive)
// when non-zero.
type AuditFilter struct {
	ActorUserID string
	EventType   string
	Since       int64
	Until       int64
}

// AuditPage is a cursor-paginated slice of AuditEntry rows, ordered
// (created_at DESC, id DESC). NextCursor is empty when there are no more
// rows to fetch.
type AuditPage struct {
	Rows       []AuditEntry
	NextCursor string
}

// AuditLogRepo is the repository for the audit_log table.
type AuditLogRepo struct{ db *sql.DB }

// AuditLog returns the repository for the audit_log table.
func (s *Store) AuditLog() *AuditLogRepo { return &AuditLogRepo{db: s.db} }

const selectAuditLogColumns = `id, actor_user_id, event_type, target_type, target_id, details_json, ip, user_agent, created_at`

// scanAuditEntry scans a single audit_log row, in column order, into an
// AuditEntry. The five nullable text columns are scanned into
// sql.NullString and converted back to Go zero values (empty string) when
// NULL.
func scanAuditEntry(scan func(dest ...any) error) (AuditEntry, error) {
	var (
		e                                                             AuditEntry
		actorUserID, targetType, targetID, detailsJSON, ip, userAgent sql.NullString
	)
	err := scan(&e.ID, &actorUserID, &e.EventType, &targetType, &targetID, &detailsJSON, &ip, &userAgent, &e.CreatedAt)
	if err != nil {
		return AuditEntry{}, err
	}
	e.ActorUserID = actorUserID.String
	e.TargetType = targetType.String
	e.TargetID = targetID.String
	e.DetailsJSON = detailsJSON.String
	e.IP = ip.String
	e.UserAgent = userAgent.String
	return e, nil
}

// Append inserts e, assigning CreatedAt = NowUnix() if it is zero. It
// returns the saved row with its SQLite-assigned ID. There is no conflict
// path here: audit_log is append-only with no UNIQUE constraint beyond the
// autoincrement primary key.
func (r *AuditLogRepo) Append(ctx context.Context, e AuditEntry) (AuditEntry, error) {
	if e.CreatedAt == 0 {
		e.CreatedAt = NowUnix()
	}

	res, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_log (actor_user_id, event_type, target_type, target_id, details_json, ip, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		nullOrString(e.ActorUserID), e.EventType, nullOrString(e.TargetType), nullOrString(e.TargetID),
		nullOrString(e.DetailsJSON), nullOrString(e.IP), nullOrString(e.UserAgent), e.CreatedAt,
	)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("store: append audit log event %q: %w", e.EventType, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AuditEntry{}, fmt.Errorf("store: append audit log event %q: last insert id: %w", e.EventType, err)
	}
	e.ID = id
	return e, nil
}

// auditPageDefaultLimit is the default page size for ListPaginated. It
// deliberately differs from ip_history's clampPageLimit default (50):
// audit_log is expected to have a higher read volume per page (compliance
// exports, admin review). pageMaxLimit (defined in ip_history.go, same
// package) is reused as-is: both task specs hardcode 500 as the same
// platform-wide page-size cap, so it is single-sourced rather than
// duplicated here.
const auditPageDefaultLimit = 100

// clampAuditLimit clamps limit to [1, pageMaxLimit], defaulting to
// auditPageDefaultLimit when limit is zero or negative.
func clampAuditLimit(limit int) int {
	switch {
	case limit <= 0:
		return auditPageDefaultLimit
	case limit > pageMaxLimit:
		return pageMaxLimit
	default:
		return limit
	}
}

// encodeAuditCursor produces the opaque cursor for a page boundary at
// (createdAt, id): base64 of "{created_at}:{id}" — the same scheme
// ip_history uses (see encodeHistoryCursor), reimplemented here rather than
// shared: the two aggregates' cursor formats are only coincidentally
// identical today, not a contract that must change together.
func encodeAuditCursor(createdAt, id int64) string {
	return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%d:%d", createdAt, id))
}

// decodeAuditCursor reverses encodeAuditCursor, returning the (createdAt,
// id) boundary to page from.
func decodeAuditCursor(cursor string) (createdAt, id int64, err error) {
	raw, err := base64.StdEncoding.DecodeString(cursor)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: %w", err)
	}
	before, after, ok := strings.Cut(string(raw), ":")
	if !ok {
		return 0, 0, fmt.Errorf("decode cursor: malformed %q", raw)
	}
	createdAt, err = strconv.ParseInt(before, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: parse created_at: %w", err)
	}
	id, err = strconv.ParseInt(after, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: parse id: %w", err)
	}
	return createdAt, id, nil
}

// auditWhereClause builds the WHERE clause (including the leading "WHERE",
// or "" if there are no conditions at all) and its parameterized args for f
// combined with the keyset predicate for cursor pagination on (created_at,
// id) when cursorSet is true. All values are bound as query args — never
// string-concatenated — so this cannot be used for SQL injection regardless
// of filter content. Extracted from ListPaginated to keep its cyclomatic
// complexity low.
func auditWhereClause(f AuditFilter, cursorSet bool, createdAt, id int64) (string, []any) {
	var conds []string
	var args []any

	if f.ActorUserID != "" {
		conds = append(conds, "actor_user_id = ?")
		args = append(args, f.ActorUserID)
	}
	if f.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.Since != 0 {
		conds = append(conds, "created_at >= ?")
		args = append(args, f.Since)
	}
	if f.Until != 0 {
		conds = append(conds, "created_at <= ?")
		args = append(args, f.Until)
	}
	if cursorSet {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, createdAt, createdAt, id)
	}

	if len(conds) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ListPaginated returns up to limit rows matching f, starting after cursor,
// ordered (created_at DESC, id DESC). cursor is empty for the first page.
// limit is clamped via clampAuditLimit. NextCursor on the returned page is
// empty once there are no more rows.
func (r *AuditLogRepo) ListPaginated(ctx context.Context, f AuditFilter, cursor string, limit int) (AuditPage, error) {
	limit = clampAuditLimit(limit)

	var (
		createdAt, cursorID int64
		cursorSet           bool
	)
	if cursor != "" {
		var err error
		createdAt, cursorID, err = decodeAuditCursor(cursor)
		if err != nil {
			return AuditPage{}, fmt.Errorf("store: list audit log: %w", err)
		}
		cursorSet = true
	}

	where, args := auditWhereClause(f, cursorSet, createdAt, cursorID)
	args = append(args, limit+1)

	//nolint:gosec // G202: where is built only from static SQL fragments chosen
	// by auditWhereClause (column names/operators from a fixed set); every
	// filter VALUE is bound via the parameterized args slice below, never
	// concatenated into the query text.
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+selectAuditLogColumns+` FROM audit_log
		 `+where+`
		 ORDER BY created_at DESC, id DESC
		 LIMIT ?`,
		args...,
	)
	if err != nil {
		return AuditPage{}, fmt.Errorf("store: list audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var page AuditPage
	for rows.Next() {
		e, scanErr := scanAuditEntry(rows.Scan)
		if scanErr != nil {
			return AuditPage{}, fmt.Errorf("store: list audit log: scan: %w", scanErr)
		}
		page.Rows = append(page.Rows, e)
	}
	if err := rows.Err(); err != nil {
		return AuditPage{}, fmt.Errorf("store: list audit log: %w", err)
	}

	// Fetching limit+1 rows lets us detect "more rows exist" without a
	// separate COUNT query: if we got the extra row, trim it and cursor from
	// the last kept row; otherwise this is the final page.
	if len(page.Rows) > limit {
		last := page.Rows[limit-1]
		page.NextCursor = encodeAuditCursor(last.CreatedAt, last.ID)
		page.Rows = page.Rows[:limit]
	}
	return page, nil
}

// Prune deletes audit_log rows with created_at strictly before olderThan.
// Unlike ip_history.Prune, there is no always-keep-latest guard: audit_log
// is a plain append-only log with no natural "latest per key" to protect.
// Returns the number of rows deleted.
func (r *AuditLogRepo) Prune(ctx context.Context, olderThan int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM audit_log WHERE created_at < ?`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: prune audit log: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune audit log: rows affected: %w", err)
	}
	return int(n), nil
}
