package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// AuditEntry represents a single row in the audit_log table.
type AuditEntry struct {
	ID          int64
	ActorUserID string // empty for system events
	EventType   string
	TargetType  string
	TargetID    string
	DetailsJSON string
	IP          string
	UserAgent   string
	CreatedAt   int64
}

// AuditFilter narrows the result set for ListPaginated.
type AuditFilter struct {
	ActorUserID string // empty = no filter
	EventType   string // empty = no filter
	Since       int64  // 0 = no lower bound
	Until       int64  // 0 = no upper bound
}

// AuditPage is a cursor-paginated slice of AuditEntry rows.
type AuditPage struct {
	Rows       []AuditEntry
	NextCursor string // empty if no more rows
}

// AuditLogRepo provides persistence operations for AuditEntry records.
type AuditLogRepo struct{ db *sql.DB }

// AuditLog returns an AuditLogRepo bound to this Store's database.
func (s *Store) AuditLog() *AuditLogRepo { return &AuditLogRepo{db: s.db} }

const auditLogColumns = `id, actor_user_id, event_type, target_type, target_id, details_json, ip, user_agent, created_at`

func scanAuditEntry(row interface {
	Scan(dest ...any) error
}) (AuditEntry, error) {
	var e AuditEntry
	var actorUserID, targetType, targetID, detailsJSON, ip, userAgent sql.NullString
	err := row.Scan(
		&e.ID,
		&actorUserID,
		&e.EventType,
		&targetType,
		&targetID,
		&detailsJSON,
		&ip,
		&userAgent,
		&e.CreatedAt,
	)
	if err != nil {
		return AuditEntry{}, err
	}
	e.ActorUserID = scanString(actorUserID)
	e.TargetType = scanString(targetType)
	e.TargetID = scanString(targetID)
	e.DetailsJSON = scanString(detailsJSON)
	e.IP = scanString(ip)
	e.UserAgent = scanString(userAgent)
	return e, nil
}

// encodeAuditCursor encodes a (createdAt, id) pair as an opaque base64 cursor.
func encodeAuditCursor(createdAt, id int64) string {
	raw := fmt.Sprintf("%d:%d", createdAt, id)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// decodeAuditCursor decodes a cursor produced by encodeAuditCursor.
func decodeAuditCursor(c string) (createdAt, id int64, err error) {
	if c == "" {
		return 0, 0, nil
	}
	raw, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, fmt.Errorf("store: audit_log cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("store: audit_log cursor format")
	}
	createdAt, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("store: audit_log cursor createdAt: %w", err)
	}
	id, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("store: audit_log cursor id: %w", err)
	}
	return createdAt, id, nil
}

// Append inserts a new AuditEntry row. If e.CreatedAt is zero, it is set to
// NowUnix(). Returns the inserted row with ID populated from LastInsertId.
func (r *AuditLogRepo) Append(ctx context.Context, e AuditEntry) (AuditEntry, error) {
	if e.CreatedAt == 0 {
		e.CreatedAt = NowUnix()
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_log (actor_user_id, event_type, target_type, target_id, details_json, ip, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		nullIfEmpty(e.ActorUserID),
		e.EventType,
		nullIfEmpty(e.TargetType),
		nullIfEmpty(e.TargetID),
		nullIfEmpty(e.DetailsJSON),
		nullIfEmpty(e.IP),
		nullIfEmpty(e.UserAgent),
		e.CreatedAt,
	)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("audit_log.Append: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AuditEntry{}, fmt.Errorf("audit_log.Append: LastInsertId: %w", err)
	}
	e.ID = id
	return e, nil
}

// ListPaginated returns a cursor-paginated slice of AuditEntry rows, ordered
// newest-first (created_at DESC, id DESC). limit is clamped to [1, 500]; 0 or
// negative defaults to 100. Filters are combined with AND; zero/empty values
// are ignored. Pass cursor="" for the first page; pass AuditPage.NextCursor for
// subsequent pages. NextCursor is empty when all rows have been returned.
func (r *AuditLogRepo) ListPaginated(ctx context.Context, f AuditFilter, cursor string, limit int) (AuditPage, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	var (
		clauses []string
		args    []any
	)

	if f.ActorUserID != "" {
		clauses = append(clauses, `actor_user_id = ?`)
		args = append(args, f.ActorUserID)
	}
	if f.EventType != "" {
		clauses = append(clauses, `event_type = ?`)
		args = append(args, f.EventType)
	}
	if f.Since != 0 {
		clauses = append(clauses, `created_at >= ?`)
		args = append(args, f.Since)
	}
	if f.Until != 0 {
		clauses = append(clauses, `created_at <= ?`)
		args = append(args, f.Until)
	}

	if cursor != "" {
		cursorTs, cursorID, decErr := decodeAuditCursor(cursor)
		if decErr != nil {
			return AuditPage{}, fmt.Errorf("audit_log.ListPaginated: %w", decErr)
		}
		clauses = append(clauses, `(created_at < ? OR (created_at = ? AND id < ?))`)
		args = append(args, cursorTs, cursorTs, cursorID)
	}

	query := `SELECT ` + auditLogColumns + ` FROM audit_log`
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, ` AND `) // #nosec G202 -- clauses are hardcoded SQL fragments; user input flows only through parameterized args.
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return AuditPage{}, fmt.Errorf("audit_log.ListPaginated: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []AuditEntry
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return AuditPage{}, fmt.Errorf("audit_log.ListPaginated: scan: %w", err)
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return AuditPage{}, fmt.Errorf("audit_log.ListPaginated: rows: %w", err)
	}

	var nextCursor string
	if len(result) == limit {
		last := result[len(result)-1]
		nextCursor = encodeAuditCursor(last.CreatedAt, last.ID)
	}

	return AuditPage{Rows: result, NextCursor: nextCursor}, nil
}

// Prune deletes all rows with created_at < olderThan.
// Returns the number of rows deleted.
func (r *AuditLogRepo) Prune(ctx context.Context, olderThan int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM audit_log WHERE created_at < ?`,
		olderThan,
	)
	if err != nil {
		return 0, fmt.Errorf("audit_log.Prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit_log.Prune: RowsAffected: %w", err)
	}
	return int(n), nil
}
