package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IPHistory records a single observed IP address event for a device.
type IPHistory struct {
	ID            int64
	DeviceID      string
	IPv4          string
	IPv6          string
	ObservedAt    int64
	ClientVersion string
}

// HistoryPage is a cursor-paginated slice of IPHistory rows.
type HistoryPage struct {
	Rows       []IPHistory
	NextCursor string // empty if no more rows
}

// IPHistoryRepo provides persistence operations for IPHistory records.
type IPHistoryRepo struct{ db *sql.DB }

// IPHistory returns an IPHistoryRepo bound to this Store's database.
func (s *Store) IPHistory() *IPHistoryRepo { return &IPHistoryRepo{db: s.db} }

const ipHistoryColumns = `id, device_id, ipv4, ipv6, observed_at, client_version`

func scanIPHistory(row interface {
	Scan(dest ...any) error
}) (IPHistory, error) {
	var h IPHistory
	var ipv4, ipv6, clientVersion sql.NullString
	err := row.Scan(
		&h.ID,
		&h.DeviceID,
		&ipv4,
		&ipv6,
		&h.ObservedAt,
		&clientVersion,
	)
	if err != nil {
		return IPHistory{}, err
	}
	h.IPv4 = scanString(ipv4)
	h.IPv6 = scanString(ipv6)
	h.ClientVersion = scanString(clientVersion)
	return h, nil
}

// encodeCursor encodes an (observedAt, id) pair as an opaque base64 cursor.
func encodeCursor(observedAt, id int64) string {
	raw := fmt.Sprintf("%d:%d", observedAt, id)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// decodeCursor decodes a cursor produced by encodeCursor.
func decodeCursor(c string) (observedAt, id int64, err error) {
	if c == "" {
		return 0, 0, nil
	}
	raw, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, fmt.Errorf("store: ip_history cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("store: ip_history cursor format")
	}
	observedAt, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("store: ip_history cursor observedAt: %w", err)
	}
	id, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("store: ip_history cursor id: %w", err)
	}
	return observedAt, id, nil
}

// Append inserts a new IPHistory row. If h.ObservedAt is zero, it is set to
// NowUnix(). Returns the inserted row with ID populated from LastInsertId.
func (r *IPHistoryRepo) Append(ctx context.Context, h IPHistory) (IPHistory, error) {
	if h.ObservedAt == 0 {
		h.ObservedAt = NowUnix()
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO ip_history (device_id, ipv4, ipv6, observed_at, client_version)
		 VALUES (?, ?, ?, ?, ?)`,
		h.DeviceID,
		nullIfEmpty(h.IPv4),
		nullIfEmpty(h.IPv6),
		h.ObservedAt,
		nullIfEmpty(h.ClientVersion),
	)
	if err != nil {
		return IPHistory{}, fmt.Errorf("ip_history.Append: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return IPHistory{}, fmt.Errorf("ip_history.Append: LastInsertId: %w", err)
	}
	h.ID = id
	return h, nil
}

// Latest returns the most recently observed IPHistory row for the given device.
// Returns ErrNotFound if no rows exist for that device.
func (r *IPHistoryRepo) Latest(ctx context.Context, deviceID string) (IPHistory, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+ipHistoryColumns+` FROM ip_history
		 WHERE device_id = ?
		 ORDER BY observed_at DESC, id DESC
		 LIMIT 1`,
		deviceID,
	)
	h, err := scanIPHistory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IPHistory{}, fmt.Errorf("ip_history.Latest: %w", ErrNotFound)
		}
		return IPHistory{}, fmt.Errorf("ip_history.Latest: %w", err)
	}
	return h, nil
}

// Page returns a cursor-paginated slice of IPHistory rows for deviceID, ordered
// newest-first. limit is clamped to [1, 500]; 0 or negative defaults to 50.
// Pass cursor="" for the first page; pass HistoryPage.NextCursor for subsequent
// pages. NextCursor is empty when the caller has reached the end of the stream.
func (r *IPHistoryRepo) Page(ctx context.Context, deviceID, cursor string, limit int) (HistoryPage, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	var (
		rows *sql.Rows
		err  error
	)

	if cursor == "" {
		rows, err = r.db.QueryContext(ctx,
			`SELECT `+ipHistoryColumns+` FROM ip_history
			 WHERE device_id = ?
			 ORDER BY observed_at DESC, id DESC
			 LIMIT ?`,
			deviceID, limit,
		)
	} else {
		cursorTs, cursorID, decErr := decodeCursor(cursor)
		if decErr != nil {
			return HistoryPage{}, fmt.Errorf("ip_history.Page: %w", decErr)
		}
		rows, err = r.db.QueryContext(ctx,
			`SELECT `+ipHistoryColumns+` FROM ip_history
			 WHERE device_id = ?
			   AND (observed_at < ? OR (observed_at = ? AND id < ?))
			 ORDER BY observed_at DESC, id DESC
			 LIMIT ?`,
			deviceID, cursorTs, cursorTs, cursorID, limit,
		)
	}
	if err != nil {
		return HistoryPage{}, fmt.Errorf("ip_history.Page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []IPHistory
	for rows.Next() {
		h, err := scanIPHistory(rows)
		if err != nil {
			return HistoryPage{}, fmt.Errorf("ip_history.Page: scan: %w", err)
		}
		result = append(result, h)
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, fmt.Errorf("ip_history.Page: rows: %w", err)
	}

	var nextCursor string
	if len(result) == limit {
		last := result[len(result)-1]
		nextCursor = encodeCursor(last.ObservedAt, last.ID)
	}

	return HistoryPage{Rows: result, NextCursor: nextCursor}, nil
}

// Prune deletes rows for deviceID that are either older than olderThan (unix
// seconds) or beyond perDeviceMax newest rows — but never deletes the row with
// the highest id (the most recent insert) for that device.
//
// If perDeviceMax <= 0 the per-device cap is treated as unlimited.
// Returns the number of rows deleted.
func (r *IPHistoryRepo) Prune(ctx context.Context, deviceID string, olderThan int64, perDeviceMax int) (int, error) {
	cap := perDeviceMax
	if cap <= 0 {
		cap = 1<<31 - 1
	}

	res, err := r.db.ExecContext(ctx,
		`DELETE FROM ip_history
		 WHERE device_id = ?
		   AND id NOT IN (
		     SELECT MAX(id) FROM ip_history WHERE device_id = ?
		   )
		   AND (
		     observed_at < ?
		     OR id < (
		       SELECT MIN(id) FROM (
		         SELECT id FROM ip_history
		         WHERE device_id = ?
		         ORDER BY id DESC
		         LIMIT ?
		       )
		     )
		   )`,
		deviceID, deviceID, olderThan, deviceID, cap,
	)
	if err != nil {
		return 0, fmt.Errorf("ip_history.Prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("ip_history.Prune: RowsAffected: %w", err)
	}
	return int(n), nil
}
