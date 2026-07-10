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

// IPHistory is the persisted shape of a single observed-IP event for a
// device (matches the ip_history table columns 1:1; null-safe). IPv4, IPv6,
// and ClientVersion are empty when unset; empty Go strings map to SQL NULL
// on write (see nullOrString). ID is assigned by SQLite on Append.
type IPHistory struct {
	ID            int64
	DeviceID      string
	IPv4          string
	IPv6          string
	ObservedAt    int64
	ClientVersion string
}

// HistoryPage is a cursor-paginated slice of IPHistory rows, ordered
// (observed_at DESC, id DESC). NextCursor is empty when there are no more
// rows to fetch.
type HistoryPage struct {
	Rows       []IPHistory
	NextCursor string
}

// IPHistoryRepo is the repository for the ip_history table.
type IPHistoryRepo struct{ db *sql.DB }

// IPHistory returns the repository for the ip_history table.
func (s *Store) IPHistory() *IPHistoryRepo { return &IPHistoryRepo{db: s.db} }

const selectIPHistoryColumns = `id, device_id, ipv4, ipv6, observed_at, client_version`

// scanIPHistory scans a single ip_history row, in column order, into an
// IPHistory. The three nullable text columns are scanned into
// sql.NullString and converted back to Go zero values (empty string) when
// NULL.
func scanIPHistory(scan func(dest ...any) error) (IPHistory, error) {
	var (
		h                    IPHistory
		ipv4, ipv6, clientVr sql.NullString
	)
	err := scan(&h.ID, &h.DeviceID, &ipv4, &ipv6, &h.ObservedAt, &clientVr)
	if err != nil {
		return IPHistory{}, err
	}
	h.IPv4 = ipv4.String
	h.IPv6 = ipv6.String
	h.ClientVersion = clientVr.String
	return h, nil
}

// Append inserts h, assigning ObservedAt = NowUnix() if it is zero. It
// returns the saved row with its SQLite-assigned ID.
func (r *IPHistoryRepo) Append(ctx context.Context, h IPHistory) (IPHistory, error) {
	if h.ObservedAt == 0 {
		h.ObservedAt = NowUnix()
	}

	res, err := r.db.ExecContext(ctx, `
		INSERT INTO ip_history (device_id, ipv4, ipv6, observed_at, client_version)
		VALUES (?, ?, ?, ?, ?)`,
		h.DeviceID, nullOrString(h.IPv4), nullOrString(h.IPv6), h.ObservedAt, nullOrString(h.ClientVersion),
	)
	if err != nil {
		return IPHistory{}, fmt.Errorf("store: append ip history for device %q: %w", h.DeviceID, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return IPHistory{}, fmt.Errorf("store: append ip history for device %q: last insert id: %w", h.DeviceID, err)
	}
	h.ID = id
	return h, nil
}

// Latest returns the most-recently observed row for deviceID, ordered by
// (observed_at DESC, id DESC). Returns ErrNotFound if the device has no
// history rows.
func (r *IPHistoryRepo) Latest(ctx context.Context, deviceID string) (IPHistory, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+selectIPHistoryColumns+` FROM ip_history
		 WHERE device_id = ?
		 ORDER BY observed_at DESC, id DESC
		 LIMIT 1`,
		deviceID,
	)
	h, err := scanIPHistory(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IPHistory{}, fmt.Errorf("store: latest ip history for device %q: %w", deviceID, ErrNotFound)
		}
		return IPHistory{}, fmt.Errorf("store: latest ip history for device %q: %w", deviceID, err)
	}
	return h, nil
}

// pageDefaultLimit and pageMaxLimit bound the limit argument to Page.
const (
	pageDefaultLimit = 50
	pageMaxLimit     = 500
)

// clampPageLimit clamps limit to [1, pageMaxLimit], defaulting to
// pageDefaultLimit when limit is zero or negative.
func clampPageLimit(limit int) int {
	switch {
	case limit <= 0:
		return pageDefaultLimit
	case limit > pageMaxLimit:
		return pageMaxLimit
	default:
		return limit
	}
}

// encodeHistoryCursor produces the opaque cursor for a page boundary at
// (observedAt, id): base64 of "{observed_at}:{id}".
func encodeHistoryCursor(observedAt, id int64) string {
	return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%d:%d", observedAt, id))
}

// decodeHistoryCursor reverses encodeHistoryCursor, returning the
// (observedAt, id) boundary to page from.
func decodeHistoryCursor(cursor string) (observedAt, id int64, err error) {
	raw, err := base64.StdEncoding.DecodeString(cursor)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: %w", err)
	}
	before, after, ok := strings.Cut(string(raw), ":")
	if !ok {
		return 0, 0, fmt.Errorf("decode cursor: malformed %q", raw)
	}
	observedAt, err = strconv.ParseInt(before, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: parse observed_at: %w", err)
	}
	id, err = strconv.ParseInt(after, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("decode cursor: parse id: %w", err)
	}
	return observedAt, id, nil
}

// Page returns up to limit rows for deviceID starting after cursor, ordered
// (observed_at DESC, id DESC). cursor is empty for the first page. limit is
// clamped via clampPageLimit. NextCursor on the returned page is empty once
// there are no more rows.
func (r *IPHistoryRepo) Page(ctx context.Context, deviceID, cursor string, limit int) (HistoryPage, error) {
	limit = clampPageLimit(limit)

	var (
		rows *sql.Rows
		err  error
	)
	if cursor == "" {
		rows, err = r.db.QueryContext(ctx,
			`SELECT `+selectIPHistoryColumns+` FROM ip_history
			 WHERE device_id = ?
			 ORDER BY observed_at DESC, id DESC
			 LIMIT ?`,
			deviceID, limit+1,
		)
	} else {
		observedAt, id, decodeErr := decodeHistoryCursor(cursor)
		if decodeErr != nil {
			return HistoryPage{}, fmt.Errorf("store: page ip history for device %q: %w", deviceID, decodeErr)
		}
		rows, err = r.db.QueryContext(ctx,
			`SELECT `+selectIPHistoryColumns+` FROM ip_history
			 WHERE device_id = ? AND (observed_at < ? OR (observed_at = ? AND id < ?))
			 ORDER BY observed_at DESC, id DESC
			 LIMIT ?`,
			deviceID, observedAt, observedAt, id, limit+1,
		)
	}
	if err != nil {
		return HistoryPage{}, fmt.Errorf("store: page ip history for device %q: %w", deviceID, err)
	}
	defer func() { _ = rows.Close() }()

	var page HistoryPage
	for rows.Next() {
		h, scanErr := scanIPHistory(rows.Scan)
		if scanErr != nil {
			return HistoryPage{}, fmt.Errorf("store: page ip history for device %q: scan: %w", deviceID, scanErr)
		}
		page.Rows = append(page.Rows, h)
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, fmt.Errorf("store: page ip history for device %q: %w", deviceID, err)
	}

	// Fetching limit+1 rows lets us detect "more rows exist" without a
	// separate COUNT query: if we got the extra row, trim it and cursor from
	// the last kept row; otherwise this is the final page.
	if len(page.Rows) > limit {
		last := page.Rows[limit-1]
		page.NextCursor = encodeHistoryCursor(last.ObservedAt, last.ID)
		page.Rows = page.Rows[:limit]
	}
	return page, nil
}

// Prune deletes ip_history rows for deviceID that are either older than
// olderThan or beyond the perDeviceMax newest (by id), except it never
// deletes the device's most-recent row (always_keep_latest). Returns the
// number of rows deleted.
//
// Two retention limits combine (a row is deleted if it trips either one, and
// the always-keep-latest protection always wins):
//
//   - Age: rows with observed_at < olderThan are pruned. Pass olderThan = 0 to
//     disable age-based pruning (no row has observed_at < 0).
//   - Count: rows beyond the perDeviceMax newest (by id) are pruned. A
//     perDeviceMax <= 0 DISABLES the per-device count cap (unlimited retained
//     by count) — matching the design's "0 = unlimited" retention convention
//     (design §8). A perDeviceMax >= 1 keeps the N newest rows (always
//     including the latest). Mechanically the cap contributes nothing when
//     perDeviceMax <= 0: LIMIT 0 yields an empty subquery so MIN(id) is NULL,
//     and a negative LIMIT means "no limit" so MIN(id) is the smallest id —
//     either way `id < (that)` is never true. When the cap is disabled,
//     age-based pruning and the always-keep-latest guarantee still apply.
func (r *IPHistoryRepo) Prune(ctx context.Context, deviceID string, olderThan int64, perDeviceMax int) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM ip_history
		WHERE device_id = ?
		  -- always_keep_latest: MAX(id) per device_id is design §3's mandated
		  -- "latest" row and is monotonic with observed_at in v1 (the only
		  -- append path, checkin, sets ObservedAt = NowUnix()), so MAX(id) is
		  -- also the (observed_at DESC, id DESC) newest that Latest/Page return.
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
		deviceID, deviceID, olderThan, deviceID, perDeviceMax,
	)
	if err != nil {
		return 0, fmt.Errorf("store: prune ip history for device %q: %w", deviceID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune ip history for device %q: rows affected: %w", deviceID, err)
	}
	return int(n), nil
}
