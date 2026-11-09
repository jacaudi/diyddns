package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// slowStatementThreshold is how long one statement may hold the store's only
// connection (SetMaxOpenConns(1)) before it is reported. A quarter of
// /readyz's 2 s ping timeout, so the warning lands well before an outage.
// Not configurable: no operator has a policy about this number (#103).
const slowStatementThreshold = 500 * time.Millisecond

// maxLoggedSQL caps the statement text in a slow-statement record.
const maxLoggedSQL = 200

var (
	sqliteDriverOnce sync.Once
	sqliteDriver     driver.Driver
	errSqliteDriver  error
)

// innerSQLiteDriver returns modernc's registered driver. Its constructor and
// fields are unexported, so the only route to it is through a *sql.DB.
func innerSQLiteDriver() (driver.Driver, error) {
	sqliteDriverOnce.Do(func() {
		db, err := sql.Open("sqlite", "")
		if err != nil {
			errSqliteDriver = fmt.Errorf("store: obtain sqlite driver: %w", err)
			return
		}
		sqliteDriver = db.Driver()
		_ = db.Close()
	})
	return sqliteDriver, errSqliteDriver
}

// timedConnector opens modernc connections wrapped so every statement's
// connection hold is timed. It is per store, so nothing is registered
// globally and a second store in the same process cannot collide.
type timedConnector struct {
	dsn       string
	log       *slog.Logger
	threshold time.Duration
}

// newTimedConnector returns a connector for sql.OpenDB that warns through
// log whenever one statement holds the connection for threshold or longer.
func newTimedConnector(dsn string, log *slog.Logger, threshold time.Duration) driver.Connector {
	return &timedConnector{dsn: dsn, log: log, threshold: threshold}
}

// innerConn is every interface modernc's conn implements that database/sql
// consults. Requiring all of them keeps the wrapper behavior-neutral.
// PrepareContext is forwarded untimed: database/sql prepares only for an
// explicit Prepare, which nothing in this module or goose calls, or when
// ExecContext/QueryContext return driver.ErrSkip, which modernc never does.
type innerConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

func (c *timedConnector) Connect(context.Context) (driver.Conn, error) {
	d, err := innerSQLiteDriver()
	if err != nil {
		return nil, err
	}
	raw, err := d.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	ic, ok := raw.(innerConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("store: sqlite conn %T lacks an interface the timing wrapper forwards", raw)
	}
	return &timedConn{innerConn: ic, c: c}, nil
}

func (c *timedConnector) Driver() driver.Driver {
	d, _ := innerSQLiteDriver()
	return d
}

// report logs one slow-statement record when the hold reached the threshold.
// Bound arguments are never passed here: they carry device ids and emails.
func (c *timedConnector) report(ctx context.Context, query string, start time.Time) {
	elapsed := time.Since(start)
	if elapsed < c.threshold {
		return
	}
	c.log.WarnContext(ctx, "store: slow statement",
		slog.String("sql", loggableSQL(query)),
		slog.Int64("duration_ms", elapsed.Milliseconds()))
}

// loggableSQL collapses whitespace runs to one space and caps the length.
func loggableSQL(query string) string {
	s := strings.Join(strings.Fields(query), " ")
	if len(s) > maxLoggedSQL {
		s = s[:maxLoggedSQL]
	}
	return s
}

type timedConn struct {
	innerConn
	c *timedConnector
}

func (t *timedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	defer t.c.report(ctx, query, time.Now())
	return t.innerConn.ExecContext(ctx, query, args)
}

func (t *timedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	start := time.Now()
	rows, err := t.innerConn.QueryContext(ctx, query, args)
	if err != nil {
		t.c.report(ctx, query, start)
		return nil, err
	}
	return &timedRows{Rows: rows, done: func() { t.c.report(ctx, query, start) }}, nil
}

func (t *timedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := t.innerConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &timedTx{Tx: tx, c: t.c, ctx: ctx}, nil
}

// timedTx times Commit and Rollback: modernc runs them directly rather than
// through ExecContext, and a commit can carry a WAL checkpoint's fsync.
type timedTx struct {
	driver.Tx
	c   *timedConnector
	ctx context.Context
}

func (t *timedTx) Commit() error {
	defer t.c.report(t.ctx, "COMMIT", time.Now())
	return t.Tx.Commit()
}

func (t *timedTx) Rollback() error {
	defer t.c.report(t.ctx, "ROLLBACK", time.Now())
	return t.Tx.Rollback()
}

// timedRows stops the timer at Close: modernc returns from QueryContext after
// one step and the rest of the read runs in Next, so the connection is held
// until the rows are released. database/sql calls Close exactly once, at EOF
// or on an explicit Close.
type timedRows struct {
	driver.Rows
	done func()
	once sync.Once
}

func (r *timedRows) Close() error {
	err := r.Rows.Close()
	r.once.Do(r.done)
	return err
}
