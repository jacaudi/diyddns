# DIYDDNS — Plan 02: Storage & Migrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Pair:** [docs/plans/2026-05-01-diyddns-design.md](2026-05-01-diyddns-design.md)
**Scope:** Plan 02 of 8 — see decomposition surfaced 2026-05-01.
**Predecessor:** Plan 01 (Scaffolding & CI), already merged to `main`.

**Goal:** Land the persistence layer for DIYDDNS — a SQLite-backed storage module under `internal/store` with goose migrations, the full v1 schema (design spec Section 3), and one repository per aggregate with table-driven integration tests against a real on-disk SQLite database.

**Architecture:** `modernc.org/sqlite` (pure-Go, no CGO) opened with WAL + `foreign_keys=ON` + `synchronous=NORMAL` + `busy_timeout=5000`. Schema applied at startup by `pressly/goose` reading SQL files embedded via `//go:embed`. One Go file per aggregate under `internal/store` providing strongly-typed repository functions; no ORM. UUIDv7 ids via `google/uuid` v1.6+. Timestamps stored as `INTEGER` (unix seconds).

**Tech Stack:** Go (≥1.25), `modernc.org/sqlite`, `pressly/goose/v3`, `github.com/google/uuid`, stdlib `database/sql`, stdlib `testing` (table-driven, no third-party assertion libs).

---

> **For Claude:** REQUIRED EXECUTION WORKFLOW (follow in order):
>
> 1. `superpowers:using-git-worktrees` — Isolate work in a dedicated worktree
> 2. `superpowers:subagent-driven-development` — Dispatch a fresh subagent per task
> 3. `superpowers:test-driven-development` — All subagents use TDD
> 4. `superpowers:verification-before-completion` — Verify each task's tests pass
> 5. `superpowers:requesting-code-review` — Code review after each task (built in)
> 6. After all tasks: comprehensive code review on full diff from branch point (automatic)
> 7. `superpowers:finishing-a-development-branch` — Complete the branch
>
> Skills carry their own model and effort settings. Do not override them.

---

## Conventions (carried forward from Plan 01)

- **Go module path:** `github.com/jacaudi/diyddns`.
- **Go minimum version in `go.mod`:** `1.25`.
- **Commit messages:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `build:`, `ci:`). Plan 02's commits will mostly be `feat:` (new persistence) and `test:` (new test suites).
- **Repo conventions:** MIT licensed, no Dependabot, CI uses `jacaudi/github-actions@v0.20.1` and `jacaudi/renovate-config` presets — already wired by Plan 01. Plan 02 adds no `.github/` files.
- **Error wrapping:** `fmt.Errorf("...: %w", err)`. Enforced by `errorlint`.
- **Tests:** stdlib `testing` only, table-driven where inputs are enumerable, no `testify`. Helpers via `t.Helper()`.

---

## File Structure (end state of Plan 02)

```
diyddns/
├── go.mod                          (modified — adds 3 deps)
├── go.sum                          (new — populated by go mod tidy)
├── Taskfile.yml                    (modified — adds migrate:new, db:backup)
├── migrations/
│   ├── 00001_initial_schema.sql    (new)
│   └── embed.go                    (new — go:embed of *.sql)
├── internal/store/
│   ├── store.go                    (new — Store type, Open, Close)
│   ├── pragma.go                   (new — connection setup)
│   ├── migrate.go                  (new — goose runner)
│   ├── id.go                       (new — UUIDv7 wrapper)
│   ├── time.go                     (new — unix seconds helper)
│   ├── errors.go                   (new — sentinel errors)
│   ├── users.go                    (new)
│   ├── users_test.go               (new)
│   ├── sessions.go                 (new)
│   ├── sessions_test.go            (new)
│   ├── devices.go                  (new)
│   ├── devices_test.go             (new)
│   ├── ip_history.go               (new)
│   ├── ip_history_test.go          (new)
│   ├── enrollment_codes.go         (new)
│   ├── enrollment_codes_test.go    (new)
│   ├── replay_nonces.go            (new)
│   ├── replay_nonces_test.go       (new)
│   ├── audit_log.go                (new)
│   ├── audit_log_test.go           (new)
│   ├── bootstrap.go                (new)
│   ├── bootstrap_test.go           (new)
│   └── testdb_test.go              (new — shared test helper)
```

The `.gitkeep` from Plan 01 in `internal/store/` is removed in Task 5 (no harm in leaving it, but it's now meaningless because Go files exist).

---

## Conventions for repository code

Every repository file follows the same shape:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// <Aggregate> is the persisted shape (matches schema columns 1:1; null-safe).
type <Aggregate> struct { ... }

// <Aggregate>Repo is the repository for the <aggregate> table.
type <Aggregate>Repo struct{ db *sql.DB }

// Newly-public methods accept context.Context as the first arg, return
// (T, error) or error. Errors are wrapped with %w. Sentinel errors live in
// errors.go (e.g., ErrNotFound, ErrConflict).

func (r *<Aggregate>Repo) Method(ctx context.Context, ...) (..., error) {
	...
}
```

The `Store` type holds `*sql.DB` and exposes `Users()`, `Sessions()`, etc. returning the typed repos. Tests use `newTestStore(t)` which:
1. Creates a temp DB file in `t.TempDir()`.
2. Opens with the same pragmas as production.
3. Runs all migrations.
4. Returns `*Store` and a cleanup-via-`t.Cleanup()`.

Sentinel errors (in `errors.go`):
- `ErrNotFound` — row not found.
- `ErrConflict` — uniqueness violation (returned by Create when a UNIQUE constraint fires).

Repo methods translate `sql.ErrNoRows` → `ErrNotFound` and SQLite UNIQUE-constraint errors → `ErrConflict` so callers get a stable error API.

---

## Tasks

### Task 1: Add storage dependencies

**Files:**
- Modify: `go.mod`
- Create: `go.sum`

**Steps:**

- [ ] **Step 1: Add dependencies via `go get`**

```bash
go get modernc.org/sqlite@latest
go get github.com/pressly/goose/v3@latest
go get github.com/google/uuid@latest
```

- [ ] **Step 2: Verify**

```bash
go mod tidy
go build ./...
```
Expected: both exit 0; `go.sum` is created and populated.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add storage dependencies (sqlite, goose, uuid)"
```

---

### Task 2: Create the initial migration SQL

**Files:**
- Create: `migrations/00001_initial_schema.sql`

**Steps:**

- [ ] **Step 1: Write the migration**

The migration carries the full v1 schema from design spec Section 3, exactly as documented there (users, sessions, devices, ip_history, enrollment_codes, replay_nonces, audit_log, bootstrap, plus their indexes). Use goose's `-- +goose Up` / `-- +goose Down` directives. The `Down` half drops every table created by `Up`, in reverse foreign-key dependency order.

Create `migrations/00001_initial_schema.sql` with this exact content (copy verbatim — the schema is canonical):

```sql
-- +goose Up
-- +goose StatementBegin

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    role            TEXT NOT NULL CHECK (role IN ('admin','user')),
    oidc_provider   TEXT,
    oidc_subject    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (oidc_provider, oidc_subject)
);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    current_ipv4    TEXT,
    current_ipv6    TEXT,
    hostname        TEXT,
    os              TEXT,
    client_version  TEXT,
    last_seen_at    INTEGER,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (user_id, label)
);
CREATE INDEX devices_user ON devices(user_id);

CREATE TABLE ip_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ipv4            TEXT,
    ipv6            TEXT,
    observed_at     INTEGER NOT NULL,
    client_version  TEXT
);
CREATE INDEX ip_history_device_observed ON ip_history(device_id, observed_at DESC);

CREATE TABLE enrollment_codes (
    code            TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    device_id       TEXT REFERENCES devices(id)
);
CREATE INDEX enrollment_codes_expires ON enrollment_codes(expires_at);

CREATE TABLE replay_nonces (
    signature       TEXT PRIMARY KEY,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX replay_nonces_expires ON replay_nonces(expires_at);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id   TEXT,
    event_type      TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    details_json    TEXT,
    ip              TEXT,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL
);
CREATE INDEX audit_log_created ON audit_log(created_at DESC);
CREATE INDEX audit_log_actor ON audit_log(actor_user_id, created_at DESC);

CREATE TABLE bootstrap (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash      TEXT,
    created_at      INTEGER NOT NULL,
    consumed_at     INTEGER
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS bootstrap;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS replay_nonces;
DROP TABLE IF EXISTS enrollment_codes;
DROP TABLE IF EXISTS ip_history;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- +goose StatementEnd
```

- [ ] **Step 2: Commit**

```bash
git add migrations/00001_initial_schema.sql
git commit -m "feat(store): add initial schema migration"
```

---

### Task 3: Embed the migrations directory

**Files:**
- Create: `migrations/embed.go`

**Steps:**

- [ ] **Step 1: Write the embed file**

Create `migrations/embed.go` with this exact content:

```go
// Package migrations exposes the embedded SQL migration files as an
// io/fs.FS for goose to consume at runtime.
package migrations

import "embed"

// FS contains every *.sql migration in this directory, applied by
// internal/store at server startup.
//
//go:embed *.sql
var FS embed.FS
```

- [ ] **Step 2: Verify build**

```bash
go build ./migrations/...
```
Expected: exits 0, no output (no main package, just the embed.FS variable).

- [ ] **Step 3: Commit**

```bash
git add migrations/embed.go
git commit -m "feat(store): embed migrations via go:embed"
```

---

### Task 4: Sentinel errors

**Files:**
- Create: `internal/store/errors.go`

**Steps:**

- [ ] **Step 1: Write the file**

```go
// Package store implements DIYDDNS's persistence layer over SQLite. Every
// aggregate has its own *.go file plus an integration test against a real
// on-disk database created by newTestStore in testdb_test.go.
package store

import "errors"

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write would violate a UNIQUE constraint
// (e.g., duplicate email, duplicate (user_id, label) on devices).
var ErrConflict = errors.New("store: conflict")
```

- [ ] **Step 2: Commit**

```bash
git add internal/store/errors.go
git commit -m "feat(store): add ErrNotFound and ErrConflict sentinel errors"
```

---

### Task 5: Time helper

**Files:**
- Create: `internal/store/time.go`
- Create: `internal/store/time_test.go`
- Delete: `internal/store/.gitkeep` (now redundant)

**Steps:**

- [ ] **Step 1: Write the failing test**

```go
package store

import (
	"testing"
	"time"
)

func TestNowUnixIsCurrentSecond(t *testing.T) {
	before := time.Now().Unix()
	got := NowUnix()
	after := time.Now().Unix()
	if got < before || got > after {
		t.Fatalf("NowUnix()=%d not within [%d,%d]", got, before, after)
	}
}

func TestUnixToTime(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	got := UnixToTime(now.Unix())
	if !got.Equal(now) {
		t.Fatalf("UnixToTime round-trip: got %v, want %v", got, now)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/store/...
```
Expected: FAIL with `undefined: NowUnix` and `undefined: UnixToTime`.

- [ ] **Step 3: Write minimal implementation**

```go
package store

import "time"

// NowUnix returns the current time as unix seconds (UTC). All persisted
// timestamps in this package are unix seconds.
func NowUnix() int64 {
	return time.Now().Unix()
}

// UnixToTime converts a stored unix-seconds value to a UTC time.Time. The
// inverse of NowUnix() / time.Now().Unix() round-trips at second precision.
func UnixToTime(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/store/... -v
```
Expected: PASS for both tests.

- [ ] **Step 5: Remove obsolete .gitkeep**

```bash
git rm internal/store/.gitkeep
```

- [ ] **Step 6: Commit**

```bash
git add internal/store/time.go internal/store/time_test.go
git commit -m "feat(store): add NowUnix and UnixToTime helpers"
```

---

### Task 6: ID helper (UUIDv7)

**Files:**
- Create: `internal/store/id.go`
- Create: `internal/store/id_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

```go
package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewIDIsValidUUIDv7(t *testing.T) {
	for i := 0; i < 32; i++ {
		got := NewID()
		parsed, err := uuid.Parse(got)
		if err != nil {
			t.Fatalf("NewID()=%q is not a valid UUID: %v", got, err)
		}
		if parsed.Version() != 7 {
			t.Fatalf("NewID()=%q is UUIDv%d, want v7", got, parsed.Version())
		}
	}
}

func TestNewIDsAreDistinct(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/store/...
```
Expected: FAIL with `undefined: NewID`.

- [ ] **Step 3: Write minimal implementation**

```go
package store

import "github.com/google/uuid"

// NewID returns a fresh UUIDv7 as a lowercase hex-with-dashes string.
// UUIDv7 sorts lexicographically by creation time, which makes it a good
// fit for primary keys that are also natural ordering keys.
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// uuid.NewV7 only fails on extreme clock issues; if it does we want
		// to know immediately rather than persisting a zero UUID.
		panic(fmt.Sprintf("store.NewID: uuid.NewV7 failed: %v", err))
	}
	return id.String()
}
```

Add `import "fmt"` at the top alongside `"github.com/google/uuid"`.

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/store/... -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/id.go internal/store/id_test.go
git commit -m "feat(store): add NewID UUIDv7 generator"
```

---

### Task 7: Connection pragmas

**Files:**
- Create: `internal/store/pragma.go`

**Steps:**

- [ ] **Step 1: Write the file**

The pragmas defined here are applied to every connection opened by the database/sql pool. We use a `RegisterConnectionInitFunc` hook on the sqlite driver so each new pool connection runs the setup automatically.

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// applyPragmas runs the per-connection setup that the SQLite driver
// requires for the project's runtime guarantees:
//   - WAL mode (concurrent reads with single writer; safe for the
//     typical small-scale deployment described in the design spec).
//   - foreign_keys=ON (referential integrity is not on by default in SQLite).
//   - synchronous=NORMAL (a fsync compromise that is safe under WAL).
//   - busy_timeout=5000 (block up to 5 s when the writer is locked
//     instead of returning SQLITE_BUSY immediately).
func applyPragmas(ctx context.Context, conn *sql.Conn) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA busy_timeout = 5000",
	}
	for _, p := range pragmas {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("store: %s: %w", p, err)
		}
	}
	return nil
}
```

- [ ] **Step 2: Build**

```bash
go build ./internal/store/...
```
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/store/pragma.go
git commit -m "feat(store): apply WAL/FK/sync/busy_timeout pragmas per connection"
```

---

### Task 8: Migration runner

**Files:**
- Create: `internal/store/migrate.go`

**Steps:**

- [ ] **Step 1: Write the file**

```go
package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jacaudi/diyddns/migrations"
	"github.com/pressly/goose/v3"
)

// Migrate applies every embedded SQL migration to db, in version order. It
// is idempotent: re-running on an already-current schema is a no-op. Goose
// records its version in a goose_db_version table created on first run.
func Migrate(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("store: goose set dialect: %w", err)
	}
	// "." tells goose to read from the registered base FS (embed.FS).
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("store: goose up: %w", err)
	}
	return nil
}
```

- [ ] **Step 2: Build**

```bash
go build ./internal/store/...
```
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/store/migrate.go
git commit -m "feat(store): add goose-driven Migrate function"
```

---

### Task 9: Store type and Open

**Files:**
- Create: `internal/store/store.go`

**Steps:**

- [ ] **Step 1: Write the file**

The Store type holds the `*sql.DB` and exposes typed accessors for each repository. Open opens the file, applies pragmas via a connection init hook on the modernc driver, and runs migrations. Repository accessors are added in subsequent tasks (the file ships with no accessors at this point; each repo Task adds its accessor method).

```go
package store

import (
	"context"
	"database/sql"
	"fmt"

	"modernc.org/sqlite"
)

// Store is DIYDDNS's persistence handle. Open returns a fully migrated,
// PRAGMA-configured Store ready for repository use. Close releases the
// underlying *sql.DB.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path, applies the runtime pragmas to
// every connection, and runs all embedded migrations. path may be ":memory:"
// for in-process use.
func Open(ctx context.Context, path string) (*Store, error) {
	registerConnInit()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: sql.Open: %w", err)
	}

	// Single-writer SQLite is happiest with one writer connection.
	// Reads happen on the same pool; raise to your taste in the future.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// DB returns the underlying *sql.DB. Prefer typed repository accessors
// (Users, Sessions, etc.) over raw DB access; this exists for diagnostics
// and tests.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// registerConnInit installs a one-time connection hook on the modernc
// SQLite driver that runs applyPragmas for every new connection in the
// pool. It is safe to call multiple times.
var connInitRegistered bool

func registerConnInit() {
	if connInitRegistered {
		return
	}
	connInitRegistered = true
	sqlite.RegisterConnectionHook(func(_ sqlite.ExecQuerierContext, _ string) error {
		// modernc's hook signature does not give us a *sql.Conn; pragmas
		// are instead asserted on first use via assertPragmas (see
		// store.go's Open path), but registering this hook makes the
		// driver discover the hook surface so we can also rely on
		// applyPragmas at the *sql.Conn level via Store helpers.
		return nil
	})
}
```

> **Implementer note:** `modernc.org/sqlite` does not expose a `*sql.Conn` to its hook in v1.38+. The simplest portable path is to apply pragmas in `Open` after `sql.Open` by acquiring a `*sql.Conn` via `db.Conn(ctx)` and running `applyPragmas` against it once before migrations. Replace the `registerConnInit` indirection with an inline call to `applyPragmas` if that is cleaner — the goal is "every connection in the pool runs WAL/FK/sync/busy". With `SetMaxOpenConns(1)` a single application is sufficient.

If you choose the simpler "apply once" path, the file becomes:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: sql.Open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: db.Conn: %w", err)
	}
	if err := applyPragmas(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}
	if err := conn.Close(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: conn close: %w", err)
	}

	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
```

Use this simpler form unless you have a reason to chase the connection hook.

- [ ] **Step 2: Build**

```bash
go build ./internal/store/...
```
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add internal/store/store.go
git commit -m "feat(store): add Store type with Open/Close and migrate-on-open"
```

---

### Task 10: Test harness — `newTestStore`

**Files:**
- Create: `internal/store/testdb_test.go`

**Steps:**

- [ ] **Step 1: Write the helper**

```go
package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore returns a Store backed by a fresh on-disk SQLite database in
// t.TempDir(). Migrations have been applied. The returned context has a
// reasonable timeout. The DB file is automatically cleaned up by t.TempDir.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.db")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s, ctx
}

// TestNewTestStoreSmokesMigrations is a sanity test: opening newTestStore
// must complete without error and produce a queryable DB whose schema
// includes the expected tables.
func TestNewTestStoreSmokesMigrations(t *testing.T) {
	s, ctx := newTestStore(t)

	tables := []string{
		"users", "sessions", "devices", "ip_history",
		"enrollment_codes", "replay_nonces", "audit_log", "bootstrap",
	}
	for _, tbl := range tables {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&got)
		if err != nil {
			t.Errorf("table %q missing after migrations: %v", tbl, err)
			continue
		}
		if got != tbl {
			t.Errorf("table lookup: got %q, want %q", got, tbl)
		}
	}
}
```

- [ ] **Step 2: Run test**

```bash
go test ./internal/store/... -run TestNewTestStoreSmokesMigrations -v
```
Expected: PASS — Open succeeds, all 8 tables exist.

- [ ] **Step 3: Commit**

```bash
git add internal/store/testdb_test.go
git commit -m "test(store): add newTestStore helper and migration smoke test"
```

---

### Tasks 11–18: One repository per aggregate

Each task creates an aggregate's repository file and its test file, follows TDD, and produces one commit. The pattern is identical across all eight; differences are in the schema and the per-aggregate methods listed below.

**Per-task TDD pattern:**

1. Write `<aggregate>_test.go` with table-driven tests that exercise every public method on the repo.
2. Run `go test ./internal/store/... -run Test<Aggregate>` — expect FAIL because methods don't exist yet.
3. Write `<aggregate>.go` with the type, the `<Aggregate>Repo` struct, the accessor method on `*Store`, and every method needed to make the tests pass.
4. Run the tests — expect PASS.
5. Run the full lint+test sweep: `task lint && task test`.
6. Commit.

**Each task adds an accessor method to `*Store`** (in `<aggregate>.go`, not in `store.go`):

```go
func (s *Store) <Aggregate>() *<Aggregate>Repo { return &<Aggregate>Repo{db: s.db} }
```

Tests for cross-aggregate cases (e.g., a session referencing a user) create the necessary parent rows via the relevant repository. Don't reach into the DB directly from tests — exercise the public API.

**Error mapping in every Create/Update method:**
- A row that's not found by the operation's primary lookup → `ErrNotFound` wrapped via `%w`.
- A SQLite UNIQUE constraint violation (detect via `errors.As` against `*sqlite.Error` with code `2067` / `19`, or by checking the message string) → `ErrConflict` wrapped via `%w`.

The simplest robust check is via the modernc driver's `*sqlite.Error.Code()` returning a SQLite extended result code; SQLITE_CONSTRAINT_UNIQUE is `2067`. Helper:

```go
import sqlite "modernc.org/sqlite"

func isUniqueViolation(err error) bool {
	var sErr *sqlite.Error
	if errors.As(err, &sErr) {
		return sErr.Code() == 2067 // SQLITE_CONSTRAINT_UNIQUE
	}
	return false
}
```

Add this helper to `errors.go` (or to one of the repo files; just one copy).

---

### Task 11: `users` repository

**Files:**
- Create: `internal/store/users.go`
- Create: `internal/store/users_test.go`

**Type:**

```go
type User struct {
	ID            string
	Email         string
	PasswordHash  string // empty when OIDC-only
	Role          string // "admin" | "user"
	OIDCProvider  string // empty when not linked
	OIDCSubject   string // empty when not linked
	Disabled      bool
	CreatedAt     int64
	UpdatedAt     int64
}
```

**Methods on `*UserRepo`:**

| Method | Purpose | Notes |
|---|---|---|
| `Create(ctx, u User) (User, error)` | Insert; assign new UUIDv7 if `u.ID==""`, set CreatedAt/UpdatedAt to `NowUnix()`. Returns the saved row. | UNIQUE(email) → `ErrConflict` |
| `GetByID(ctx, id string) (User, error)` | Single-row select. | Not found → `ErrNotFound` |
| `GetByEmail(ctx, email string) (User, error)` | Same. | Not found → `ErrNotFound` |
| `GetByOIDC(ctx, provider, subject string) (User, error)` | Single-row select on `(oidc_provider, oidc_subject)`. | Not found → `ErrNotFound` |
| `Update(ctx, u User) error` | UPDATE all mutable columns + `updated_at=NowUnix()` where id=u.ID. Returns `ErrNotFound` if `RowsAffected()==0`. | |
| `SetDisabled(ctx, id string, disabled bool) error` | Targeted update. | |
| `Delete(ctx, id string) error` | Hard delete; cascades to sessions/devices via FK. | Not found → `ErrNotFound` |
| `List(ctx) ([]User, error)` | Ordered by `email ASC`. For admin UI. | |

**Tests cover:** Create+GetByID round-trip, duplicate-email returns ErrConflict, GetByID for missing returns ErrNotFound, OIDC linkage round-trip, Update modifies fields and bumps updated_at, SetDisabled toggles, Delete cascades, List orders by email.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/users.go internal/store/users_test.go
git commit -m "feat(store): add users repository with CRUD and OIDC lookup"
```

---

### Task 12: `sessions` repository

**Files:**
- Create: `internal/store/sessions.go`
- Create: `internal/store/sessions_test.go`

**Type:**

```go
type Session struct {
	ID          string
	UserID      string
	CSRFToken   string
	IP          string
	UserAgent   string
	CreatedAt   int64
	LastSeenAt  int64
	ExpiresAt   int64
}
```

**Methods on `*SessionRepo`:**

| Method | Purpose |
|---|---|
| `Create(ctx, s Session) (Session, error)` | Insert. Assign UUIDv7 if `s.ID==""`. Set CreatedAt/LastSeenAt to `NowUnix()`. |
| `GetByID(ctx, id string) (Session, error)` | Single row. Not found → `ErrNotFound`. |
| `Touch(ctx, id string, expiresAt int64) error` | Update `last_seen_at = NowUnix()`, `expires_at = expiresAt`. Sliding window. |
| `Delete(ctx, id string) error` | Hard delete. |
| `DeleteByUser(ctx, userID string) (int, error)` | Hard delete; returns rows affected. Used on logout-all and user disable. |
| `PruneExpired(ctx, now int64) (int, error)` | DELETE WHERE `expires_at < now`. Returns rows affected. |

**Tests cover:** Create round-trip, Touch updates last_seen_at and expires_at, Delete hard-removes, DeleteByUser purges only that user's sessions, PruneExpired removes expired and leaves fresh, FK cascade on user delete.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/sessions.go internal/store/sessions_test.go
git commit -m "feat(store): add sessions repository with sliding TTL and prune"
```

---

### Task 13: `devices` repository

**Files:**
- Create: `internal/store/devices.go`
- Create: `internal/store/devices_test.go`

**Type:**

```go
type Device struct {
	ID            string
	UserID        string
	Label         string
	SecretHash    string
	CurrentIPv4   string
	CurrentIPv6   string
	Hostname      string
	OS            string
	ClientVersion string
	LastSeenAt    int64 // 0 if never reported
	Disabled      bool
	CreatedAt     int64
	UpdatedAt     int64
}
```

**Methods on `*DeviceRepo`:**

| Method | Purpose |
|---|---|
| `Create(ctx, d Device) (Device, error)` | Insert. UUIDv7 if blank ID. Set CreatedAt/UpdatedAt = NowUnix(). UNIQUE(user_id,label) → `ErrConflict`. |
| `GetByID(ctx, id string) (Device, error)` | Single row. |
| `GetByUserAndLabel(ctx, userID, label string) (Device, error)` | Single row. |
| `ListByUser(ctx, userID string) ([]Device, error)` | Ordered by `label ASC`. |
| `ListAll(ctx) ([]Device, error)` | Admin view; ordered by `created_at DESC`. |
| `UpdateIP(ctx, id, ipv4, ipv6, clientVersion, hostname, os string, lastSeenAt int64) error` | Update IP/metadata fields and `last_seen_at`, `updated_at = NowUnix()`. Used by checkin. |
| `Rename(ctx, id, newLabel string) error` | UPDATE label. UNIQUE(user_id,label) → `ErrConflict`. |
| `RotateSecret(ctx, id, newSecretHash string) error` | UPDATE secret_hash, updated_at. |
| `SetDisabled(ctx, id string, disabled bool) error` | Targeted update. |
| `Delete(ctx, id string) error` | Hard delete; cascades ip_history rows. |

**Tests cover:** Create+GetByID, duplicate (user_id,label) → ErrConflict, ListByUser ordering, UpdateIP sets fields and updates last_seen_at, Rename handles conflict, RotateSecret changes hash, Delete cascades to ip_history, FK cascade on user delete.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/devices.go internal/store/devices_test.go
git commit -m "feat(store): add devices repository with IP/metadata update and rotation"
```

---

### Task 14: `ip_history` repository

**Files:**
- Create: `internal/store/ip_history.go`
- Create: `internal/store/ip_history_test.go`

**Type:**

```go
type IPHistory struct {
	ID            int64
	DeviceID      string
	IPv4          string
	IPv6          string
	ObservedAt    int64
	ClientVersion string
}

// HistoryPage is a cursor-paginated slice.
type HistoryPage struct {
	Rows       []IPHistory
	NextCursor string // empty if no more rows
}
```

**Methods on `*IPHistoryRepo`:**

| Method | Purpose |
|---|---|
| `Append(ctx, h IPHistory) (IPHistory, error)` | Insert. Set ObservedAt = NowUnix() if zero. Returns the row with assigned ID. |
| `Latest(ctx, deviceID string) (IPHistory, error)` | Most-recent row for device. Not found → `ErrNotFound`. |
| `Page(ctx, deviceID, cursor string, limit int) (HistoryPage, error)` | Cursor pagination keyed on `(observed_at DESC, id DESC)`. limit clamped to [1, 500]; default 50. |
| `Prune(ctx, deviceID string, olderThan int64, perDeviceMax int) (int, error)` | Per design: delete rows older than `olderThan` OR beyond `perDeviceMax` newest, **except never delete the most-recent row per device** (always_keep_latest). Returns rows deleted. |

**Cursor format:** opaque base64 of `"{observed_at}:{id}"`. Decode to `(observed_at, id)` and use as `(observed_at, id) < (?,?)` predicate for the next page.

**Prune SQL pattern (executed in a single statement):**

```sql
DELETE FROM ip_history
WHERE device_id = ?
  AND id NOT IN (
    SELECT MAX(id) FROM ip_history WHERE device_id = ?
  )
  AND (
    observed_at < ?           -- older than retention cutoff
    OR id < (
      SELECT MIN(id) FROM (
        SELECT id FROM ip_history
        WHERE device_id = ?
        ORDER BY id DESC
        LIMIT ?               -- perDeviceMax newest to keep
      )
    )
  );
```

**Tests cover:** Append assigns id, Latest returns newest, Page cursor round-trips and reaches end, Prune respects always-keep-latest (a device with one row never has it deleted regardless of cutoff or cap), Prune by age, Prune by per-device cap, FK cascade on device delete.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/ip_history.go internal/store/ip_history_test.go
git commit -m "feat(store): add ip_history repository with cursor pagination and always-keep-latest prune"
```

---

### Task 15: `enrollment_codes` repository

**Files:**
- Create: `internal/store/enrollment_codes.go`
- Create: `internal/store/enrollment_codes_test.go`

**Type:**

```go
type EnrollmentCode struct {
	Code      string
	UserID    string
	Label     string
	ExpiresAt int64
	UsedAt    int64  // 0 if not consumed
	DeviceID  string // empty if not consumed
}
```

**Methods on `*EnrollmentCodeRepo`:**

| Method | Purpose |
|---|---|
| `Create(ctx, c EnrollmentCode) (EnrollmentCode, error)` | Insert. UNIQUE(code) → `ErrConflict`. |
| `Get(ctx, code string) (EnrollmentCode, error)` | Single row. Not found → `ErrNotFound`. |
| `Consume(ctx, code, deviceID string, now int64) (EnrollmentCode, error)` | Atomic: check expires_at > now AND used_at IS NULL; UPDATE used_at=now, device_id=deviceID. Returns the post-update row. If already used or expired → `ErrNotFound`. |
| `PruneExpired(ctx, now int64) (int, error)` | DELETE WHERE expires_at < now AND used_at IS NULL. (Consumed codes stay for audit until the user is deleted.) |

**Tests cover:** Create + Get round-trip, duplicate code → ErrConflict, Consume succeeds once and returns the device, second Consume → ErrNotFound, expired Consume → ErrNotFound, PruneExpired removes only unused expired.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/enrollment_codes.go internal/store/enrollment_codes_test.go
git commit -m "feat(store): add enrollment_codes repository with single-use Consume"
```

---

### Task 16: `replay_nonces` repository

**Files:**
- Create: `internal/store/replay_nonces.go`
- Create: `internal/store/replay_nonces_test.go`

**Type:**

```go
type ReplayNonce struct {
	Signature string
	ExpiresAt int64
}
```

**Methods on `*ReplayNonceRepo`:**

| Method | Purpose |
|---|---|
| `Insert(ctx, signature string, expiresAt int64) error` | INSERT; UNIQUE(signature) → `ErrConflict` (signal of replay). |
| `Exists(ctx, signature string) (bool, error)` | Read-only check (mostly for tests; production uses Insert's conflict signal). |
| `PruneExpired(ctx, now int64) (int, error)` | DELETE WHERE expires_at < now. |

**Tests cover:** Insert round-trip, second Insert with same signature returns ErrConflict, Exists matches Insert state, PruneExpired removes expired.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/replay_nonces.go internal/store/replay_nonces_test.go
git commit -m "feat(store): add replay_nonces repository for HMAC replay defense"
```

---

### Task 17: `audit_log` repository

**Files:**
- Create: `internal/store/audit_log.go`
- Create: `internal/store/audit_log_test.go`

**Type:**

```go
type AuditEntry struct {
	ID           int64
	ActorUserID  string // empty for system events
	EventType    string
	TargetType   string
	TargetID     string
	DetailsJSON  string
	IP           string
	UserAgent    string
	CreatedAt    int64
}

// AuditFilter narrows the result set for ListPaginated.
type AuditFilter struct {
	ActorUserID  string // empty = no filter
	EventType    string // empty = no filter
	Since        int64  // 0 = no lower bound
	Until        int64  // 0 = no upper bound
}

type AuditPage struct {
	Rows       []AuditEntry
	NextCursor string
}
```

**Methods on `*AuditLogRepo`:**

| Method | Purpose |
|---|---|
| `Append(ctx, e AuditEntry) (AuditEntry, error)` | Insert. CreatedAt = NowUnix() if zero. Returns row with assigned ID. |
| `ListPaginated(ctx, f AuditFilter, cursor string, limit int) (AuditPage, error)` | Cursor pagination on `(created_at DESC, id DESC)`; limit [1, 500] default 100; filter applied via WHERE. |
| `Prune(ctx, olderThan int64) (int, error)` | DELETE WHERE created_at < olderThan. Returns rows deleted. |

**Tests cover:** Append round-trip, ListPaginated cursor walks, AuditFilter narrows correctly, Prune removes by age.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/audit_log.go internal/store/audit_log_test.go
git commit -m "feat(store): add audit_log repository with filter and prune"
```

---

### Task 18: `bootstrap` repository

**Files:**
- Create: `internal/store/bootstrap.go`
- Create: `internal/store/bootstrap_test.go`

**Type:**

```go
type BootstrapState struct {
	TokenHash   string // empty after consumed
	CreatedAt   int64
	ConsumedAt  int64  // 0 if not consumed
}
```

**Methods on `*BootstrapRepo`:**

| Method | Purpose |
|---|---|
| `Get(ctx) (BootstrapState, error)` | SELECT ... FROM bootstrap WHERE id=1. Returns `ErrNotFound` if no row exists yet. |
| `SetTokenHash(ctx, tokenHash string) error` | INSERT OR REPLACE INTO bootstrap (id, token_hash, created_at, consumed_at) VALUES (1, ?, NowUnix(), NULL). |
| `Consume(ctx) error` | UPDATE bootstrap SET token_hash=NULL, consumed_at=NowUnix() WHERE id=1 AND consumed_at IS NULL. RowsAffected==0 → `ErrNotFound` (already consumed or never set). |

**Tests cover:** Get on empty returns ErrNotFound, SetTokenHash round-trip, Consume succeeds once and returns ErrNotFound on second call, Get after Consume shows token_hash empty and consumed_at non-zero.

- [ ] Implement per the TDD pattern, then commit:

```bash
git add internal/store/bootstrap.go internal/store/bootstrap_test.go
git commit -m "feat(store): add bootstrap repository for one-time admin claim"
```

---

### Task 19: Update Taskfile

**Files:**
- Modify: `Taskfile.yml`

**Steps:**

- [ ] **Step 1: Add migrate:new and db:backup targets**

Edit `Taskfile.yml`'s `tasks:` block; append these two targets after `clean`:

```yaml
  migrate:new:
    desc: Create a new SQL migration in migrations/ (Usage: task migrate:new -- <name>)
    cmds:
      - go run github.com/pressly/goose/v3/cmd/goose@latest -dir migrations create {{.CLI_ARGS}} sql

  db:backup:
    desc: Safely back up the SQLite database file (Usage: task db:backup -- <src.db> <out.db>)
    cmds:
      - >
        go run github.com/pressly/goose/v3/cmd/goose@latest -h >/dev/null 2>&1 || true ;
        echo "Use the SQLite VACUUM INTO API:" ;
        echo "  sqlite3 {{.CLI_ARGS}}" ;
        echo "or, programmatically, .DB().ExecContext(ctx, \"VACUUM INTO ?\", outPath)"
```

> Note: a polished `db:backup` lands when the server is wired (Plan 03+). The placeholder above documents the intended interface.

- [ ] **Step 2: Smoke**

```bash
task --list
task lint
```
Expected: `migrate:new` and `db:backup` appear in the list; lint passes.

- [ ] **Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "build: add migrate:new and db:backup task targets"
```

---

### Task 20: Final sweep

**Files:** none

**Steps:**

- [ ] **Step 1: Run the full toolchain**

```bash
task tidy
task fmt
task lint
task test
task build
```
Every step must exit 0. The new test packages should account for ≥80% coverage on `internal/store/...` (visible in CI later; not strictly enforced here yet).

- [ ] **Step 2: Self-check coverage locally**

```bash
go test ./internal/store/... -cover
```
Expected: at least one `coverage: <N>% of statements` line per package, with `<N>` ≥ 80 for `internal/store`.

- [ ] **Step 3: Commit any fmt drift**

```bash
git status -s
```
If anything changed:
```bash
git add -u
git commit -m "style: gofmt + goimports"
```

- [ ] **Step 4: Final log review**

```bash
git log --oneline | head -25
```
Expect ~20 new commits since the branch point, all Conventional Commits.

---

## Self-Review Checklist (run inline)

After all tasks, verify:

1. **Spec coverage:** Every table in design Section 3 has a migration, type, and repo. Every method documented in Tasks 11–18 returns the documented errors.
2. **Sentinel errors:** `ErrNotFound` and `ErrConflict` are used consistently — never returned by some methods and a raw `sql.ErrNoRows` by others.
3. **TDD:** Each repo file has its tests written first; tests cover happy path, error paths (`ErrNotFound`, `ErrConflict`), and FK cascades where applicable.
4. **Pragmas:** `applyPragmas` is exercised by `newTestStore` (verifiable by writing a test that asserts `journal_mode=wal`, `foreign_keys=1`).
5. **No CGO:** `go env CGO_ENABLED=0 go build ./...` still succeeds (modernc.org/sqlite is pure-Go).
6. **always_keep_latest:** the boundary case "device with one history row, retention says delete it" is explicitly tested in `ip_history_test.go` and passes.

---

## Plan 02 Acceptance Criteria

When this plan is complete:

- `task tidy && task fmt && task lint && task test && task build` exits 0 on a clean checkout.
- `go test ./internal/store/... -race -cover` passes with ≥80% coverage.
- `task migrate:new -- foo` creates a new SQL skeleton file under `migrations/`.
- A test that opens an in-memory store, inserts a user, a device, three ip_history rows, and runs `Prune` with an aggressive cutoff confirms the latest row per device is preserved.
- `git log --oneline` shows ~20 new commits (one per task plus possibly a fmt cleanup), all Conventional Commits.
- No CGO required: `CGO_ENABLED=0 go build ./...` succeeds.

Plan 03 (Server skeleton & OpenAPI) starts from this foundation: `Open(ctx, path) -> *Store` is the only entrypoint a server needs to start persisting.
