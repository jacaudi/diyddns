# Plan 05 — OIDC Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **For Claude:** REQUIRED EXECUTION WORKFLOW (follow in order):
> 1. `superpowers:using-git-worktrees` — Isolate work in a dedicated worktree
> 2. `superpowers:subagent-driven-development` — Dispatch a fresh subagent per task
> 3. `superpowers:test-driven-development` — All subagents use TDD
> 4. `superpowers:verification-before-completion` — Verify all tests pass per task
> 5. `superpowers:requesting-code-review` — Code review after each task (built in)
> 6. After all tasks: comprehensive code review on full diff from branch point (automatic)
> 7. `superpowers:finishing-a-development-branch` — Complete the branch
>
> Skills carry their own model and effort settings. Do not override them.

**Goal:** Add OpenID Connect to diyddns — a browser authorization-code+PKCE login flow and an agent RFC 8628 device-code enrollment flow — additively on top of the merged Plan 04 auth machinery.

**Architecture:** All go-oidc/oauth2 code lives in a new `internal/oidc` package (the only importer of those server-only deps). An `oidc.Manager` owns provider discovery behind an atomic pointer (degrade-and-retry, or fail-closed when `auth.oidc.required`). A `service.OIDCService` owns the link/signup policy; browser ops (`api/oidc.go`) and agent device-code ops (`api/enroll_oidc.go`) attach to the existing `registerAuthOps`/`registerEnrollOps` seams. Pending device flows persist in a new `oidc_device_flows` SQLite table. No change to HMAC, sessions, CSRF, or the `users`/`sessions`/`devices` schemas.

**Tech Stack:** Go 1.25 (no CGO), `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `github.com/go-jose/go-jose/v4` (test signer only), huma v2.38.0, goose migrations, modernc SQLite, argon2id/AES-256-GCM (Plan 04 `internal/auth`).

**Source of truth:** `docs/designs/2026-07-13-diyddns-05-oidc-design.md`.

## Global Constraints

- **Go 1.25, no CGO.** `GOFLAGS` unchanged; SQLite via modernc.
- **Server-only deps:** `go-oidc`, `oauth2`, `go-jose` must NEVER reach `cmd/diyddns-client`. Enforced by `cmd/diyddns-client/deps_test.go` (Task 15 extends it).
- **All new packages import path prefix:** `github.com/jacaudi/diyddns`.
- **Errors wrapped with `%w`;** package-qualified messages (`"oidc.Manager.Discover: %w"`).
- **Tests:** stdlib `testing`, table-driven where natural, run under `-race`. Integration tests use `httptest` + an in-process mock IdP (Task 5) + a `:memory:` store. No live network in the default suite.
- **Never log** tokens, authorization codes, `device_code`, `state`, PKCE verifier, `client_secret`, or device secrets.
- **Uniform failure:** every OIDC login/enroll rejection returns one generic outcome (browser `302 /login?error=no_account`; agent `401`) and logs the specific reason server-side.
- **Migrations** are goose SQL files in the top-level `migrations/` package (`embed.FS` via `migrations.FS`); next version number is `00002`.
- **Store helpers** already exist: `nullIfEmpty`, `nullIfZero`, `scanString`, `scanInt64`, `isUniqueViolation`, `ErrConflict`, `ErrNotFound`, `NowUnix()`, `NewID()`.

---

## Test Harness Reference (authoritative — use these EXACT names)

Every task's tests MUST use the real helpers below. Do NOT invent `newTestStore` in the wrong package, `buildTestAPIHandler`, `testLogger`, `getJSON`, `postRaw`, or `pollUntilDevice` — they do not exist. Match each package's existing test form:

| Package | Test package form | Store helper | Logger helper | Other |
|---|---|---|---|---|
| `internal/auth` | `package auth` (in-package) | — | — | call `SealWithAAD` unqualified |
| `internal/store` | `package store` (in-package) | `newTestStore(t) (*Store, context.Context)` — **returns store AND ctx** | — | use returned `ctx`; types unqualified (`OIDCDeviceFlow`, `ErrNotFound`) |
| `internal/config` | `package config_test` | — | — | build `*viper.Viper`, call `config.Load` |
| `internal/oidc` | `package oidc_test` | — | define `testLogger(t)` in `manager_test.go` (Task 6) | `oidctest.New(t, ...)` |
| `internal/server/service` | `package service` (in-package) | `openTestStore(t) *store.Store` | `discardLogger() *slog.Logger` | `testPasswordCfg() config.PasswordCfg`; call `NewOIDCService`/`NewBootstrapService` **unqualified** |
| `internal/server` (pruner/server) | `package server` (in-package) | `openTestStore(t) *store.Store` | `discardLog() *slog.Logger` | — |
| `internal/server/api` | `package api_test` | `memStore(t) *store.Store` | `discardLogger() *slog.Logger` | `newFullHarness(t) fullHarness` (assembles ALL ServerDeps → the place to add OIDC wiring); `postJSON(t, url, body) (status int, respBody []byte)` — **3-arg**; `doJSON(t, method, url, body, cookie, csrf) (status, header, respBody)`; `findCookie(header, name) *http.Cookie` |

**Devices repo method is `GetByID(ctx, id)`, not `Get`.**

**API integration tests (Tasks 12–14) extend `newFullHarness`** (`internal/server/api/devices_test.go:33`) — it is the single place `api.Build(ServerDeps{...})` is assembled for tests, and its comment says so. Add the OIDC wiring there (construct an `oidc.Manager` discovered against an `oidctest.IdP`, an `service.OIDCService`, and set `OIDC`/`OIDCMgr`/`HMACKey` on the `ServerDeps` literal, reusing the harness's existing `key := make([]byte, 32){byte(i)}`). Have `newFullHarness` accept an optional `*oidc.Manager` (or add a `newOIDCHarness(t, idp)` sibling that calls the same assembly with OIDC fields set) — do NOT invent a parallel `buildTestAPIHandler`.

---

## Task Dependency Order

```
T1  Bootstrap admin-gate fix (#13)      — independent
T2  AEAD AAD sealing                     — independent
T3  oidc_device_flows store + migration  — independent
T4  config OIDCCfg                        — independent
T5  mock IdP test harness (oidctest)      — adds go-jose
T6  Manager: discovery & state            — adds go-oidc + oauth2; needs T5
T7  Manager: browser helpers              — needs T6
T8  Manager: device helpers               — needs T6
T9  Manager: RetryLoop                     — needs T6
T10 OIDCService.LoginOrLink + BrowserLogin — needs T4
T11 EnrollmentService.EnrollForUser        — independent (refactor)
T12 Browser API ops                        — needs T2,T6,T7,T10
T13 Agent API ops                          — needs T3,T6,T8,T10,T11
T14 Capabilities dynamic                   — needs T6
T15 Server assembly + client-isolation     — needs all
```

---

## Task 1: Bootstrap admin-gate fix (issue #13)

**Files:**
- Modify: `internal/server/service/bootstrap.go:92-99` (`Startup`)
- Test: `internal/server/service/bootstrap_test.go`

**Interfaces:**
- Consumes: `BootstrapService.AdminExists(ctx) (bool, error)` (exists).
- Produces: no signature change — behavior change only.

**Why:** Once OIDC creates `role=user` accounts, `Startup`'s `len(users) > 0` early-return would stop bootstrapping while no admin exists. Gate on admin existence instead, matching `Consume`/`AdminExists`.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/service/bootstrap_test.go` — **in-package `package service`**, using the package's real helpers `openTestStore(t)`, `testPasswordCfg()`, `discardLogger()`, and unqualified `NewBootstrapService`/`NewAuditWriter`:

```go
func TestStartup_BootstrapsWhenUsersExistButNoAdmin(t *testing.T) {
	st := openTestStore(t) // service package's helper: migrated :memory: store
	// Seed a non-admin user (simulating an OIDC signup) so len(users) > 0
	// but AdminExists == false.
	if _, err := st.Users().Create(t.Context(), store.User{
		Email: "oidc-user@example.com", Role: "user", OIDCProvider: "https://idp", OIDCSubject: "sub-1",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	var emitted string
	svc := NewBootstrapService(st, config.BootstrapCfg{}, testPasswordCfg(), discardLogger(), NewAuditWriter(st), func(tok string) { emitted = tok })

	if err := svc.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if emitted == "" {
		t.Fatal("expected a bootstrap token to be emitted when users exist but no admin does; got none")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/service/ -run TestStartup_BootstrapsWhenUsersExistButNoAdmin -v`
Expected: FAIL — no token emitted, because the current `len(users) > 0` gate returns early.

- [ ] **Step 3: Change the gate**

In `internal/server/service/bootstrap.go`, replace the opening of `Startup`:

```go
func (s *BootstrapService) Startup(ctx context.Context) error {
	hasAdmin, err := s.AdminExists(ctx)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if hasAdmin {
		return nil
	}
	// ... unchanged: env path, pending-token check, mint+emit token ...
```

Remove the old `users, err := s.st.Users().List(ctx)` / `if len(users) > 0` block. The rest of `Startup` (env path, `Bootstrap().Get` pending-token check, token mint) is unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/service/ -race`
Expected: PASS (new test + all existing bootstrap tests).

- [ ] **Step 5: Commit**

```bash
git add internal/server/service/bootstrap.go internal/server/service/bootstrap_test.go
git commit -m "fix(service): gate bootstrap Startup on AdminExists, not any-user (#13)"
```

---

## Task 2: AEAD AAD sealing

**Files:**
- Modify: `internal/auth/secret.go` (add two functions)
- Test: `internal/auth/secret_test.go`

**Interfaces:**
- Produces:
  - `func SealWithAAD(key, plaintext, aad []byte) (string, error)`
  - `func OpenWithAAD(key []byte, sealed string, aad []byte) ([]byte, error)`

**Why:** The browser flow-state cookie is sealed under the same AES-256-GCM master key as device secrets. GCM AAD domain-separates the two contexts so a blob from one never opens in the other.

- [ ] **Step 1: Write the failing test**

Add to `internal/auth/secret_test.go`:

```go
func TestSealWithAAD_RoundTripAndDomainSeparation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key { key[i] = byte(i) }
	pt := []byte(`{"state":"abc","nonce":"xyz"}`)
	aad := []byte("diyddns/oidc-flow-v1")

	sealed, err := auth.SealWithAAD(key, pt, aad)
	if err != nil { t.Fatalf("SealWithAAD: %v", err) }

	got, err := auth.OpenWithAAD(key, sealed, aad)
	if err != nil { t.Fatalf("OpenWithAAD: %v", err) }
	if !bytes.Equal(got, pt) { t.Fatalf("round-trip mismatch: %q != %q", got, pt) }

	// Wrong AAD must fail (domain separation).
	if _, err := auth.OpenWithAAD(key, sealed, []byte("other-context")); err == nil {
		t.Fatal("OpenWithAAD with wrong AAD must fail, but succeeded")
	}
	// A blob sealed WITH aad must not open via the no-AAD SealSecret path.
	if _, err := auth.OpenSecret(key, sealed); err == nil {
		t.Fatal("OpenSecret must reject an AAD-sealed blob, but succeeded")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestSealWithAAD -v`
Expected: FAIL — `undefined: auth.SealWithAAD`.

- [ ] **Step 3: Implement the two functions**

Add to `internal/auth/secret.go` (mirrors `SealSecret`/`OpenSecret` but passes `aad` as GCM additional data; existing functions unchanged):

```go
// SealWithAAD AES-256-GCM-encrypts plaintext under key (32 bytes) binding aad
// as additional authenticated data, and returns base64(nonce || ciphertext).
// aad is not encrypted but is authenticated: OpenWithAAD must be given the same
// aad or authentication fails. Used to domain-separate sealed contexts that
// share the master key (e.g. the OIDC flow cookie vs. device secrets).
func SealWithAAD(key, plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return "", fmt.Errorf("auth.SealWithAAD: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// OpenWithAAD reverses SealWithAAD. It returns an error if the key is wrong,
// the payload is malformed, aad differs, or the GCM tag fails to authenticate.
func OpenWithAAD(key []byte, sealed string, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenWithAAD: decode: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("auth.OpenWithAAD: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenWithAAD: %w", err)
	}
	return pt, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/secret.go internal/auth/secret_test.go
git commit -m "feat(auth): add AAD-bound AES-256-GCM seal/open for domain separation"
```

---

## Task 3: `oidc_device_flows` store + migration

**Files:**
- Create: `migrations/00002_oidc_device_flows.sql`
- Create: `internal/store/oidc_device_flows.go`
- Test: `internal/store/oidc_device_flows_test.go`

**Interfaces:**
- Produces (`store` package):
  - `type OIDCDeviceFlow struct { FlowID, DeviceCode string; Interval, ExpiresAt, LastPolledAt, CreatedAt int64 }`
  - `func (s *Store) OIDCDeviceFlows() *OIDCDeviceFlowRepo`
  - `func (r *OIDCDeviceFlowRepo) Create(ctx, f OIDCDeviceFlow) (OIDCDeviceFlow, error)`
  - `func (r *OIDCDeviceFlowRepo) Get(ctx, flowID string) (OIDCDeviceFlow, error)` — `ErrNotFound` if absent
  - `func (r *OIDCDeviceFlowRepo) TryPoll(ctx, flowID string, now int64) (OIDCDeviceFlow, bool, error)` — atomically stamps `last_polled_at=now` iff `now - last_polled_at >= interval` AND not expired; returns `(row, true, nil)` when allowed, `(row, false, nil)` when paced/slow_down, `ErrNotFound` when the flow is gone/expired.
  - `func (r *OIDCDeviceFlowRepo) BumpInterval(ctx, flowID string, delta int64) error`
  - `func (r *OIDCDeviceFlowRepo) Delete(ctx, flowID string) error`
  - `func (r *OIDCDeviceFlowRepo) PruneExpired(ctx, now int64) (int, error)`

- [ ] **Step 1: Write the migration**

Create `migrations/00002_oidc_device_flows.sql`:

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE oidc_device_flows (
    flow_id        TEXT PRIMARY KEY,
    device_code    TEXT NOT NULL,
    interval       INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_polled_at INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL
);
CREATE INDEX oidc_device_flows_expires ON oidc_device_flows(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_device_flows;
-- +goose StatementEnd
```

- [ ] **Step 2: Write the failing test**

Create `internal/store/oidc_device_flows_test.go` (follow the existing store test setup — an in-package test opening a migrated `:memory:` store; reuse the package's existing `openTestDB`/`newTestStore` helper, whatever it is named):

```go
package store

import (
	"errors"
	"testing"
)

func TestOIDCDeviceFlows_CreateGetTryPoll(t *testing.T) {
	st, ctx := newTestStore(t) // store package helper: returns (*Store, context.Context)
	r := st.OIDCDeviceFlows()

	f := OIDCDeviceFlow{FlowID: "flow-1", DeviceCode: "dc-1", Interval: 5, ExpiresAt: 1000, CreatedAt: 100}
	if _, err := r.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.Get(ctx, "flow-1")
	if err != nil || got.DeviceCode != "dc-1" {
		t.Fatalf("Get: %v, %+v", err, got)
	}

	// First poll at now=200: last_polled_at(0) + interval(5) <= 200 → allowed.
	row, ok, err := r.TryPoll(ctx, "flow-1", 200)
	if err != nil || !ok || row.LastPolledAt != 200 {
		t.Fatalf("TryPoll first: err=%v ok=%v row=%+v", err, ok, row)
	}
	// Immediate second poll at now=201: 201 - 200 < interval(5) → paced.
	_, ok, err = r.TryPoll(ctx, "flow-1", 201)
	if err != nil || ok {
		t.Fatalf("TryPoll paced: err=%v ok=%v (want ok=false)", err, ok)
	}
	// After the interval, now=206: allowed again.
	_, ok, err = r.TryPoll(ctx, "flow-1", 206)
	if err != nil || !ok {
		t.Fatalf("TryPoll after interval: err=%v ok=%v", err, ok)
	}

	// Expired flow → ErrNotFound.
	if _, _, err := r.TryPoll(ctx, "flow-1", 2000); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TryPoll expired: want ErrNotFound, got %v", err)
	}
}

func TestOIDCDeviceFlows_DeleteAndPrune(t *testing.T) {
	st, ctx := newTestStore(t) // store package helper: returns (*Store, context.Context)
	r := st.OIDCDeviceFlows()
	_, _ = r.Create(ctx, OIDCDeviceFlow{FlowID: "a", DeviceCode: "x", Interval: 5, ExpiresAt: 500, CreatedAt: 1})
	_, _ = r.Create(ctx, OIDCDeviceFlow{FlowID: "b", DeviceCode: "y", Interval: 5, ExpiresAt: 5000, CreatedAt: 1})

	n, err := r.PruneExpired(ctx, 1000)
	if err != nil || n != 1 {
		t.Fatalf("PruneExpired: n=%d err=%v (want 1)", n, err)
	}
	if err := r.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: want ErrNotFound, got %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestOIDCDeviceFlows -v`
Expected: FAIL — `st.OIDCDeviceFlows undefined`.

- [ ] **Step 4: Implement the repo**

Create `internal/store/oidc_device_flows.go`:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/ -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add migrations/00002_oidc_device_flows.sql internal/store/oidc_device_flows.go internal/store/oidc_device_flows_test.go
git commit -m "feat(store): oidc_device_flows table + repo with atomic poll pacing"
```

---

## Task 4: config `OIDCCfg`

**Files:**
- Modify: `internal/config/config.go` (add `OIDCCfg`, `Auth.OIDC` field, `keyDefaults`, validation)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.OIDCCfg` (fields per design §7); `config.Auth.OIDC OIDCCfg`.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (reuse the file's existing loader helper — most tests build a `*viper.Viper`, set `database.path`, and call `config.Load`):

```go
func TestLoad_OIDCValidation(t *testing.T) {
	base := func(v *viper.Viper) {
		v.Set("database.path", ":memory:")
		v.Set("auth.hmac.secret_key", "") // not required unless server starts
	}

	// enabled but missing issuer → error
	t.Run("missing issuer", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		if _, err := config.Load(v, ""); err == nil {
			t.Fatal("expected error for enabled OIDC without issuer")
		}
	})

	// enabled but scopes lack openid → error
	t.Run("missing openid scope", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.issuer", "https://idp.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		v.Set("auth.oidc.scopes", []string{"profile", "email"})
		if _, err := config.Load(v, ""); err == nil {
			t.Fatal("expected error for OIDC scopes missing 'openid'")
		}
	})

	// enabled + valid → defaults present
	t.Run("valid", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.issuer", "https://idp.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		cfg, err := config.Load(v, "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.Auth.OIDC.AutoLinkByEmail || !cfg.Auth.OIDC.AllowOIDCSignup {
			t.Fatalf("expected auto_link/signup defaults true, got %+v", cfg.Auth.OIDC)
		}
		if len(cfg.Auth.OIDC.Scopes) == 0 || cfg.Auth.OIDC.Scopes[0] != "openid" {
			t.Fatalf("expected default scopes with openid first, got %v", cfg.Auth.OIDC.Scopes)
		}
	})

	// disabled → no validation, loads clean
	t.Run("disabled", func(t *testing.T) {
		v := viper.New()
		base(v)
		if _, err := config.Load(v, ""); err != nil {
			t.Fatalf("Load with OIDC disabled: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoad_OIDCValidation -v`
Expected: FAIL — `cfg.Auth.OIDC undefined`.

- [ ] **Step 3: Add the struct, defaults, and validation**

In `internal/config/config.go`:

Add to the `Auth` struct:
```go
type Auth struct {
	Session   SessionCfg
	HMAC      HMACCfg
	Password  PasswordCfg
	Bootstrap BootstrapCfg
	OIDC      OIDCCfg
}
```

Add the struct:
```go
// OIDCCfg holds single-provider OpenID Connect settings. client_secret is
// supplied via DIYDDNS_AUTH_OIDC_CLIENT_SECRET and is never logged.
type OIDCCfg struct {
	Enabled         bool
	Required        bool // fail-closed startup if discovery fails (default false)
	Issuer          string
	ClientID        string   `mapstructure:"client_id"`
	ClientSecret    string   `mapstructure:"client_secret"`
	Scopes          []string
	AutoLinkByEmail bool `mapstructure:"auto_link_by_email"`
	AllowOIDCSignup bool `mapstructure:"allow_oidc_signup"`
}
```

Add to `keyDefaults`:
```go
	"auth.oidc.enabled":            false,
	"auth.oidc.required":           false,
	"auth.oidc.issuer":             "",
	"auth.oidc.client_id":          "",
	"auth.oidc.client_secret":      "",
	"auth.oidc.scopes":             []string{"openid", "profile", "email"},
	"auth.oidc.auto_link_by_email": true,
	"auth.oidc.allow_oidc_signup":  true,
```

Add validation near the end of `Load`, after the existing `NonceTTL >= SkewWindow` check:
```go
	if cfg.Auth.OIDC.Enabled {
		if cfg.Auth.OIDC.Issuer == "" || cfg.Auth.OIDC.ClientID == "" || cfg.Auth.OIDC.ClientSecret == "" {
			return Server{}, fmt.Errorf("config: auth.oidc.enabled requires issuer, client_id, and client_secret")
		}
		if cfg.Server.BaseURL == "" {
			return Server{}, fmt.Errorf("config: auth.oidc.enabled requires server.base_url (for the OIDC redirect_uri)")
		}
		if !slices.Contains(cfg.Auth.OIDC.Scopes, "openid") {
			return Server{}, fmt.Errorf("config: auth.oidc.scopes must include \"openid\"")
		}
	}
```

Add `"slices"` to the imports.

> **Note (documented caveat, no code):** `auth.oidc.scopes` cannot be set via the `DIYDDNS_AUTH_OIDC_SCOPES` env var (viper delivers it as a single string, not `[]string`). Configure scopes via YAML or flags. The default covers the common case.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): auth.oidc section with enabled/issuer/scopes validation"
```

---

## Task 5: mock IdP test harness (`oidctest`)

**Files:**
- Create: `internal/oidc/oidctest/mockidp.go` (a normal package, importable by tests in `internal/oidc` and `internal/server/api`)
- Test: `internal/oidc/oidctest/mockidp_test.go`
- Modify: `go.mod`/`go.sum` (add `github.com/go-jose/go-jose/v4`)

**Interfaces:**
- Produces:
  - `func New(t *testing.T, opts Options) *IdP` — starts an `httptest.Server`; `t.Cleanup` closes it.
  - `type Options struct { SupportDevice bool }`
  - `type IdP struct { Issuer string; ... }` with:
    - `func (i *IdP) SignIDToken(claims Claims) string` — a signed RS256 JWT verifiable against the served JWKS.
    - `type Claims struct { Subject, Email, Nonce, Audience string; EmailVerified bool; ExpiresIn int64 }`
    - `func (i *IdP) SetAuthCodeClaims(c Claims)` — claims the next auth-code `/token` mints.
    - `func (i *IdP) ApproveDevice(deviceCode string, claims Claims)` — flips a device flow from `authorization_pending` to success (test drives pending→complete).

**Why:** Every OIDC test needs an issuer whose discovery `issuer` equals its own base URL (go-oidc requires the match), a JWKS backing the signatures, and controllable token/device endpoints. Making it a normal package (not `_test.go`) lets both `internal/oidc` and `internal/server/api` tests import it.

- [ ] **Step 1: Add the go-jose dependency**

Run:
```bash
go get github.com/go-jose/go-jose/v4@latest
```

- [ ] **Step 2: Write the harness**

Create `internal/oidc/oidctest/mockidp.go`. It must serve:
- `GET /.well-known/openid-configuration` → JSON with `issuer` = server URL, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and (when `SupportDevice`) `device_authorization_endpoint`.
- `GET /jwks` → the RSA public key as a JWKS.
- `POST /token` → for auth-code: returns `{id_token}`; for device-code grant: returns staged `authorization_pending` until `ApproveDevice`, then `{id_token}`.
- `POST /device` (when `SupportDevice`) → returns `{device_code, user_code, verification_uri, expires_in, interval}`.
- `GET /authorize` → immediately 302 back to the `redirect_uri` with `code` + echoed `state` (so the browser test needs no user interaction).

Full implementation:

```go
// Package oidctest provides an in-process mock OpenID Provider for tests.
// It is a normal (non-_test) package so tests across internal/oidc and
// internal/server/api can import it. Never use it outside tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims are the ID-token claims a test wants minted.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
	Audience      string
	ExpiresIn     int64 // seconds from now; default 300 when 0
}

// Options configures the mock provider.
type Options struct {
	SupportDevice bool // advertise + serve the RFC 8628 device endpoints
}

// IdP is a running mock OpenID Provider.
type IdP struct {
	Issuer string

	srv     *httptest.Server
	key     *rsa.PrivateKey
	keyID   string
	support bool

	mu           sync.Mutex
	authCode     Claims            // claims to mint for the next auth-code /token
	device       map[string]Claims // device_code → approved claims (absent = pending)
	deviceUser   map[string]string // user_code → device_code (staging)
	pollInterval int64
}

// New starts a mock IdP and registers cleanup on t.
func New(t *testing.T, opts Options) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: gen key: %v", err)
	}
	i := &IdP{
		key:          key,
		keyID:        "test-key-1",
		support:      opts.SupportDevice,
		device:       map[string]Claims{},
		deviceUser:   map[string]string{},
		pollInterval: 1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("/jwks", i.handleJWKS)
	mux.HandleFunc("/authorize", i.handleAuthorize)
	mux.HandleFunc("/token", i.handleToken)
	if opts.SupportDevice {
		mux.HandleFunc("/device", i.handleDevice)
	}
	i.srv = httptest.NewServer(mux)
	i.Issuer = i.srv.URL
	t.Cleanup(i.srv.Close)
	return i
}

// SetAuthCodeClaims sets the claims the next auth-code /token exchange returns.
func (i *IdP) SetAuthCodeClaims(c Claims) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.authCode = c
}

// ApproveDevice marks a device_code approved, so the next /token device poll
// returns an id_token with the given claims (before this it returns
// authorization_pending).
func (i *IdP) ApproveDevice(deviceCode string, c Claims) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.device[deviceCode] = c
}

func (i *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                 i.Issuer,
		"authorization_endpoint": i.Issuer + "/authorize",
		"token_endpoint":         i.Issuer + "/token",
		"jwks_uri":               i.Issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	if i.support {
		doc["device_authorization_endpoint"] = i.Issuer + "/device"
	}
	writeJSON(w, doc)
}

func (i *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{Key: &i.key.PublicKey, KeyID: i.keyID, Algorithm: "RS256", Use: "sig"}
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (i *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	rq := redirect.Query()
	rq.Set("code", "test-auth-code")
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (i *IdP) handleDevice(w http.ResponseWriter, _ *http.Request) {
	dc := "test-device-code"
	writeJSON(w, map[string]any{
		"device_code":      dc,
		"user_code":        "WXYZ-1234",
		"verification_uri": i.Issuer + "/verify",
		"expires_in":       600,
		"interval":         i.pollInterval,
	})
}

func (i *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	grant := r.Form.Get("grant_type")
	i.mu.Lock()
	defer i.mu.Unlock()

	if grant == "urn:ietf:params:oauth:grant-type:device_code" {
		dc := r.Form.Get("device_code")
		claims, ok := i.device[dc]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "authorization_pending"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": i.sign(claims)})
		return
	}
	// auth-code grant
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": i.sign(i.authCode)})
}

func (i *IdP) sign(c Claims) string {
	if c.Audience == "" {
		c.Audience = "test-client"
	}
	exp := c.ExpiresIn
	if exp == 0 {
		exp = 300
	}
	now := time.Now().Unix()
	payload := map[string]any{
		"iss": i.Issuer,
		"sub": c.Subject,
		"aud": c.Audience,
		"exp": now + exp,
		"iat": now,
	}
	if c.Email != "" {
		payload["email"] = c.Email
		payload["email_verified"] = c.EmailVerified
	}
	if c.Nonce != "" {
		payload["nonce"] = c.Nonce
	}
	b, _ := json.Marshal(payload)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.keyID),
	)
	if err != nil {
		panic(fmt.Sprintf("oidctest: signer: %v", err))
	}
	obj, err := signer.Sign(b)
	if err != nil {
		panic(fmt.Sprintf("oidctest: sign: %v", err))
	}
	s, _ := obj.CompactSerialize()
	return s
}

// SignIDToken exposes signing for tests that verify tokens directly.
func (i *IdP) SignIDToken(c Claims) string { return i.sign(c) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 3: Write a self-test**

Create `internal/oidc/oidctest/mockidp_test.go`:

```go
package oidctest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestMockIdP_DiscoveryAdvertisesDeviceOnlyWhenEnabled(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	resp, err := http.Get(idp.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["issuer"] != idp.Issuer {
		t.Fatalf("issuer mismatch: %v != %v", doc["issuer"], idp.Issuer)
	}
	if _, ok := doc["device_authorization_endpoint"]; !ok {
		t.Fatal("expected device endpoint advertised")
	}
}
```

- [ ] **Step 4: Run tests + tidy**

Run: `go mod tidy && go test ./internal/oidc/oidctest/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/oidc/oidctest/
git commit -m "test(oidc): in-process mock OpenID Provider harness"
```

---

## Task 6: `oidc.Manager` — discovery & state

**Files:**
- Create: `internal/oidc/manager.go`
- Test: `internal/oidc/manager_test.go`
- Modify: `go.mod`/`go.sum` (add `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`)

**Interfaces:**
- Produces:
  - `type Manager struct { ... }`
  - `func NewManager(cfg config.OIDCCfg, baseURL string, log *slog.Logger) *Manager` — always constructed; never does network in the constructor.
  - `func (m *Manager) Discover(ctx context.Context) error` — one synchronous discovery attempt; on success publishes state atomically.
  - `func (m *Manager) Enabled() bool` — cfg.Enabled AND state published.
  - `func (m *Manager) DeviceEnabled() bool` — Enabled AND the discovered endpoint has a DeviceAuthURL.
  - Unexported `state` struct `{provider *oidc.Provider; verifier *oidc.IDTokenVerifier; oauth2 oauth2.Config; deviceAuthURL string}` behind `atomic.Pointer[state]`.
  - `var ErrNotReady = errors.New("oidc: provider not ready")`

- [ ] **Step 1: Add deps**

Run:
```bash
go get github.com/coreos/go-oidc/v3@latest golang.org/x/oauth2@latest
```

- [ ] **Step 2: Write the failing test**

Create `internal/oidc/manager_test.go`:

```go
package oidc_test

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func newManager(t *testing.T, idp *oidctest.IdP, device bool) *oidc.Manager {
	t.Helper()
	cfg := config.OIDCCfg{
		Enabled: true, Issuer: idp.Issuer, ClientID: "test-client",
		ClientSecret: "secret", Scopes: []string{"openid", "profile", "email"},
		AutoLinkByEmail: true, AllowOIDCSignup: true,
	}
	return oidc.NewManager(cfg, "https://ddns.example.com", testLogger(t))
}

func TestManager_DiscoverPublishesState(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	m := newManager(t, idp, true)

	if m.Enabled() {
		t.Fatal("Enabled() must be false before Discover")
	}
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !m.Enabled() {
		t.Fatal("Enabled() must be true after successful Discover")
	}
	if !m.DeviceEnabled() {
		t.Fatal("DeviceEnabled() must be true when the IdP advertises a device endpoint")
	}
}

func TestManager_DeviceDisabledWhenIdPLacksEndpoint(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !m.Enabled() {
		t.Fatal("Enabled() true expected")
	}
	if m.DeviceEnabled() {
		t.Fatal("DeviceEnabled() must be false when no device endpoint is advertised")
	}
}

func TestManager_DiscoverFailsOnBadIssuer(t *testing.T) {
	cfg := config.OIDCCfg{Enabled: true, Issuer: "http://127.0.0.1:1/nope", ClientID: "x", ClientSecret: "y", Scopes: []string{"openid"}}
	m := oidc.NewManager(cfg, "https://ddns.example.com", testLogger(t))
	if err := m.Discover(t.Context()); err == nil {
		t.Fatal("expected Discover to fail against an unreachable issuer")
	}
	if m.Enabled() {
		t.Fatal("Enabled() must stay false after a failed Discover")
	}
}
```

Add a `testLogger` helper in the same test file:
```go
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
```
(imports: `io`, `log/slog`)

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/oidc/ -run TestManager_Discover -v`
Expected: FAIL — `undefined: oidc.NewManager`.

- [ ] **Step 4: Implement the Manager core**

Create `internal/oidc/manager.go`:

```go
// Package oidc implements diyddns's OpenID Connect client: provider discovery,
// ID-token verification, and the browser authorization-code and agent device-code
// flows. It is the ONLY package that imports go-oidc/oauth2, keeping those
// server-only dependencies out of the client binary.
package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jacaudi/diyddns/internal/config"
)

// ErrNotReady is returned by flow methods when the provider has not been
// discovered yet (degraded state).
var ErrNotReady = errors.New("oidc: provider not ready")

// ErrDeviceUnsupported is returned when the IdP advertises no device endpoint.
var ErrDeviceUnsupported = errors.New("oidc: device flow not supported by provider")

// idpCallTimeout bounds every outbound call to the IdP.
const idpCallTimeout = 10 * time.Second

// state is the published, ready-to-use provider snapshot, swapped atomically.
type state struct {
	verifier      *oidc.IDTokenVerifier
	oauth2        oauth2.Config
	deviceAuthURL string
}

// Manager owns OIDC provider discovery and the resulting verifier/oauth2 config.
// It is always constructed; when cfg.Enabled is false, or before the first
// successful Discover, it is simply not ready (Enabled() == false).
type Manager struct {
	cfg      config.OIDCCfg
	baseURL  string
	log      *slog.Logger
	hc       *http.Client
	st       atomic.Pointer[state]
}

// NewManager constructs a Manager. It performs no network I/O.
func NewManager(cfg config.OIDCCfg, baseURL string, log *slog.Logger) *Manager {
	return &Manager{
		cfg:     cfg,
		baseURL: baseURL,
		log:     log,
		hc: &http.Client{
			Timeout:   idpCallTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		},
	}
}

// ctx returns a context carrying the Manager's bounded HTTP client for both
// go-oidc and oauth2 calls.
func (m *Manager) clientCtx(ctx context.Context) context.Context {
	return context.WithValue(oidc.ClientContext(ctx, m.hc), oauth2.HTTPClient, m.hc)
}

// Discover performs one synchronous discovery attempt. On success it publishes
// the verifier + oauth2 config atomically. Safe to call repeatedly.
func (m *Manager) Discover(ctx context.Context) error {
	if !m.cfg.Enabled {
		return nil
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(cctx, m.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc.Manager.Discover: %w", err)
	}
	m.st.Store(&state{
		verifier: provider.Verifier(&oidc.Config{ClientID: m.cfg.ClientID}),
		oauth2: oauth2.Config{
			ClientID:     m.cfg.ClientID,
			ClientSecret: m.cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  m.baseURL + "/api/v1/auth/oidc/callback",
			Scopes:       m.cfg.Scopes,
		},
		deviceAuthURL: provider.Endpoint().DeviceAuthURL,
	})
	return nil
}

// Enabled reports whether OIDC is configured AND discovery has succeeded.
// Nil-receiver-safe: a nil Manager (never constructed) reports false, so the
// api layer can call it unconditionally without a nil check.
func (m *Manager) Enabled() bool { return m != nil && m.cfg.Enabled && m.st.Load() != nil }

// DeviceEnabled reports whether the device-code flow is available. Nil-safe.
func (m *Manager) DeviceEnabled() bool {
	if m == nil {
		return false
	}
	s := m.st.Load()
	return m.cfg.Enabled && s != nil && s.deviceAuthURL != ""
}
```

- [ ] **Step 5: Run tests + tidy**

Run: `go mod tidy && go test ./internal/oidc/ -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/oidc/manager.go internal/oidc/manager_test.go
git commit -m "feat(oidc): Manager with atomic discovery state + bounded IdP client"
```

---

## Task 7: `oidc.Manager` — browser helpers

**Files:**
- Create: `internal/oidc/browser.go`
- Test: `internal/oidc/browser_test.go`

**Interfaces:**
- Produces:
  - `type Claims struct { Subject, Email string; EmailVerified bool }`
  - `type AuthRequest struct { URL, State, Verifier, Nonce string }`
  - `func (m *Manager) BeginAuth() (AuthRequest, error)` — generates `state`, PKCE verifier, `nonce`; builds the authorization-endpoint redirect URL. `ErrNotReady` if not discovered.
  - `func (m *Manager) CompleteAuth(ctx context.Context, code, verifier, expectedNonce string) (Claims, error)` — exchanges the code (with PKCE), verifies the ID token, checks the nonce, returns claims. `ErrNotReady` if not discovered.

- [ ] **Step 1: Write the failing test**

Create `internal/oidc/browser_test.go`:

```go
package oidc_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestBeginAuth_BuildsPKCERedirect(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	req, err := m.BeginAuth()
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("expected PKCE S256 challenge, got %v", q)
	}
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Fatal("state/nonce not reflected in redirect URL")
	}
	if !strings.HasPrefix(req.URL, idp.Issuer+"/authorize") {
		t.Fatalf("redirect not to IdP authorize endpoint: %s", req.URL)
	}
}

func TestCompleteAuth_VerifiesTokenAndNonce(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	req, _ := m.BeginAuth()
	idp.SetAuthCodeClaims(oidctest.Claims{
		Subject: "sub-1", Email: "u@example.com", EmailVerified: true,
		Nonce: req.Nonce, Audience: "test-client",
	})

	claims, err := m.CompleteAuth(t.Context(), "test-auth-code", req.Verifier, req.Nonce)
	if err != nil {
		t.Fatalf("CompleteAuth: %v", err)
	}
	if claims.Subject != "sub-1" || claims.Email != "u@example.com" || !claims.EmailVerified {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Nonce mismatch must fail.
	idp.SetAuthCodeClaims(oidctest.Claims{Subject: "sub-1", Nonce: "WRONG", Audience: "test-client"})
	if _, err := m.CompleteAuth(t.Context(), "test-auth-code", req.Verifier, req.Nonce); err == nil {
		t.Fatal("CompleteAuth must reject an ID token whose nonce != expected")
	}
}

func TestBeginAuth_NotReady(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false) // no Discover
	if _, err := m.BeginAuth(); err == nil {
		t.Fatal("BeginAuth must return ErrNotReady before Discover")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/oidc/ -run 'TestBeginAuth|TestCompleteAuth' -v`
Expected: FAIL — `m.BeginAuth undefined`.

- [ ] **Step 3: Implement the browser helpers**

Create `internal/oidc/browser.go`:

```go
package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jacaudi/diyddns/internal/auth"
)

// Claims is the subset of ID-token claims the link/signup policy needs.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// AuthRequest carries the redirect URL plus the per-request secrets the caller
// must persist (sealed in a cookie) to validate the callback.
type AuthRequest struct {
	URL      string
	State    string
	Verifier string
	Nonce    string
}

// BeginAuth generates state, a PKCE verifier, and a nonce, and builds the
// authorization-endpoint redirect URL. Returns ErrNotReady if not discovered.
func (m *Manager) BeginAuth() (AuthRequest, error) {
	s := m.st.Load()
	if s == nil {
		return AuthRequest{}, ErrNotReady
	}
	state, err := auth.RandToken(32)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("oidc.BeginAuth: state: %w", err)
	}
	nonce, err := auth.RandToken(32)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("oidc.BeginAuth: nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	url := s.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
	return AuthRequest{URL: url, State: state, Verifier: verifier, Nonce: nonce}, nil
}

// CompleteAuth exchanges the authorization code (with the PKCE verifier),
// verifies the returned ID token, checks the nonce, and returns its claims.
func (m *Manager) CompleteAuth(ctx context.Context, code, verifier, expectedNonce string) (Claims, error) {
	s := m.st.Load()
	if s == nil {
		return Claims{}, ErrNotReady
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	tok, err := s.oauth2.Exchange(cctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: token response has no id_token")
	}
	idt, err := s.verifier.Verify(cctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: verify: %w", err)
	}
	// go-oidc does NOT check nonce; the caller must.
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(expectedNonce)) != 1 {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: nonce mismatch")
	}
	return claimsFrom(idt)
}

// claimsFrom extracts the policy-relevant claims from a verified ID token.
func claimsFrom(idt *oidc.IDToken) (Claims, error) {
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("oidc: parse claims: %w", err)
	}
	return Claims{Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/oidc/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc/browser.go internal/oidc/browser_test.go
git commit -m "feat(oidc): browser BeginAuth (PKCE) + CompleteAuth (verify+nonce)"
```

---

## Task 8: `oidc.Manager` — device helpers

**Files:**
- Create: `internal/oidc/device.go`
- Test: `internal/oidc/device_test.go`

**Interfaces:**
- Produces:
  - `type DeviceAuth struct { DeviceCode, UserCode, VerificationURI, VerificationURIComplete string; ExpiresIn, Interval int64 }`
  - `func (m *Manager) DeviceStart(ctx context.Context) (DeviceAuth, error)` — calls the IdP device endpoint. `ErrDeviceUnsupported` when unavailable, `ErrNotReady` when not discovered.
  - `type PollStatus int` with `PollPending`, `PollSlowDown`, `PollComplete`.
  - `type PollResult struct { Status PollStatus; Claims Claims }`
  - `func (m *Manager) DevicePoll(ctx context.Context, deviceCode string) (PollResult, error)` — one non-blocking token-endpoint POST; parses `authorization_pending`/`slow_down`/success; verifies the ID token on success.

- [ ] **Step 1: Write the failing test**

Create `internal/oidc/device_test.go`:

```go
package oidc_test

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestDeviceStartAndPoll(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	m := newManager(t, idp, true)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	da, err := m.DeviceStart(t.Context())
	if err != nil {
		t.Fatalf("DeviceStart: %v", err)
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		t.Fatalf("incomplete device auth: %+v", da)
	}

	// Before approval → pending.
	res, err := m.DevicePoll(t.Context(), da.DeviceCode)
	if err != nil {
		t.Fatalf("DevicePoll pending: %v", err)
	}
	if res.Status != oidc.PollPending {
		t.Fatalf("want PollPending, got %v", res.Status)
	}

	// Approve → complete with claims.
	idp.ApproveDevice(da.DeviceCode, oidctest.Claims{Subject: "dev-sub", Email: "d@example.com", EmailVerified: true, Audience: "test-client"})
	res, err = m.DevicePoll(t.Context(), da.DeviceCode)
	if err != nil {
		t.Fatalf("DevicePoll complete: %v", err)
	}
	if res.Status != oidc.PollComplete || res.Claims.Subject != "dev-sub" {
		t.Fatalf("want PollComplete for dev-sub, got %v %+v", res.Status, res.Claims)
	}
}

func TestDeviceStart_UnsupportedProvider(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := m.DeviceStart(t.Context()); !errors.Is(err, oidc.ErrDeviceUnsupported) {
		t.Fatalf("want ErrDeviceUnsupported, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/oidc/ -run TestDevice -v`
Expected: FAIL — `m.DeviceStart undefined`.

- [ ] **Step 3: Implement the device helpers**

Create `internal/oidc/device.go`. `DeviceStart` uses `oauth2.Config.DeviceAuth`. `DevicePoll` does a manual single-shot token POST (NOT `DeviceAccessToken`, which blocks) and parses the RFC 8628 error codes:

```go
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceAuth is the device-authorization response handed (in part) to the agent.
// ExpiresAt is an ABSOLUTE unix expiry (the api layer stores it directly and
// derives the agent-facing expires_in = ExpiresAt - now).
type DeviceAuth struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               int64
	Interval                int64
}

// PollStatus is the outcome of a single device-token poll.
type PollStatus int

const (
	PollPending  PollStatus = iota
	PollSlowDown            // caller should back off and keep polling
	PollComplete           // tokens obtained; Claims populated
	PollDenied             // terminal: user denied or the device code expired — stop polling
)

// PollResult carries the poll status and, when complete, the verified claims.
type PollResult struct {
	Status PollStatus
	Claims Claims
}

// DeviceStart begins the device-authorization grant at the IdP.
func (m *Manager) DeviceStart(ctx context.Context) (DeviceAuth, error) {
	s := m.st.Load()
	if s == nil {
		return DeviceAuth{}, ErrNotReady
	}
	if s.deviceAuthURL == "" {
		return DeviceAuth{}, ErrDeviceUnsupported
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	resp, err := s.oauth2.DeviceAuth(cctx)
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("oidc.DeviceStart: %w", err)
	}
	// oauth2 populates resp.Expiry (absolute) from the IdP's expires_in. Guard a
	// zero Expiry (some servers omit it) with a conservative 10-minute default so
	// the stored expires_at is never a huge negative value.
	expiry := resp.Expiry
	if expiry.IsZero() {
		expiry = timeNow().Add(10 * time.Minute)
	}
	return DeviceAuth{
		DeviceCode:              resp.DeviceCode,
		UserCode:                resp.UserCode,
		VerificationURI:         resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		ExpiresAt:               expiry.Unix(),
		Interval:                int64(resp.Interval),
	}, nil
}

// timeNow is indirected so the zero-expiry fallback is testable; production is time.Now.
var timeNow = time.Now
```

(add `"time"` to `internal/oidc/device.go` imports.)

```go

// deviceTokenResponse is the subset of the token-endpoint JSON we read.
type deviceTokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DevicePoll performs ONE non-blocking token-endpoint request for deviceCode.
// It is deliberately manual — oauth2.DeviceAccessToken self-polls and blocks,
// which is wrong for a per-request proxy endpoint.
func (m *Manager) DevicePoll(ctx context.Context, deviceCode string) (PollResult, error) {
	s := m.st.Load()
	if s == nil {
		return PollResult{}, ErrNotReady
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {m.cfg.ClientID},
		"client_secret": {m.cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, s.oauth2.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.hc.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: read: %w", err)
	}

	var tr deviceTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: decode (status %d): %w", resp.StatusCode, err)
	}
	switch tr.Error {
	case "authorization_pending":
		return PollResult{Status: PollPending}, nil
	case "slow_down":
		return PollResult{Status: PollSlowDown}, nil
	case "access_denied", "expired_token":
		// Terminal per RFC 8628 §3.5 — the caller must stop polling and drop the flow.
		return PollResult{Status: PollDenied}, nil
	case "":
		// success path below
	default:
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: idp error: %s", tr.Error)
	}
	if tr.IDToken == "" {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: success response has no id_token")
	}
	idt, err := s.verifier.Verify(cctx, tr.IDToken)
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: verify: %w", err)
	}
	// Device-flow ID tokens carry no nonce (RFC 8628 has no auth request) — no nonce check.
	claims, err := claimsFrom(idt)
	if err != nil {
		return PollResult{}, err
	}
	return PollResult{Status: PollComplete, Claims: claims}, nil
}
```

> **Implementer note:** `s.oauth2` (an `oauth2.Config` stored on `state`) is accessed via the field, so `device.go` does not import the `oauth2` package directly — only `internal/oidc/manager.go` does. `DevicePoll` reaches the token URL via `s.oauth2.Endpoint.TokenURL`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/oidc/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc/device.go internal/oidc/device_test.go
git commit -m "feat(oidc): device-code DeviceStart + single-shot DevicePoll"
```

---

## Task 9: `oidc.Manager` — RetryLoop

**Files:**
- Modify: `internal/oidc/manager.go` (add `RetryLoop` + injectable backoff/clock)
- Test: `internal/oidc/manager_test.go`

**Interfaces:**
- Produces: `func (m *Manager) RetryLoop(ctx context.Context)` — repeatedly calls `Discover` with backoff until it succeeds (or `ctx` is done), then returns. No-op immediately if `!cfg.Enabled` or already ready.
- Adds an unexported injectable `sleep func(context.Context, time.Duration) bool` field defaulting to a real timer, so tests avoid real sleeps.

- [ ] **Step 1: Write the failing test**

Add to `internal/oidc/manager_test.go`:

```go
func TestRetryLoop_RecoversAfterIdPComesUp(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)

	// Force discovery to fail once, then succeed: point at a bad issuer, run the
	// loop with an instant (fake) sleep, and flip the issuer after the first try.
	// Simplest deterministic form: use the manager's test hook to make sleep
	// instant, start the loop, and assert it reaches Enabled().
	oidc.SetSleepForTest(m, func(ctx context.Context, _ time.Duration) bool {
		return ctx.Err() == nil // return immediately, honoring cancellation
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { m.RetryLoop(ctx); close(done) }()

	// The good issuer means the first Discover succeeds; the loop should exit.
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("RetryLoop did not exit after successful discovery")
	}
	if !m.Enabled() {
		t.Fatal("Enabled() expected true after RetryLoop")
	}
}
```

> **Note:** expose a tiny test hook in a `manager_export_test.go` (package `oidc`) so tests can inject the sleep without exporting production API:
> ```go
> package oidc
> import (
> 	"context"
> 	"time"
> )
> func SetSleepForTest(m *Manager, f func(context.Context, time.Duration) bool) { m.sleep = f }
> ```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/oidc/ -run TestRetryLoop -v`
Expected: FAIL — `m.RetryLoop undefined` / `m.sleep undefined`.

- [ ] **Step 3: Implement RetryLoop + injectable sleep**

In `internal/oidc/manager.go`, add the `sleep` field and initialize it in `NewManager`:

```go
type Manager struct {
	cfg     config.OIDCCfg
	baseURL string
	log     *slog.Logger
	hc      *http.Client
	st      atomic.Pointer[state]
	sleep   func(ctx context.Context, d time.Duration) bool // returns false if ctx cancelled during the wait
}
```

In `NewManager`, set:
```go
	m.sleep = func(ctx context.Context, d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	return m
```
(restructure `NewManager` to assign to a local `m` then return it.)

Add the loop:
```go
// retryBackoff is the capped backoff schedule for discovery retries.
var retryBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}

// RetryLoop retries Discover with backoff until it succeeds or ctx is done,
// then returns. It is a no-op if OIDC is disabled or already ready. Intended to
// run as a goroutine (server.Run), so an IdP that is down at startup does not
// block the server; once discovery succeeds, go-oidc's key set self-refreshes.
func (m *Manager) RetryLoop(ctx context.Context) {
	if !m.cfg.Enabled || m.Enabled() {
		return
	}
	for i := 0; ; i++ {
		if err := m.Discover(ctx); err != nil {
			m.log.LogAttrs(ctx, slog.LevelWarn, "oidc discovery failed; retrying", slog.String("issuer", m.cfg.Issuer), slog.Any("error", err))
		} else if m.Enabled() {
			m.log.LogAttrs(ctx, slog.LevelInfo, "oidc provider ready", slog.String("issuer", m.cfg.Issuer))
			return
		}
		d := retryBackoff[min(i, len(retryBackoff)-1)]
		if !m.sleep(ctx, d) {
			return // ctx cancelled
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/oidc/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc/manager.go internal/oidc/manager_test.go internal/oidc/manager_export_test.go
git commit -m "feat(oidc): background RetryLoop with injectable backoff"
```

---

## Task 10: `OIDCService.LoginOrLink` + `BrowserLogin`

**Files:**
- Create: `internal/server/service/oidc.go`
- Test: `internal/server/service/oidc_test.go`

**Interfaces:**
- Consumes: `oidc.Claims` (Subject/Email/EmailVerified), `config.OIDCCfg`, `*store.Store`, `*auth.SessionManager`, `service.AuditSink`.
- Produces:
  - `type OIDCService struct { ... }`
  - `func NewOIDCService(st *store.Store, sessions *auth.SessionManager, cfg config.OIDCCfg, audit AuditSink, log *slog.Logger) *OIDCService`
  - `var ErrOIDCRejected = errors.New("service: oidc login rejected")` — the single generic rejection. Every reject path logs the *specific* reason server-side (design §9) before returning this sentinel.
  - `func (s *OIDCService) LoginOrLink(ctx, issuer, subject, email string, emailVerified bool) (store.User, error)` — the shared resolve/link/signup policy; emits `user.created` (signup) and `user.oidc.linked` (link) audits. Returns `ErrOIDCRejected` for every policy reject.
  - `func (s *OIDCService) BrowserLogin(ctx, issuer, subject, email string, emailVerified bool, ip, ua string) (store.Session, error)` — calls `LoginOrLink`, then `sessions.Create`, then audits `user.login.oidc`.

- [ ] **Step 1: Write the failing test**

Create `internal/server/service/oidc_test.go` — **in-package `package service`** (like the other service tests), so drop all `service.` qualifiers and use the package's own `openTestStore(t)` (returns `*store.Store`) and `discardLogger()`. Cover: existing-subject login, verified-email link (non-admin), admin-not-linked, unverified-email-conflict reject, empty-email reject, signup, signup-disabled, disabled-user:

```go
func TestOIDCLoginOrLink(t *testing.T) {
	newSvc := func(t *testing.T, st *store.Store, cfg config.OIDCCfg) *OIDCService {
		sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
		return NewOIDCService(st, sm, cfg, NewAuditWriter(st), discardLogger())
	}
	baseCfg := config.OIDCCfg{AutoLinkByEmail: true, AllowOIDCSignup: true}
	const iss = "https://idp.example.com"

	t.Run("existing subject logs in", func(t *testing.T) {
		st := newTestStore(t)
		u, _ := st.Users().Create(t.Context(), store.User{Email: "a@x.com", Role: "user", OIDCProvider: iss, OIDCSubject: "s1"})
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s1", "a@x.com", true)
		if err != nil || got.ID != u.ID {
			t.Fatalf("want login of %s, got %+v err=%v", u.ID, got, err)
		}
	})

	t.Run("verified email links existing local user", func(t *testing.T) {
		st := newTestStore(t)
		u, _ := st.Users().Create(t.Context(), store.User{Email: "b@x.com", Role: "user", PasswordHash: "h"})
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s2", "b@x.com", true)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if got.OIDCProvider != iss || got.OIDCSubject != "s2" || got.ID != u.ID {
			t.Fatalf("expected link onto %s, got %+v", u.ID, got)
		}
	})

	t.Run("admin is never auto-linked", func(t *testing.T) {
		st := newTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "admin@x.com", Role: "admin", PasswordHash: "h"})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s3", "admin@x.com", true); !errors.Is(err, service.ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for admin email, got %v", err)
		}
	})

	t.Run("unverified email with existing account is rejected, not duplicated", func(t *testing.T) {
		st := newTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "c@x.com", Role: "user", PasswordHash: "h"})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s4", "c@x.com", false); !errors.Is(err, service.ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
	})

	t.Run("empty email is rejected", func(t *testing.T) {
		st := newTestStore(t)
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s5", "", true); !errors.Is(err, service.ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for empty email, got %v", err)
		}
	})

	t.Run("new verified user is created as role=user", func(t *testing.T) {
		st := newTestStore(t)
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s6", "new@x.com", true)
		if err != nil || got.Role != "user" || got.OIDCSubject != "s6" {
			t.Fatalf("signup: %+v err=%v", got, err)
		}
	})

	t.Run("signup disabled rejects unknown user", func(t *testing.T) {
		st := newTestStore(t)
		cfg := baseCfg
		cfg.AllowOIDCSignup = false
		if _, err := newSvc(t, st, cfg).LoginOrLink(t.Context(), iss, "s7", "nope@x.com", true); !errors.Is(err, service.ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
	})

	t.Run("disabled linked user is rejected", func(t *testing.T) {
		st := newTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "d@x.com", Role: "user", OIDCProvider: iss, OIDCSubject: "s8", Disabled: true})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s8", "d@x.com", true); !errors.Is(err, service.ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for disabled user, got %v", err)
		}
	})
}

func TestOIDCBrowserLogin_CreatesSession(t *testing.T) {
	st := openTestStore(t)
	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	svc := NewOIDCService(st, sm, config.OIDCCfg{AutoLinkByEmail: true, AllowOIDCSignup: true}, NewAuditWriter(st), discardLogger())
	sess, err := svc.BrowserLogin(t.Context(), "https://idp.example.com", "s9", "e@x.com", true, "1.2.3.4", "ua")
	if err != nil || sess.ID == "" || sess.CSRFToken == "" {
		t.Fatalf("BrowserLogin: sess=%+v err=%v", sess, err)
	}
}
```

> **Helpers (per the Test Harness Reference):** this file is `package service`. Every `st := newTestStore(t)` above must be `st := openTestStore(t)` (the service package's single-value helper), and all `service.`/`store.User{}` etc. stay unqualified for `service` symbols. `errors.Is(err, ErrOIDCRejected)` — unqualified.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/service/ -run 'TestOIDCLoginOrLink|TestOIDCBrowserLogin' -v`
Expected: FAIL — `service.NewOIDCService undefined`.

- [ ] **Step 3: Implement the service**

Create `internal/server/service/oidc.go`:

```go
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrOIDCRejected is the single generic rejection returned for every OIDC
// login/link/signup policy failure, so callers surface one uniform outcome and
// never leak which check failed or whether an account exists.
var ErrOIDCRejected = errors.New("service: oidc login rejected")

// OIDCService owns the OIDC link/signup policy: it resolves an authenticated
// OIDC identity to a local user (matching by subject, then verified email, then
// signup) and, for the browser flow, mints a session.
type OIDCService struct {
	st       *store.Store
	sessions *auth.SessionManager
	cfg      config.OIDCCfg
	audit    AuditSink
	log      *slog.Logger
}

// NewOIDCService constructs an OIDCService.
func NewOIDCService(st *store.Store, sessions *auth.SessionManager, cfg config.OIDCCfg, audit AuditSink, log *slog.Logger) *OIDCService {
	return &OIDCService{st: st, sessions: sessions, cfg: cfg, audit: audit, log: log}
}

// reject logs the specific policy-rejection reason server-side (so operators can
// see WHY a login failed, design §9) and returns the single generic sentinel.
func (s *OIDCService) reject(ctx context.Context, reason string) error {
	s.log.LogAttrs(ctx, slog.LevelInfo, "oidc login rejected", slog.String("reason", reason))
	return ErrOIDCRejected
}

// LoginOrLink resolves an authenticated OIDC identity to a local user. Order:
//  1. (issuer, subject) match → that user (rejected if disabled)
//  2. verified email + auto-link + existing non-admin local user → link + that user
//  3. signup allowed → create role=user
//  4. otherwise → ErrOIDCRejected
// Admins are never auto-created or auto-linked. Every reject is ErrOIDCRejected.
func (s *OIDCService) LoginOrLink(ctx context.Context, issuer, subject, email string, emailVerified bool) (store.User, error) {
	// 1. Existing linked identity.
	u, err := s.st.Users().GetByOIDC(ctx, issuer, subject)
	if err == nil {
		if u.Disabled {
			return store.User{}, s.reject(ctx, "linked user disabled")
		}
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("service.LoginOrLink: %w", err)
	}

	// 2. Verified-email auto-link.
	if email == "" {
		return store.User{}, s.reject(ctx, "no email claim") // cannot link or sign up without an email
	}
	if emailVerified && s.cfg.AutoLinkByEmail {
		existing, err := s.st.Users().GetByEmail(ctx, email)
		switch {
		case err == nil:
			if existing.Role == "admin" || existing.OIDCSubject != "" {
				return store.User{}, s.reject(ctx, "email matches admin or already-linked account") // never auto-link admins or already-linked accounts
			}
			existing.OIDCProvider = issuer
			existing.OIDCSubject = subject
			if err := s.st.Users().Update(ctx, existing); err != nil {
				return store.User{}, fmt.Errorf("service.LoginOrLink: link: %w", err)
			}
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: existing.ID, EventType: "user.oidc.linked", TargetType: "user", TargetID: existing.ID})
			return existing, nil
		case errors.Is(err, store.ErrNotFound):
			// fall through to signup
		default:
			return store.User{}, fmt.Errorf("service.LoginOrLink: %w", err)
		}
	}

	// 3. Signup.
	if !s.cfg.AllowOIDCSignup {
		return store.User{}, s.reject(ctx, "signup disabled")
	}
	created, err := s.st.Users().Create(ctx, store.User{
		Email: email, Role: "user", OIDCProvider: issuer, OIDCSubject: subject,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Email already exists but wasn't linkable above (unverified, auto-link off,
			// or already linked). Reject uniformly — never leak existence, never 500.
			return store.User{}, s.reject(ctx, "email exists but not linkable (unverified / auto-link off / already linked)")
		}
		return store.User{}, fmt.Errorf("service.LoginOrLink: create: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: created.ID, EventType: "user.created", TargetType: "user", TargetID: created.ID})
	return created, nil
}

// BrowserLogin resolves the identity via LoginOrLink and mints a browser
// session, auditing user.login.oidc.
func (s *OIDCService) BrowserLogin(ctx context.Context, issuer, subject, email string, emailVerified bool, ip, ua string) (store.Session, error) {
	u, err := s.LoginOrLink(ctx, issuer, subject, email, emailVerified)
	if err != nil {
		return store.Session{}, err
	}
	sess, err := s.sessions.Create(ctx, u.ID, ip, ua)
	if err != nil {
		return store.Session{}, fmt.Errorf("service.BrowserLogin: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.login.oidc", IP: ip})
	return sess, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/service/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/service/oidc.go internal/server/service/oidc_test.go
git commit -m "feat(service): OIDC LoginOrLink policy + BrowserLogin session mint"
```

---

## Task 11: `EnrollmentService.EnrollForUser`

**Files:**
- Modify: `internal/server/service/enrollment.go` (add exported `EnrollForUser`)
- Test: `internal/server/service/enrollment_test.go`

**Interfaces:**
- Produces: `func (s *EnrollmentService) EnrollForUser(ctx context.Context, userID, eventType string, meta ClientMeta) (EnrollResult, error)` — mints a sealed device for an already-authenticated user (label defaults to `meta.Hostname` or `"device"`) via the existing `createSealedDevice`, and audits `eventType`.

**Why:** The OIDC device-code poll (Task 13) mints a device for an OIDC-resolved user — the same operation as `EnrollCredentials` minus the password check. Extract the shared tail into an exported entry so the audit event stays service-owned.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/service/enrollment_test.go`:

```go
func TestEnrollForUser_MintsSealedDeviceWithAudit(t *testing.T) {
	st := newTestStore(t)
	key := make([]byte, 32)
	svc := service.NewEnrollmentService(st, key, 15*time.Minute, service.NewAuditWriter(st))
	u, _ := st.Users().Create(t.Context(), store.User{Email: "u@x.com", Role: "user", OIDCProvider: "iss", OIDCSubject: "s"})

	res, err := svc.EnrollForUser(t.Context(), u.ID, "device.enroll.oidc", service.ClientMeta{Hostname: "homelab"})
	if err != nil {
		t.Fatalf("EnrollForUser: %v", err)
	}
	if res.DeviceID == "" || len(res.Secret) != 32 {
		t.Fatalf("unexpected result: %+v", res)
	}
	dev, err := st.Devices().Get(t.Context(), res.DeviceID)
	if err != nil || dev.UserID != u.ID || dev.Label != "homelab" {
		t.Fatalf("device not created correctly: %+v err=%v", dev, err)
	}
}
```

(If `st.Devices().Get` has a different signature in this repo, use the one the devices repo actually exposes — check `internal/store/devices.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/service/ -run TestEnrollForUser -v`
Expected: FAIL — `svc.EnrollForUser undefined`.

- [ ] **Step 3: Implement `EnrollForUser`**

Add to `internal/server/service/enrollment.go`:

```go
// EnrollForUser mints and seals a fresh device for an already-authenticated
// user — the shared tail of every non-code enrollment path. label defaults to
// meta.Hostname, or "device" when empty. eventType is the audit event to
// record (e.g. "device.enroll.oidc").
func (s *EnrollmentService) EnrollForUser(ctx context.Context, userID, eventType string, meta ClientMeta) (EnrollResult, error) {
	label := meta.Hostname
	if label == "" {
		label = "device"
	}
	dev, secret, err := s.createSealedDevice(ctx, userID, label, meta)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.EnrollForUser: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID,
		EventType:   eventType,
		TargetType:  "device",
		TargetID:    dev.ID,
	})
	return EnrollResult{DeviceID: dev.ID, Secret: secret}, nil
}
```

> **Optional DRY refactor (safe):** `EnrollCredentials`'s tail (label default + `createSealedDevice` + audit) may be replaced with a call to `EnrollForUser(ctx, u.ID, "device.enroll.credentials", meta)`. Only do this if all existing `EnrollCredentials` tests still pass unchanged; otherwise leave `EnrollCredentials` as-is (the shared `createSealedDevice` already satisfies DRY).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/service/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/service/enrollment.go internal/server/service/enrollment_test.go
git commit -m "feat(service): EnrollForUser for authenticated (OIDC) device enrollment"
```

---

## Task 12: Browser API ops (`/api/v1/auth/oidc/start` + `/callback`)

**Files:**
- Create: `internal/server/api/oidc.go`
- Modify: `internal/server/api/api.go` (add `OIDC`, `OIDCMgr` to `ServerDeps`; add `registerOIDCOps(a, deps)` to `registerAuthOps`)
- Test: `internal/server/api/oidc_test.go`

**Interfaces:**
- Consumes: `*oidc.Manager` (BeginAuth/CompleteAuth), `*service.OIDCService` (BrowserLogin), `config.SessionCfg` + `config.OIDCCfg`, `auth.SealWithAAD`/`OpenWithAAD`, the AEAD master key bytes.
- Produces: two registered huma operations; `ServerDeps.OIDC`, `ServerDeps.OIDCMgr`, `ServerDeps.HMACKey []byte` (the decoded master key, needed for cookie sealing).

**Design notes:**
- The flow cookie `diyddns_oidc_flow` seals `{state, verifier, nonce, next}` JSON with `auth.SealWithAAD(masterKey, json, []byte("diyddns/oidc-flow-v1"))`; `HttpOnly`, `Secure` (from `SessionCfg.CookieSecure` OR TLS), `SameSite=Lax`, `Path=/api/v1/auth/oidc`, `MaxAge=600`.
- Both ops are plain redirects (`302`), no session/CSRF middleware (pre-session).
- `next` is validated: empty or must `url.Parse` with empty Scheme/Host and Path starting `/`, and must not start with `//` or `/\`; else default to `/`.
- Since these ops are `GET` redirects that read the raw request (cookies, TLS, query) and write `Location`/`Set-Cookie`, they use the `humago.Unwrap` pattern (like Plan 04's `hmacMiddleware`) OR register raw `http.HandlerFunc`s on the mux. **Use the huma op + a metadata middleware** consistent with `loginMetaMiddleware`, reading `*http.Request` via `humago.Unwrap`, and returning a `*struct{ ... header:"..." }` output. Because both cookie and redirect are headers, the output struct carries `Location` and `Set-Cookie` headers with `DefaultStatus: 302`.

- [ ] **Step 1: Write the failing test (end-to-end over httptest + mock IdP)**

Create `internal/server/api/oidc_test.go`. Build the real server handler wired with an enabled Manager (discovered against the mock IdP) and drive start→IdP→callback with a non-following client so redirects and cookies can be asserted:

```go
func TestOIDCBrowserFlow_EndToEnd(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	st := newTestStore(t)            // api package test helper: migrated :memory: store
	key := make([]byte, 32)

	cfg := config.OIDCCfg{
		Enabled: true, Issuer: idp.Issuer, ClientID: "test-client", ClientSecret: "secret",
		Scopes: []string{"openid", "profile", "email"}, AutoLinkByEmail: true, AllowOIDCSignup: true,
	}
	mgr := oidc.NewManager(cfg, "http://server.example", discardLogger())
	if err := mgr.Discover(t.Context()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Wire the full server WITH OIDC. Extend newFullHarness (or add newOIDCHarness)
	// to set OIDC/OIDCMgr/HMACKey on the ServerDeps it already assembles, reusing
	// its `key`. cfg.OIDC in ServerDeps.Cfg must carry `cfg` so the callback reads
	// the right issuer. See the Test Harness Reference section — do NOT invent a
	// separate buildTestAPIHandler.
	h := newOIDCHarness(t, st, mgr, cfg) // returns { srv *httptest.Server; ... }
	srv := h.srv

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. /start → 302 to the IdP, sets the flow cookie.
	resp, err := client.Get(srv.URL + "/api/v1/auth/oidc/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, idp.Issuer+"/authorize") {
		t.Fatalf("start: status=%d loc=%s", resp.StatusCode, loc)
	}
	// Stage the claims the IdP will mint, keyed to the nonce carried in the auth URL.
	nonce := mustQuery(t, loc, "nonce")
	idp.SetAuthCodeClaims(oidctest.Claims{Subject: "sub-1", Email: "new@x.com", EmailVerified: true, Nonce: nonce, Audience: "test-client"})

	// 2. Follow to the IdP authorize (it 302s back to our callback with code+state).
	// The cookie jar carries the flow cookie to the callback.
	cbURL := followToCallback(t, client, loc) // GET loc, read its Location (our callback)
	resp2, err := client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp2.StatusCode)
	}
	// 3. Session cookie set; the OIDC user exists.
	if !hasCookie(resp2, "diyddns_session") {
		t.Fatal("callback did not set the session cookie")
	}
	if _, err := st.Users().GetByOIDC(t.Context(), idp.Issuer, "sub-1"); err != nil {
		t.Fatalf("OIDC user not created: %v", err)
	}
}

func TestOIDCCallback_StateMismatchRejected(t *testing.T) {
	// start to obtain a valid flow cookie, then call /callback with a wrong state → 400.
	// (Build as above; assert resp.StatusCode == http.StatusBadRequest.)
}
```

> **Implementer note:** `buildTestAPIHandler`, `mustQuery`, `followToCallback`, `hasCookie`, and `testLogger` are small test helpers — define them in the api test package (or reuse existing ones). `mgr.Config()` is illustrative only; pass the identical `config.OIDCCfg` used to build the manager into `NewOIDCService`. If the api package already has a helper that assembles a full handler (Plan 04's black-box tests use one via `server.Handler` or `api.Build`), prefer it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/api/ -run TestOIDCBrowserFlow -v`
Expected: FAIL — start route 404 / `registerOIDCOps` undefined.

- [ ] **Step 3: Add ServerDeps fields + wire registration**

In `internal/server/api/api.go`:
```go
type ServerDeps struct {
	// ... existing fields ...
	OIDC    *service.OIDCService
	OIDCMgr *oidc.Manager
	HMACKey []byte // decoded AEAD master key, for sealing the OIDC flow cookie
}
```
(add the `internal/oidc` import.)

In `registerAuthOps`, add one line at the end:
```go
	registerOIDCOps(a, deps)
```

- [ ] **Step 4: Implement the browser ops**

Create `internal/server/api/oidc.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
)

// oidcFlowCookie is the sealed cookie holding the in-flight browser auth state.
const oidcFlowCookie = "diyddns_oidc_flow"

// oidcFlowAAD domain-separates the flow cookie's AEAD sealing from device-secret sealing.
var oidcFlowAAD = []byte("diyddns/oidc-flow-v1")

// oidcFlowState is the JSON sealed into oidcFlowCookie.
type oidcFlowState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Next     string `json:"next"`
}

// oidcRedirectOutput carries a 302 redirect plus an optional Set-Cookie.
type oidcRedirectOutput struct {
	Status    int
	Location  string      `header:"Location"`
	SetCookie http.Cookie `header:"Set-Cookie"`
}

// safeNext returns next if it is a local path (leading "/", not scheme-relative),
// else "/".
func safeNext(next string) string {
	if next == "" || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return next
}

func registerOIDCOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodGet,
		Path:          "/api/v1/auth/oidc/start",
		DefaultStatus: http.StatusFound,
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, in *struct {
		Next string `query:"next"`
	}) (*oidcRedirectOutput, error) {
		if !deps.OIDCMgr.Enabled() {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=oidc_unavailable"}, nil
		}
		req, err := deps.OIDCMgr.BeginAuth()
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc begin auth failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=oidc_unavailable"}, nil
		}
		blob, _ := json.Marshal(oidcFlowState{State: req.State, Verifier: req.Verifier, Nonce: req.Nonce, Next: safeNext(in.Next)})
		sealed, err := auth.SealWithAAD(deps.HMACKey, blob, oidcFlowAAD)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc seal flow cookie failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=oidc_unavailable"}, nil
		}
		meta := loginMetaFrom(ctx)
		return &oidcRedirectOutput{
			Status:    http.StatusFound,
			Location:  req.URL,
			SetCookie: oidcFlowSetCookie(deps, sealed, 600, meta.tls),
		}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodGet,
		Path:          "/api/v1/auth/oidc/callback",
		DefaultStatus: http.StatusFound,
		Middlewares:   huma.Middlewares{loginMetaMiddleware(), oidcFlowMiddleware()},
	}, func(ctx context.Context, in *struct {
		Code  string `query:"code"`
		State string `query:"state"`
		Error string `query:"error"`
	}) (*oidcRedirectOutput, error) {
		meta := loginMetaFrom(ctx)
		clear := oidcFlowSetCookie(deps, "", -1, meta.tls) // expire the flow cookie on every terminal outcome

		if in.Error != "" {
			deps.Log.LogAttrs(ctx, slog.LevelWarn, "oidc idp returned error", slog.String("error", in.Error))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=no_account", SetCookie: clear}, nil
		}

		// The flow cookie's raw value was captured from *http.Request by
		// oidcFlowMiddleware (huma business handlers get a plain context.Context,
		// never the request — mirror loginMetaMiddleware's humago.Unwrap pattern).
		sealed, ok := oidcFlowCookieFrom(ctx)
		if !ok {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=no_account", SetCookie: clear}, nil
		}
		raw, err := auth.OpenWithAAD(deps.HMACKey, sealed, oidcFlowAAD)
		if err != nil {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=no_account", SetCookie: clear}, nil
		}
		var fs oidcFlowState
		if err := json.Unmarshal(raw, &fs); err != nil || subtleMismatch(fs.State, in.State) {
			return &oidcRedirectOutput{Status: http.StatusBadRequest, Location: "", SetCookie: clear}, nil
		}

		claims, err := deps.OIDCMgr.CompleteAuth(ctx, in.Code, fs.Verifier, fs.Nonce)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc complete auth failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=no_account", SetCookie: clear}, nil
		}
		sess, err := deps.OIDC.BrowserLogin(ctx, deps.Cfg.OIDC.Issuer, claims.Subject, claims.Email, claims.EmailVerified, meta.ip, meta.ua)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelInfo, "oidc login rejected", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: "/login?error=no_account", SetCookie: clear}, nil
		}
		// Success: set the session cookie (reusing the Plan 04 helper) and clear the flow cookie.
		// Two Set-Cookie headers are needed; return both via a slice-carrying output (see note).
		return &oidcRedirectOutput{
			Status:    http.StatusFound,
			Location:  safeNext(fs.Next),
			SetCookie: sessionCookie(deps.Cfg.Session, sess.ID, 0, meta.tls),
		}, nil
	})
}

func oidcFlowSetCookie(deps ServerDeps, value string, maxAge int, tlsActive bool) http.Cookie {
	return http.Cookie{
		Name:     oidcFlowCookie,
		Value:    value,
		Path:     "/api/v1/auth/oidc",
		HttpOnly: true,
		Secure:   tlsActive || deps.Cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// oidcFlowKey is the context key for the raw (sealed) flow-cookie value.
type oidcFlowKey struct{}

// oidcFlowMiddleware reads the diyddns_oidc_flow cookie off the raw request
// (huma business handlers receive a plain context.Context, never *http.Request)
// and stashes its raw sealed value for the callback handler — the same
// humago.Unwrap → huma.WithValue pattern loginMetaMiddleware uses.
func oidcFlowMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		if c, err := r.Cookie(oidcFlowCookie); err == nil {
			ctx = huma.WithValue(ctx, oidcFlowKey{}, c.Value)
		}
		next(ctx)
	}
}

// oidcFlowCookieFrom returns the raw sealed flow-cookie value stashed by
// oidcFlowMiddleware, and whether it was present.
func oidcFlowCookieFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(oidcFlowKey{}).(string)
	return v, ok && v != ""
}
```

> **Implementer notes (resolve during coding):**
> 1. **Two `Set-Cookie` headers on success.** huma serializes one `http.Cookie` per `header:"Set-Cookie"` field. To emit BOTH the session cookie and the flow-cookie-clear on the success path, either (a) give `oidcRedirectOutput` a `SetCookies []http.Cookie` with a `header:"Set-Cookie"` tag (huma emits one header per slice element), or (b) rely on the flow cookie's short `MaxAge` and `Path` scoping and only set the session cookie on success (the flow cookie expires on its own in ≤10 min). Prefer (a) for cleanliness; (b) is acceptable. Update the struct accordingly and keep the failing-path `clear` cookie.
> 2. **Reading the request cookie is DONE** via `oidcFlowMiddleware` (above), which mirrors `loginMetaMiddleware`'s `humago.Unwrap`→`huma.WithValue` pattern and is attached to the callback op. The handler reads the raw sealed value with `oidcFlowCookieFrom(ctx)`. Never call `humago.Unwrap` on a plain `context.Context`.
> 3. `subtleMismatch(a, b)` is `subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1` — add it as a small helper (import `crypto/subtle`).
> 4. **`safeNext` needs its own test** (open-redirect defense): table cases `"//evil.com"→"/"`, `"/\\evil"→"/"`, `"https://evil"→"/"`, `"/devices"→"/devices"`, `""→"/"`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/api/oidc.go internal/server/api/api.go internal/server/api/oidc_test.go
git commit -m "feat(api): OIDC browser start/callback with sealed PKCE flow cookie"
```

---

## Task 13: Agent API ops (`/agent/v1/enroll/oidc/start` + `/poll`)

**Files:**
- Create: `internal/server/api/enroll_oidc.go`
- Modify: `internal/server/api/api.go` (add `registerEnrollOIDCOps(a, deps)` to `registerEnrollOps` — note that function is in `enroll.go`; add the call there)
- Test: `internal/server/api/enroll_oidc_test.go`

**Interfaces:**
- Consumes: `*oidc.Manager` (DeviceStart/DevicePoll), `*service.OIDCService` (LoginOrLink), `*service.EnrollmentService` (EnrollForUser), `store.OIDCDeviceFlowRepo` (via `deps.Store.OIDCDeviceFlows()`).
- Produces: two agent operations.

**Design notes:**
- `/start`: `501` if `!deps.OIDCMgr.DeviceEnabled()`. Else `DeviceStart`, persist a flow row (`flow_id = auth.RandToken(32)`, `device_code`, `interval`, `expires_at`, `last_polled_at=0`, `created_at=now`), return `{flow_id, user_code, verification_uri, verification_uri_complete, expires_in, interval}`.
- `/poll`: `TryPoll` → `410` on `ErrNotFound`; `{status:"slow_down"}` when not allowed. When allowed, `DevicePoll`; on `PollSlowDown` also `BumpInterval(+5)`; on `PollPending`/`PollSlowDown` return the status; on `PollComplete` → `LoginOrLink` → `EnrollForUser(...,"device.enroll.oidc",...)` → delete flow → `{device_id, secret}`. Reject (`LoginOrLink` error) → `401` + delete flow.
- No HMAC middleware (pre-secret), consistent with the other enroll ops.

- [ ] **Step 1: Write the failing test**

Create `internal/server/api/enroll_oidc_test.go`:

```go
func TestOIDCDeviceEnroll_StartPollComplete(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	st := newTestStore(t)
	// ... build handler with an enabled+discovered Manager (device supported), OIDC service, enrollment service ...
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// 1. start → flow_id + user_code
	var start struct{ FlowID, UserCode, VerificationURI string }
	postJSON(t, srv.URL+"/agent/v1/enroll/oidc/start", nil, &start)
	if start.FlowID == "" || start.UserCode == "" {
		t.Fatalf("start incomplete: %+v", start)
	}

	// 2. poll before approval → pending
	var p1 struct{ Status string }
	postJSON(t, srv.URL+"/agent/v1/enroll/oidc/poll", map[string]string{"flow_id": start.FlowID}, &p1)
	if p1.Status != "pending" {
		t.Fatalf("want pending, got %q", p1.Status)
	}

	// 3. approve at the IdP, advance the poll clock past interval, poll → device
	idp.ApproveDevice("test-device-code", oidctest.Claims{Subject: "dsub", Email: "dev@x.com", EmailVerified: true, Audience: "test-client"})
	// (Pace: the store's TryPoll enforces interval; the test injects the clock or waits — see note.)
	var p2 struct{ DeviceID, Secret string }
	pollUntilDevice(t, srv.URL, start.FlowID, &p2)
	if p2.DeviceID == "" || p2.Secret == "" {
		t.Fatalf("want device, got %+v", p2)
	}
}

func TestOIDCDeviceStart_501WhenUnsupported(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	// ... handler with Manager discovered against a device-less IdP ...
	resp := postRaw(t, srv.URL+"/agent/v1/enroll/oidc/start", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", resp.StatusCode)
	}
}
```

> **Helpers (Test Harness Reference):** this is `package api_test`. Use the OIDC-wired `newOIDCHarness` (from Task 12), the existing 3-arg `postJSON(t, url, body) (status, respBody)` (decode `respBody` yourself), and `doJSON` — do NOT call a 4-arg `postJSON` or invent `getJSON`/`postRaw`/`pollUntilDevice`/`buildTestAPIHandler`. Write `pollUntilDevice` as a small local loop over `postJSON` if you want one.
>
> **Pacing/time:** the guard uses store time (`store.NowUnix()`). Plan 04's `authmw.go` exposes a package `nowUnix` var — the enroll_oidc handlers should use `store.NowUnix()` directly (not that var), so to pin time either set the flow `interval` low and have the local poll loop retry across the mock's 1s interval, or (cleaner) drive `store`'s injectable clock if available. Keep the mock IdP `pollInterval` at 1 and retry for up to ~3s.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/api/ -run TestOIDCDeviceEnroll -v`
Expected: FAIL — route 404.

- [ ] **Step 3: Wire registration**

In `internal/server/api/enroll.go`, at the end of `registerEnrollOps`:
```go
	registerEnrollOIDCOps(a, deps)
```

- [ ] **Step 4: Implement the agent ops**

Create `internal/server/api/enroll_oidc.go`:

```go
package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// slowDownBumpSeconds is added to a flow's poll interval on a slow_down (RFC 8628 §3.5).
const slowDownBumpSeconds = 5

type oidcDeviceStartOutput struct {
	Body struct {
		FlowID                  string `json:"flow_id"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
}

type oidcDevicePollInput struct {
	Body struct {
		FlowID string `json:"flow_id"`
	}
}

type oidcDevicePollOutput struct {
	Body struct {
		Status   string `json:"status,omitempty"` // "pending" | "slow_down" (omitted on success)
		DeviceID string `json:"device_id,omitempty"`
		Secret   string `json:"secret,omitempty"`
	}
}

func registerEnrollOIDCOps(a huma.API, deps ServerDeps) {
	huma.Post(a, "/agent/v1/enroll/oidc/start", func(ctx context.Context, _ *struct{}) (*oidcDeviceStartOutput, error) {
		if !deps.OIDCMgr.DeviceEnabled() {
			return nil, huma.Error501NotImplemented("oidc device flow not available")
		}
		da, err := deps.OIDCMgr.DeviceStart(ctx)
		if err != nil {
			if errors.Is(err, oidc.ErrDeviceUnsupported) {
				return nil, huma.Error501NotImplemented("oidc device flow not available")
			}
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device start failed", slog.Any("error", err))
			return nil, huma.Error502BadGateway("oidc device start failed")
		}
		flowID, err := auth.RandToken(32)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow id gen failed", slog.Any("error", err))
			return nil, huma.Error500InternalServerError("internal error")
		}
		now := store.NowUnix()
		interval := da.Interval
		if interval < 5 {
			interval = 5 // design §6 default; also prevents a 0-interval disabling the pacing guard
		}
		if _, err := deps.Store.OIDCDeviceFlows().Create(ctx, store.OIDCDeviceFlow{
			FlowID:     flowID,
			DeviceCode: da.DeviceCode,
			Interval:   interval,
			ExpiresAt:  da.ExpiresAt, // absolute unix expiry from DeviceStart
			CreatedAt:  now,
		}); err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow persist failed", slog.Any("error", err))
			return nil, huma.Error500InternalServerError("internal error")
		}
		out := &oidcDeviceStartOutput{}
		out.Body.FlowID = flowID
		out.Body.UserCode = da.UserCode
		out.Body.VerificationURI = da.VerificationURI
		out.Body.VerificationURIComplete = da.VerificationURIComplete
		out.Body.ExpiresIn = da.ExpiresAt - now
		out.Body.Interval = interval
		return out, nil
	})

	huma.Post(a, "/agent/v1/enroll/oidc/poll", func(ctx context.Context, in *oidcDevicePollInput) (*oidcDevicePollOutput, error) {
		now := store.NowUnix()
		flow, allowed, err := deps.Store.OIDCDeviceFlows().TryPoll(ctx, in.Body.FlowID, now)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, huma.Error410Gone("device flow expired or unknown")
			}
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow trypoll failed", slog.Any("error", err))
			return nil, huma.Error500InternalServerError("internal error")
		}
		out := &oidcDevicePollOutput{}
		if !allowed {
			out.Body.Status = "slow_down"
			return out, nil
		}

		res, err := deps.OIDCMgr.DevicePoll(ctx, flow.DeviceCode)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device poll failed", slog.Any("error", err))
			return nil, huma.Error502BadGateway("oidc device poll failed")
		}
		switch res.Status {
		case oidc.PollPending:
			out.Body.Status = "pending"
			return out, nil
		case oidc.PollSlowDown:
			_ = deps.Store.OIDCDeviceFlows().BumpInterval(ctx, flow.FlowID, slowDownBumpSeconds)
			out.Body.Status = "slow_down"
			return out, nil
		case oidc.PollDenied:
			// Terminal: user denied or the IdP device_code expired. Drop the flow
			// and tell the agent to stop polling.
			_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
			return nil, huma.Error410Gone("device authorization denied or expired")
		case oidc.PollComplete:
			// resolve user, mint device, delete the flow (below)
		}

		user, err := deps.OIDC.LoginOrLink(ctx, deps.Cfg.OIDC.Issuer, res.Claims.Subject, res.Claims.Email, res.Claims.EmailVerified)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelInfo, "oidc device enroll rejected", slog.Any("error", err))
			_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
			return nil, huma.Error401Unauthorized("enrollment not authorized")
		}
		enr, err := deps.Enroll.EnrollForUser(ctx, user.ID, "device.enroll.oidc", service.ClientMeta{})
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device mint failed", slog.Any("error", err))
			return nil, huma.Error500InternalServerError("internal error")
		}
		_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
		out.Body.DeviceID = enr.DeviceID
		out.Body.Secret = base64.StdEncoding.EncodeToString(enr.Secret)
		return out, nil
	})
}
```

> **Implementer note:** confirm `huma.Error501NotImplemented`, `Error502BadGateway`, `Error410Gone` exist in huma v2.38.0 (they do; huma generates helpers for standard codes). If a specific helper is absent, use `huma.NewError(status, msg)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/api/enroll_oidc.go internal/server/api/enroll.go internal/server/api/enroll_oidc_test.go
git commit -m "feat(api): agent OIDC device-code enroll start/poll"
```

---

## Task 14: Capabilities dynamic

**Files:**
- Modify: `internal/server/api/capabilities.go` (add two fields; read from the manager)
- Modify: `internal/server/api/api.go` (pass `deps` to `registerCapabilities`)
- Test: `internal/server/api/capabilities_test.go`

**Interfaces:**
- Produces: `Capabilities` gains `OIDCEnabled bool` and `OIDCDeviceEnabled bool`, read from `deps.OIDCMgr`.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/api/capabilities_test.go` (or create it if absent):

```go
func TestCapabilities_ReflectsOIDCManager(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	mgr := oidc.NewManager(config.OIDCCfg{
		Enabled: true, Issuer: idp.Issuer, ClientID: "test-client", ClientSecret: "s",
		Scopes: []string{"openid"},
	}, "http://server.example", testLogger(t))
	if err := mgr.Discover(t.Context()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	// ... build handler with deps.OIDCMgr = mgr ...
	var caps struct {
		OIDCEnabled       bool `json:"oidc_enabled"`
		OIDCDeviceEnabled bool `json:"oidc_device_enabled"`
	}
	getJSON(t, srv.URL+"/agent/v1/capabilities", &caps)
	if !caps.OIDCEnabled || !caps.OIDCDeviceEnabled {
		t.Fatalf("expected both OIDC flags true, got %+v", caps)
	}
}
```

Also assert the disabled case (a manager built with `Enabled:false`, no discovery) reports both `false` without panicking.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/api/ -run TestCapabilities_ReflectsOIDC -v`
Expected: FAIL — field/JSON missing.

- [ ] **Step 3: Make capabilities dynamic**

In `internal/server/api/capabilities.go`:
```go
type Capabilities struct {
	ServerVersion     string   `json:"server_version"`
	SkewWindowSeconds int      `json:"skew_window_seconds"`
	AddressFamilies   []string `json:"address_families"`
	OIDCEnabled       bool     `json:"oidc_enabled"`
	OIDCDeviceEnabled bool     `json:"oidc_device_enabled"`
}

func registerCapabilities(a huma.API, deps ServerDeps) {
	huma.Get(a, "/agent/v1/capabilities", func(_ context.Context, _ *struct{}) (*capabilitiesOutput, error) {
		return &capabilitiesOutput{Body: Capabilities{
			ServerVersion:     deps.Info.Version,
			SkewWindowSeconds: hmacSkewWindowSeconds,
			AddressFamilies:   []string{"ipv4", "ipv6"},
			OIDCEnabled:       deps.OIDCMgr.Enabled(),
			OIDCDeviceEnabled: deps.OIDCMgr.DeviceEnabled(),
		}}, nil
	})
}
```

In `internal/server/api/api.go`, change the call in `Build`:
```go
	registerCapabilities(agentAPI, deps)
```
(from `registerCapabilities(agentAPI, deps.Info)`.)

> **Guard:** `Enabled()`/`DeviceEnabled()` are nil-receiver-safe (Task 6), so the existing `newAPIServer` harness (`api_test.go`, which sets no `OIDCMgr`) keeps working and reports both flags `false` — the existing `TestCapabilities_Response` assertion `got.OIDCEnabled == false` still holds. No harness change needed for the disabled case; the enabled case uses the OIDC-wired harness (Test Harness Reference).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/api/capabilities.go internal/server/api/api.go internal/server/api/capabilities_test.go
git commit -m "feat(api): dynamic oidc_enabled/oidc_device_enabled capabilities"
```

---

## Task 15: Server assembly + pruner sweep + client isolation guard

**Files:**
- Modify: `internal/server/server.go` (construct the Manager, decode the master key once, wire deps, discovery, RetryLoop)
- Modify: `internal/server/pruner.go` (sweep `oidc_device_flows`)
- Modify: `cmd/diyddns-client/deps_test.go` (forbid `oauth2`/`go-oidc`)
- Test: `internal/server/server_test.go` (or the existing black-box handler test), `internal/server/pruner_test.go`

**Interfaces:**
- Consumes: everything above. Produces the fully wired server.

- [ ] **Step 1: Write the failing tests**

**Replace** the existing `TestClientExcludesHuma` in `cmd/diyddns-client/deps_test.go` with an extended version (don't add a second test that re-checks huma — rename or broaden the existing one):
```go
// TestClientExcludesServerOnlyDeps asserts the client binary's transitive
// imports include none of the server-only dependencies.
func TestClientExcludesServerOnlyDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	for _, forbidden := range []string{
		"github.com/danielgtaylor/huma",
		"golang.org/x/oauth2",
		"github.com/coreos/go-oidc",
		"github.com/go-jose/go-jose",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Errorf("client binary imports server-only dependency %q", forbidden)
		}
	}
}
```

Add a pruner sweep test in `internal/server/pruner_test.go` (follow the existing pruner test if present; otherwise a small one):
```go
// package server (in-package): openTestStore + discardLog are the real helpers (pruner_test.go).
func TestPrune_SweepsOIDCDeviceFlows(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	_, _ = st.OIDCDeviceFlows().Create(ctx, store.OIDCDeviceFlow{FlowID: "old", DeviceCode: "d", Interval: 5, ExpiresAt: 1, CreatedAt: 1})
	prune(ctx, st, discardLog())
	if _, err := st.OIDCDeviceFlows().Get(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expired flow pruned, got %v", err)
	}
}
```

Add a server-level assertion that a server with OIDC enabled but an unreachable IdP still starts (degrade) — extend the existing `server_test.go` handler test: build `config.Server` with `Auth.OIDC.Enabled=true`, `Required=false`, a bogus issuer, and assert `server.Handler(...)` returns no error and `GET /agent/v1/capabilities` reports `oidc_enabled=false`. Also assert `Required=true` + bogus issuer makes `Handler` return an error.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/diyddns-client/ ./internal/server/ -run 'Excludes|OIDC|Prune' -v`
Expected: FAIL — deps not yet imported by server wiring / pruner sweep absent.

- [ ] **Step 3: Wire the server**

In `internal/server/server.go`, rename the current `Handler` to unexported `handler` returning the manager too (the exported `Handler` wrapper is added in the concrete-wiring block below):
```go
func handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *oidc.Manager, error) {
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("server: %w", err)
	}
	// ... existing verifier/sessions/audit/authSvc ...

	oidcMgr := oidc.NewManager(cfg.Auth.OIDC, cfg.Server.BaseURL, log)
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.Required {
		// Fail-closed: an operator who marked OIDC required wants the server to
		// refuse to start if the IdP is unreachable (mirrors the HMAC-key path).
		dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := oidcMgr.Discover(dctx); err != nil {
			return nil, nil, fmt.Errorf("server: oidc required but discovery failed: %w", err)
		}
	}

	oidcSvc := service.NewOIDCService(st, sessions, cfg.Auth.OIDC, audit, log)

	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		// ... existing fields ...
		OIDC:    oidcSvc,
		OIDCMgr: oidcMgr,
		HMACKey: key,
	})
	handler := middleware.Chain(mux, middleware.RequestID, middleware.AccessLog(log), middleware.Recover(log))
	return handler, oidcMgr, nil
}
```

**Concrete wiring (do exactly this — no overloads, Go has none):**
1. Rename the current exported `Handler` to an **unexported** `func handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *oidc.Manager, error)` — the body above (returns the handler AND the constructed manager).
2. Keep an **exported thin wrapper** so the existing black-box test (`server_test.go` calls `server.Handler(cfg, st, log)` and expects `(http.Handler, error)`) still compiles unchanged:
   ```go
   // Handler builds the fully-wrapped HTTP handler. (The OIDC manager it
   // constructs is only needed by New/Run, so this wrapper discards it.)
   func Handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, error) {
       h, _, err := handler(cfg, st, log)
       return h, err
   }
   ```
3. Add an `oidcMgr *oidc.Manager` field to the `Server` struct. In `New`, call `handler(...)` (not the wrapper), store the manager:
   ```go
   func New(cfg config.Server, st *store.Store, log *slog.Logger) (*Server, error) {
       h, mgr, err := handler(cfg, st, log)
       if err != nil {
           return nil, err
       }
       return &Server{httpServer: &http.Server{Addr: cfg.Server.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}, log: log, st: st, oidcMgr: mgr}, nil
   }
   ```
4. In `Run`, next to `go runPruner(ctx, s.st, s.log)`, add **unconditionally**:
   ```go
   go s.oidcMgr.RetryLoop(ctx)
   ```
   `RetryLoop` is a no-op when OIDC is disabled or already ready (from the `required` sync path), so no guard is needed.

In `internal/server/pruner.go`, add to `prune`:
```go
	flows, err := st.OIDCDeviceFlows().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune oidc_device_flows failed", slog.Any("error", err))
	}
```
and add `slog.Int("oidc_device_flows", flows)` to the summary log.

- [ ] **Step 4: Run the full suite**

Run: `go test ./... -race`
Expected: PASS across all packages.

Run: `go build ./...`
Expected: clean.

Run: `golangci-lint run`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/server/server.go internal/server/pruner.go internal/server/pruner_test.go internal/server/server_test.go cmd/diyddns-client/deps_test.go
git commit -m "feat(server): wire OIDC manager, degrade/required startup, flow pruner + client isolation"
```

---

## Self-Review

**Spec coverage** (design → task):
- Browser auth-code+PKCE (§3) → T2 (cookie seal), T7 (Manager), T12 (ops). ✓
- Agent device-code (§4) → T3 (store), T8 (Manager), T13 (ops). ✓
- Link/signup policy (§5), incl. empty-email/ErrConflict/admin-not-linked → T10. ✓
- `oidc_device_flows` + atomic pacing (§6) → T3; pruner sweep → T15. ✓
- Manager lifecycle, timeouts, degrade/required, RetryLoop, injectable backoff (§7) → T6, T9, T15. ✓
- Config `auth.oidc.*` + validation + scopes caveat (§7) → T4. ✓
- Issue #13 (§8) → T1. ✓
- Server-side logging of infra + policy rejections (§9) → T10, T12, T13 (log lines). ✓
- Mock-IdP tests (§10) → T5 + every integration task. ✓
- Two capability flags (§ D4) → T14. ✓
- Client isolation (§2) → T15. ✓
- AAD domain separation (§3) → T2, used in T12. ✓
- `EnrollForUser` over `createSealedDevice` (§4/§12) → T11. ✓

**Placeholder scan:** the `> Implementer note` blocks in T8/T12/T13/T15 flag genuine library-integration decisions (huma multi-cookie output, request access in a redirect op, server/Run manager wiring) that must be resolved against the real huma/go-oidc APIs during coding — they are NOT hand-waved logic; the surrounding code is complete. Every code step shows real code. No "TODO"/"add error handling"/"similar to Task N".

**Type consistency:** `oidc.Claims{Subject,Email,EmailVerified}` is produced in T7 and consumed in T10/T13. `oidc.PollStatus`/`PollResult` produced T8, consumed T13. `store.OIDCDeviceFlow` + repo methods produced T3, consumed T13/T15. `service.OIDCService.LoginOrLink`/`BrowserLogin` produced T10, consumed T12/T13. `EnrollForUser(ctx, userID, eventType, meta)` produced T11, consumed T13. `ServerDeps.{OIDC,OIDCMgr,HMACKey}` added T12, consumed T13/T14/T15. `Manager.{Enabled,DeviceEnabled,BeginAuth,CompleteAuth,DeviceStart,DevicePoll,Discover,RetryLoop}` — signatures consistent across T6–T9 and their consumers. Names verified consistent.

**Known integration risks flagged for the executor** (not blockers — resolve in-task against live APIs):
1. huma emitting two `Set-Cookie` headers on the OIDC success path (T12 note 1).
2. Reading the flow cookie inside a huma middleware via `humago.Unwrap`, not on a bare context (T12 note 2).
3. `oauth2.DeviceAuthResponse.Expiry`/`Interval` field types + `S256ChallengeOption`/`VerifierOption`/`oidc.Nonce` availability at the pinned versions (T7/T8) — verified present per the design's Context7 check; re-confirm on `go get`.
4. `server.Run` obtaining the `*oidc.Manager` to launch `RetryLoop` — now spelled out concretely in T15 (unexported `handler` returns the manager; exported `Handler` wraps).

---

## Review provenance

- **Self-review** (2026-07-13): spec coverage, placeholder scan, type consistency (above).
- **sr-go-engineer review** (Fable, 2026-07-13, verdict AMEND-BEFORE-EXECUTION): all Critical + Important folded in —
  - **C1** nil-receiver-safe `Manager.Enabled/DeviceEnabled` (T6) so the existing `newAPIServer` harness doesn't nil-panic (T14).
  - **C2/C3** every test now names the REAL helpers per package (added the **Test Harness Reference** table): store `newTestStore` returns `(*Store, ctx)`; service/server/auth tests are in-package using `openTestStore`/`discardLogger`/`discardLog`/`testPasswordCfg`; api tests use `postJSON`(3-arg)/`doJSON`/`findCookie` and extend `newFullHarness`; devices method is `GetByID`.
  - **C4** replaced the non-existent `huma.WithContext` with a real `oidcFlowMiddleware` (humago.Unwrap→huma.WithValue) + `oidcFlowCookieFrom`; fixed the `mgr.Config()` test line.
  - **I1** `access_denied`/`expired_token` → terminal `PollDenied` (T8) → T13 deletes the flow + `410`.
  - **I2** `OIDCService` gained a logger; every policy reject logs its specific reason (design §9).
  - **I3** device-flow `interval` floored at 5 (T13) so a 0-interval can't disable the pacing guard.
  - **I4** one concrete `handler`/`Handler`/`New`/`Run` wiring for the manager + `RetryLoop` (T15).
  - Minors: `DeviceAuth.ExpiresAt` (absolute) + zero-expiry fallback; dropped dead `oauth2` import/`var _`; removed the unimplemented `StageDevice`/`deviceUser`; extend the existing client-isolation test rather than duplicate it; `safeNext` gets its own table test.
  - Confirmed solid by the reviewer: library-API composition (go-oidc `Endpoint().DeviceAuthURL`, oauth2 PKCE helpers, huma error/cookie helpers), `TryPoll` SQL + pacing math, the issue-#13 fix, the AAD test, T10 policy, and the T1–T13 compile-order/dep-add sequencing.
