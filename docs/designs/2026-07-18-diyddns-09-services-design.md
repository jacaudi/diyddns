# DIYDDNS Plan 09 — Services (device management + admin) — Design

- **Date:** 2026-07-18
- **Type:** Design
- **Status:** Approved (pending final spec read)
- **Parent spec:** `docs/plans/2026-05-01-diyddns-design.md` (§3 data model, §4 API surface, §5 auth model)
- **Builds on:** Plan 04 auth machinery (`docs/designs/2026-07-12-diyddns-04-auth-machinery-design.md`)

---

## 1. Purpose & Scope

The **Services plan** delivers the server-side device-management and administration
surface that was explicitly deferred out of Plan 04 ("device CRUD/rotate/history +
admin/users/audit/server → Services plan"). It **unblocks the Web UI plan** (the UI
needs these endpoints to display and manage devices, users, and audit history) and
**completes the `/api/v1` OpenAPI surface**.

It has **no prerequisites** — Plans 01–08 are all merged (`origin/main` @ `537434e`).

### Guiding property: purely additive over existing seams

This plan introduces **no schema migration and no new persistence subsystem**. Every
capability it exposes already exists in the store layer (`DeviceRepo.Rename` /
`SetDisabled` / `Delete` / `RotateSecret` / `ListAll`, `UserRepo.Update` /
`SetDisabled` / `Delete` / `List`, `AuditLogRepo.ListPaginated`, `IPHistoryRepo.Page`,
`SessionRepo.DeleteByUser`). The work is: new **service methods** + new **huma ops**
over those repos, plus exactly two small new seams (an admin-gate middleware and a
`Verifier` cache-eviction method).

### In scope

- Device management (user-scope): `PATCH` (rename / enable-disable), `DELETE`,
  `POST /rotate-secret`, `GET /history`.
- Admin (admin-role): users list/create/patch/delete, all-devices list, audit-log
  search, server-info (`GET` only).
- Two new seams: `adminMiddleware` and `Verifier.Invalidate(deviceID)`.

### Out of scope (deferred — see §9)

`PATCH /api/v1/admin/server` and all live-tunable settings; `hide_local_login_ui`;
"force password reset on next login" as a flag; HMAC master-key rotation; issue #27
(`/agent/v1` wire-DTO consolidation); issue #11 (`CheckinService.audit` field).

---

## 2. Decisions

- **D1 — Full Services plan in one pass.** Device-management vertical *and* admin
  vertical ship together. They reuse the same middleware and DTO patterns, are all
  additive, and shipping both fully unblocks the Web UI plan and completes the
  OpenAPI surface. (~11 new ops.)

- **D2 — `rotate-secret` is in-place re-seal, plaintext returned once.** The server
  mints a fresh HMAC secret, AES-256-GCM-seals it into `devices.secret_hash`, evicts
  the in-memory secret cache, and returns the plaintext exactly once. The device keeps
  the same `device_id` and its full IP history; the operator reconfigures the client's
  `credentials.json`. This **supersedes the parent spec §4 wording** ("New enrollment
  code, invalidates old secret" — a re-enrollment model), because the in-place model
  reuses the Plan 04 `SealSecret` + secret-cache machinery, keeps one device row, and
  avoids the re-enrollment model's need to rebind an enrollment code to an existing
  device (the current `enroll/code` flow mints a *new* device). The parent spec §4
  row and §6 client `rotate` note should be reconciled to the in-place model when the
  client `rotate` vertical is built.

- **D3 — `admin/server` is `GET`-only; `PATCH`/live-settings deferred.** `GET`
  server-info reads from existing `config` + `version.Info` (zero new persistence).
  `PATCH`/live-tunable settings (retention days, `hide_local_login_ui`) would require a
  new settings-persistence subsystem and file-vs-DB precedence rules, which are outside
  this plan's reuse-existing-seams shape. `hide_local_login_ui` is already allocated to
  the Web UI plan (Plan 05 D3).

- **D4 — New `adminMiddleware` gates on `Role == "admin"`.** No admin/role-check
  middleware exists today. Add one that runs after `sessionMiddleware`, reads
  `UserFrom(ctx).Role == "admin"`, and returns `403` otherwise. Follows the only
  existing role convention (`BootstrapService`'s `Role == "admin"` check).

- **D5 — Owner-scope foreign access returns 404, not 403.** Owner-scoped device ops on
  a device owned by another user return `404 Not Found`, matching the existing
  `DeviceService.Get` behavior (foreign owner → `store.ErrNotFound`). Avoids leaking
  device existence across users.

- **D6 — Admin user-management guards.** The admin user endpoints enforce:
  cannot demote / disable / delete the **last remaining admin**; cannot disable or
  delete **your own account**; disabling (and deleting) a user **revokes their
  sessions**. See §5.

- **D7 — Password is the *local* credential only.** `POST /admin/users` creates a
  *local* user (password required). `PATCH` password-reset sets/replaces the local
  argon2id credential and is permitted **only on accounts that already have a local
  password**. On an OIDC-only account (no `password_hash`) it returns `409` — admins
  may still role-change / disable / delete OIDC accounts, but not graft a local
  password onto them (respects OIDC-only intent; avoids a local login path that would
  survive `hide_local_login_ui`).

- **D8 — DELETE cascade is the existing schema FK behavior.** No new logic: deleting a
  device cascade-removes its `ip_history` (`ON DELETE CASCADE`) and SET-NULLs the
  consumed enrollment code's `device_id` (`ON DELETE SET NULL`, code row survives for
  audit). Deleting a user cascades sessions + devices + codes. Pinned by
  `internal/store/device_delete_fk_test.go`.

---

## 3. Endpoint set & auth

All ops register on the existing **`apiAPI`** (`/api` group) via a new
`registerServicesOps(a huma.API, deps ServerDeps)` file wired with one line in
`api.Build`. Auth column: **S** = session, **C** = CSRF (mutations only), **A** =
admin role.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PATCH`  | `/api/v1/devices/{id}` | S+C | Rename (label) and/or enable/disable — owner-scoped |
| `DELETE` | `/api/v1/devices/{id}` | S+C | Delete device (cascades history; code → NULL) |
| `POST`   | `/api/v1/devices/{id}/rotate-secret` | S+C | New secret, re-seal, evict cache, return plaintext once |
| `GET`    | `/api/v1/devices/{id}/history` | S | Cursor-paginated IP history |
| `GET`    | `/api/v1/admin/users` | S+A | List users |
| `POST`   | `/api/v1/admin/users` | S+A+C | Create local user `{email, password, role}` |
| `PATCH`  | `/api/v1/admin/users/{id}` | S+A+C | Set role / enable-disable / reset local password |
| `DELETE` | `/api/v1/admin/users/{id}` | S+A+C | Delete user (cascades) |
| `GET`    | `/api/v1/admin/devices` | S+A | List all devices (cross-user) |
| `GET`    | `/api/v1/admin/audit` | S+A | Audit-log search (cursor-paginated) |
| `GET`    | `/api/v1/admin/server` | S+A | Server info: version, OIDC (sans secret), HMAC skew, session cookie (see §5 — no retention/TLS in config yet) |

The existing Plan 04 device ops (`GET`/`POST` `/api/v1/devices`, `GET
/api/v1/devices/{id}`) stay unchanged.

### Middleware chains

Built from the existing `sessionMiddleware` / `csrfMiddleware` plus the new
`adminMiddleware`, composed per-op via `huma.Operation.Middlewares`:

- Owner read (`GET history`): `session`
- Owner mutation (`PATCH`/`DELETE`/`rotate`): `session → csrf`
- Admin read (`GET users`/`devices`/`audit`/`server`): `session → admin`
- Admin mutation (`POST`/`PATCH`/`DELETE users`): `session → admin → csrf`

`adminMiddleware` must run after `sessionMiddleware` (needs `UserFrom(ctx)`); `csrf`
must run after `session` (needs `SessionFrom(ctx).CSRFToken`).

---

## 4. Device-management vertical

Extends the thin `DeviceService` (`internal/server/service/device.go`, currently
`List`/`Get` only) with owner-scoped mutation methods. All resolve ownership first
(foreign owner → `store.ErrNotFound` → 404, per D5).

### PATCH `/api/v1/devices/{id}`

Body `{label?: string, disabled?: bool}`, both optional (a `*bool` / presence-aware
shape so "not supplied" differs from "set false").

- Rename → `DeviceRepo.Rename(id, label)`; `store.ErrConflict` on `UNIQUE(user_id,
  label)` → `409`. Audit `device.renamed`.
- Enable/disable → `DeviceRepo.SetDisabled(id, disabled)`. Audit `device.disabled` /
  `device.enabled`.

**Disable is honored live with no cache eviction.** `Verifier.Verify` looks up the
device row and checks `disabled` on every check-in, so toggling `disabled` takes
effect immediately; only a secret *value* change (rotate) requires cache eviction.

### DELETE `/api/v1/devices/{id}`

`DeviceRepo.Delete(id)`. FK cascade (D8) removes `ip_history`; the consumed enrollment
code survives with `device_id = NULL`. Audit `device.deleted`.

### POST `/api/v1/devices/{id}/rotate-secret`

The one endpoint with a real seam gap. The `Verifier` cache is **populate-only** today
(`internal/auth/hmac.go`: *"populate-only in Plan 04 — secrets never rotate here"*),
so rotation needs a new eviction method or the stale decrypted secret keeps
authenticating.

Flow (in `DeviceService.RotateSecret`):

1. Resolve ownership (foreign → 404).
2. `secret := auth.GenerateSecret()` — 32 fresh random bytes.
3. `sealed := auth.SealSecret(s.key, secret)` — re-seal under the master key.
4. `DeviceRepo.RotateSecret(id, sealed)`.
5. **`s.invalidator.Invalidate(id)`** — new seam; evicts `cache[id]`.
6. Audit `device.secret.rotated`.
7. Return `{secret: base64(secret)}` **once** (reuses the enroll response shape).

`DeviceService` gains a `key []byte` field (mirrors `EnrollmentService`) and a narrow
`SecretCacheInvalidator interface { Invalidate(deviceID string) }` dependency,
satisfied by `*auth.Verifier` — keeps the service decoupled and unit-testable.

**New method** `Verifier.Invalidate(deviceID string)`
(`internal/auth/hmac.go`): `v.mu.Lock(); delete(v.cache, deviceID); v.mu.Unlock()`.

### GET `/api/v1/devices/{id}/history`

`IPHistoryRepo.Page(deviceID, cursor, limit)`. Query params `cursor` (opaque),
`limit` (default 50, max 500 — the repo already clamps). Response
`{rows: [...], next_cursor: string}` (empty `next_cursor` = end). Reuses the existing
base64 keyset cursor idiom verbatim.

---

## 5. Admin vertical

New `AdminService` (`internal/server/service/admin.go`) holds the guarded
user-management logic and the audit read. It depends on `store.Store`, the existing
argon2id password hasher, `SessionRepo` (for revocation), and the shared `AuditSink`.

### GET `/api/v1/admin/users`

`UserRepo.List()` (ordered `email ASC`). Response is a non-secret projection (drops
`PasswordHash`; `oidc_provider`/`oidc_subject` may be surfaced as booleans/opaque).

### POST `/api/v1/admin/users`

Body `{email, password, role}` (`role ∈ {admin, user}`). Hash the password with the
existing argon2id hasher (the one used by `BootstrapService` / `AuthService`);
`UserRepo.Create` (409 on email conflict). Creates a *local* account (no OIDC linkage).
Audit `user.created`.

### PATCH `/api/v1/admin/users/{id}`

Body `{role?, disabled?, password?}`, all optional.

- `role` → `UserRepo.Update` with the new role. Audit `user.role_change`.
- `disabled` → `UserRepo.SetDisabled`; on disable, revoke sessions via
  `SessionRepo.DeleteByUser`. Audit `user.disabled` / `user.enabled` (+
  `session.revoked` when sessions were revoked).
- `password` → set the local credential; **permitted only if the target already has a
  local password** (D7). On an OIDC-only account (empty `PasswordHash`), return `409`
  ("user is OIDC-managed; no local password").

**Guards (D6), evaluated before mutating, audited on rejection where meaningful:**

- **Last-admin guard** — reject (`409`) a change that would remove the final admin:
  demoting the only admin's role, or disabling/deleting the only admin. Admin count via
  `UserRepo.List()` filtered on `Role == "admin"` and not `disabled` (bootstrap's
  pattern).
- **Self-lockout guard** — reject (`409`/`400`) disabling or deleting *your own*
  account (`UserFrom(ctx).ID == target`). Self role-change is likewise blocked for
  admins (an admin cannot demote themselves — subsumed by last-admin when solo, but
  blocked explicitly for clarity).

### DELETE `/api/v1/admin/users/{id}`

Subject to the last-admin and self-lockout guards. `UserRepo.Delete(id)` — FK cascade
removes sessions + devices + codes (D8). Audit `user.deleted`.

### GET `/api/v1/admin/devices`

`DeviceRepo.ListAll()` (already ordered `created_at DESC` — the "admin view"). Uses an
admin device projection that extends the non-secret `deviceView` with `user_id` (so the
UI can group devices by owner); it still drops `SecretHash`. Owner *email* is not
joined in v1 (the UI resolves it from the users list) to keep the store query unchanged.

### GET `/api/v1/admin/audit`

`AuditLogRepo.ListPaginated(filter, cursor, limit)` with query filters
`{actor_user_id?, event_type?, since?, until?}` (AND-combined; zero = ignored). Response
`{rows, next_cursor}`; default 100, max 500 (repo clamps). Reuses the base64 keyset
cursor.

### GET `/api/v1/admin/server`

Assembled in-handler (pure read — no service needed) from `deps.Cfg` (`config.Auth`) +
`deps.Info` (`version.Info`). Surfaces exactly what the current config exposes:
`version` / `commit` / `date`; OIDC `enabled` / `required` / `issuer` / `client_id` /
`scopes` / `auto_link_by_email` / `allow_oidc_signup` (**never `client_secret`**); HMAC
`skew_window`; session cookie `name` / `secure` / `samesite`.

**Retention days and TLS mode are intentionally omitted** — neither exists as a config
field today (`config.Auth` has no retention knob; TLS is handled by a reverse proxy per
parent spec §8). They arrive with the deferred `PATCH admin/server` settings work. (The
§3 table row's "retention, TLS mode" wording is superseded by this paragraph.)

---

## 6. Seams — reused vs. new

**Reused, unchanged:**

- `api.Build` / `ServerDeps` wiring; ops register as `func(a huma.API, deps
  ServerDeps)` + one call line in `Build`.
- `sessionMiddleware`, `csrfMiddleware`, `UserFrom`, `SessionFrom` (`authmw.go`).
- `AuditSink` / `NewAuditWriter` (`service/enrollment.go`) — the shared audit seam
  every service takes.
- Base64 keyset cursor idiom (`ip_history.go`, `audit_log.go`).
- All store repos (`Devices`, `Users`, `Sessions`, `AuditLog`, `IPHistory`,
  `EnrollmentCodes`).
- `auth.GenerateSecret`, `auth.SealSecret`; the argon2id password hasher.
- Non-secret `deviceView` projection + `newDeviceView` (`api/devices.go`).

**New (small, localized):**

| Seam | Location | What |
|---|---|---|
| `Verifier.Invalidate(deviceID)` | `internal/auth/hmac.go` | Evict `cache[deviceID]` under lock |
| `adminMiddleware(api)` | `internal/server/api/authmw.go` | `403` unless `UserFrom(ctx).Role == "admin"` |
| `DeviceService` extensions | `internal/server/service/device.go` | `Rename`, `SetEnabled`, `Delete`, `RotateSecret`, `History` (+ `key`, `invalidator` deps) |
| `AdminService` | `internal/server/service/admin.go` (new) | User CRUD + guards + session revocation + `ListAudit` |
| `registerServicesOps` | `internal/server/api/services.go` (new) | The 11 ops above; one line added to `Build` |
| `ServerDeps.Admin` | `internal/server/api/api.go` | Wire the new `AdminService` (Device stays on existing `Devices` field) |

---

## 7. Error model & conventions

huma RFC-7807 problem responses throughout:

- `store.ErrNotFound` / foreign-owner → `404`.
- `store.ErrConflict` (dup label, dup email) → `409`.
- Guard violations (last-admin, self-lockout, OIDC-password) → `409`.
- Admin gate → `403`; missing/invalid session → `401`; missing/invalid CSRF → `403`.
- Body validation → `422` (huma default).

Pagination everywhere is cursor-based `{rows, next_cursor}` (empty `next_cursor` =
end), reusing the existing opaque base64 `(timestamp, id)` keyset cursor.

---

## 8. Audit events

Reuses the parent spec's event vocabulary (§3), emitted via the shared `AuditSink`:

`device.renamed`, `device.disabled`, `device.enabled`, `device.deleted`,
`device.secret.rotated`, `user.created`, `user.role_change`, `user.disabled`,
`user.enabled`, `user.deleted`, `session.revoked`.

---

## 9. Out of scope / deferred (explicit)

- **`PATCH /api/v1/admin/server`** + all live-tunable settings — needs a
  settings-persistence subsystem + config precedence rules (D3). Future plan.
- **`hide_local_login_ui`** — allocated to the Web UI plan (Plan 05 D3).
- **"Force password reset on next login" flag** — needs a new `users` column
  (`must_change_password`); v1 does admin-set-password only. Future work.
- **HMAC master-key rotation** (re-sealing every stored secret) — already documented
  out-of-scope in parent spec §5A.
- **Issue #27** (`/agent/v1` client/shared wire-DTO consolidation) — **does not belong
  here.** Services adds *browser* `/api` DTOs and never touches the `/agent` wire DTOs
  shared with the client. It fits a plan that edits `/agent` (e.g. a client vertical),
  not this one.
- **Issue #11** (`CheckinService.audit` unused field) — Services does not touch
  `CheckinService`; leave for a separate trivial KISS cleanup.

---

## 10. Testing

TDD per task, `go test ./... -race`, `golangci-lint` clean, client-isolation guard
(`cmd/diyddns-client/deps_test.go`) stays green (all changes are server-side).

Store methods already have coverage. New tests:

- **Service unit tests** — guards and boundaries: last-admin rejection,
  self-lockout rejection, foreign-owner → `ErrNotFound`, OIDC-only password → conflict,
  rotate re-seals + evicts (assert the *old* secret no longer verifies after rotate —
  mutation-checked so a missing `Invalidate` call fails the test).
- **huma op tests** — the auth matrix per op: missing session → `401`, non-admin on an
  admin op → `403`, missing CSRF on a mutation → `403`; rotate returns the secret
  exactly once; pagination `next_cursor` round-trips.
- **`Verifier.Invalidate`** — a focused unit test that a cached secret is gone after
  `Invalidate` and re-populates on next `Verify` from the new sealed value.

---

## 11. Execution workflow

> **For Claude:** REQUIRED EXECUTION WORKFLOW (the implementation plan will carry this
> block; recorded here for continuity):
> 1. `superpowers:using-git-worktrees` — isolate work in a dedicated worktree.
> 2. `superpowers:subagent-driven-development` — fresh subagent per task.
> 3. `superpowers:test-driven-development` — all subagents use TDD.
> 4. `superpowers:verification-before-completion` — verify tests pass per task.
> 5. `superpowers:requesting-code-review` — per-task review (built in).
> 6. After all tasks: independent whole-branch review on the full diff from branch point.
> 7. `superpowers:finishing-a-development-branch` — complete the branch.
>
> Skills carry their own model and effort settings. Do not override them.

Next step after this design is approved: `superpowers:writing-plans` →
`docs/plans/2026-07-18-diyddns-09-services-implementation.md`.
