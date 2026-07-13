# DIYDDNS Plan 04 — Auth Machinery & Agent Device-Auth Vertical (Design)

- **Date:** 2026-07-12
- **Type:** Design
- **Status:** Draft — SGE-reviewed 2026-07-12 (AMEND-BEFORE-PLANNING; findings folded); pending user approval
- **Parent spec:** [docs/plans/2026-05-01-diyddns-design.md](../plans/2026-05-01-diyddns-design.md) — §3 (schema), §4 (API surface), §5 (auth model), §10 (security), §11 (boundaries)
- **Builds on:** Plan 02 (merged) — `internal/store` repositories; Plan 03 (merged) — server skeleton, two huma APIs, net/http middleware chain, `/agent/v1/capabilities`.

---

## 1. Purpose & Scope

Plan 04 adds the **authentication layer** the Plan 03 skeleton was built to receive, plus the
minimal agent endpoints required to exercise it end to end. It delivers device→server HMAC
auth, browser cookie-sessions + CSRF, argon2id local passwords, the bootstrap-admin flow, and
the agent device-auth vertical (enroll → checkin → self), so a device can register and report
its IP through a fully authenticated path.

It attaches at the seams Plan 03 documented (§8 of the Plan 03 design) **additively** — new
packages and new files under `internal/server/api`, no rewrite of skeleton code.

### In scope

- `internal/shared` — HMAC wire contract (header names, canonical signing input, body hash,
  sign) — stdlib only; the future client reuses it.
- `internal/auth` — HMAC `Verifier` (+ in-memory secret cache), `SessionManager` + CSRF,
  argon2id password hashing, AEAD secret sealing, secret generation.
- `internal/server/service` — enrollment, device (list/get), checkin, auth (login/logout/
  me/password), bootstrap services; audit logging woven in.
- `internal/server/api` — new operation files (enroll, checkin, devices, auth, bootstrap) and
  the huma HMAC / session / CSRF middleware.
- `internal/config` — new `Auth` section (session, hmac, password, bootstrap).
- `internal/server` — construct the `Verifier` + services, run `BootstrapService.Startup`,
  start a minimal background pruner.
- Endpoints: `POST /agent/v1/enroll/code`, `POST /agent/v1/enroll/credentials`,
  `POST /agent/v1/checkin` (HMAC), `GET /agent/v1/self` (HMAC);
  `POST /api/v1/auth/{login,logout,password,bootstrap}`, `GET /api/v1/auth/me`,
  `POST /api/v1/devices` (mint enrollment code), `GET /api/v1/devices`,
  `GET /api/v1/devices/{id}`.

### Out of scope (deferred, named)

| Deferred capability | Owning plan |
|---|---|
| OIDC (browser PKCE + agent RFC 8628 device-code, auto-link policy) | **Plan 05** |
| Device PATCH/DELETE/rotate-secret/history; admin/users; admin/audit; admin/server | **Services plan** |
| General rate-limiting middleware (per-IP enroll/login, per-device checkin) | **Hardening plan** (see §9 — documented risk) |
| Web UI embed + SPA fallback | UI plan |
| TLS `cert`/`acme` modes | Deploy/TLS plan |

---

## 2. Decisions locked (this session) & deviations from the parent spec

Four scope/architecture decisions were made with the user:

1. **Scope** = auth machinery **+** the agent device-auth vertical (not machinery-only; not
   full-incl-OIDC). OIDC → Plan 05.
2. **Device endpoints** = mint + read only (`POST`/`GET`/`GET{id}`). CRUD/rotate/history → Services.
3. **Rate-limiting** = deferred to the Hardening plan; risk documented (§9).
4. **HMAC secret at rest** = AEAD-encrypted (see deviation D1).

### Deviations from the approved parent spec (require the spec to be amended)

- **D1 — HMAC secret stored AEAD-encrypted, not argon2id (§3, §5A, §10).**
  The parent spec stores `devices.secret_hash = argon2id(secret)`. This is **cryptographically
  unworkable**: HMAC-SHA256 verification requires the *recoverable* secret bytes, and argon2id
  is one-way — the server could never recompute the signature, and the in-memory
  "`device_id → secret bytes`" cache could never repopulate after a restart (plaintext gone,
  hash irreversible). Resolution: store `base64(AEAD(secret))` (AES-256-GCM, P2) in the
  **existing** `secret_hash TEXT NOT NULL` column — **no schema change** — with a 32-byte
  server master key from config `auth.hmac.secret_key` (`${file:}`/`${env:}`). Cold-storage
  protection is preserved: a DB copy without the master key yields nothing. argon2id remains
  correct for **passwords** (§5B) and the **bootstrap token** (§5C) — values verified against
  a user-supplied candidate, never recovered. **Master-key operational note:** the key is a
  single point of both compromise and failure for *all* device secrets — key loss ⇒ every device
  must re-enroll (documented recovery, not automated); key **rotation** (re-sealing every stored
  secret under a new key) is a named, out-of-scope follow-up.

- **D2 — In-memory secret cache repopulates by decrypting the stored ciphertext** (not by a
  "one-time argon2id verify"). Refinement of §5A step 4 consequent to D1.

- **D3 — HMAC verify ordering:** verify the signature **before** inserting the replay nonce,
  so forged/invalid requests never write to `replay_nonces`. Refinement of §5A steps 3–5.

- **D4 — New config key `auth.hmac.secret_key`** (32-byte AEAD master key). Additive to §8.

These will be folded back into the parent spec (§3 comment, §5A, §10, §8) as part of Plan 04.

---

## 3. Architecture

### 3.1 Package layout (additive)

```
internal/shared/                NEW — HMAC wire contract; stdlib only; imported by server now, client later
internal/auth/                  NEW — password.go, secret.go, hmac.go, session.go
internal/server/service/        NEW — enrollment.go, device.go, checkin.go, auth.go, bootstrap.go
internal/server/api/            +  — enroll.go, checkin.go, devices.go, auth.go, bootstrap.go, authmw.go
internal/config/                ~  — Auth section added (additive struct growth)
internal/server/                ~  — New()/Handler() wire Verifier+services; Startup(bootstrap); pruner
```

`internal/shared` is created now because the canonical signing-input format and the
`X-Diyddns-*` header names are an **external contract** that the server's `Verify` consumes
**today** and the future client will reuse — single-sourcing it (DRY, external-contract tier)
in the one package both binaries import (parent spec §2, §11) is correct, not speculative.

### 3.2 Middleware mechanism — huma per-operation

HMAC, session, and CSRF checks are **huma per-operation middleware** (`func(huma.Context,
func(huma.Context))`): they read typed headers/cookies via `huma.Context`, return huma RFC 7807
errors, and attach to exactly the operations that need them — satisfying the Plan 03 seam's
"HMAC is per-operation, not a blanket group." `capabilities`, `enroll/*`, `login`, and
`bootstrap` are **not** HMAC/session-guarded.

The HMAC middleware needs the raw body for `SHA256(BODY)`. It buffers via
`io.ReadAll(ctx.BodyReader())`, verifies, and restores the body so the handler's input parsing
re-reads it.

> **CONFIRMED against huma v2.38.0** (SGE review, verified in module source): per-operation
> middleware is native (`huma.Operation.Middlewares`); body buffer+restore works with
> `r, _ := humago.Unwrap(ctx)` then, after the read, `r.Body = io.NopCloser(bytes.NewReader(buf))`
> (the context reads `c.r.Body` live, so the restore is visible to huma's later body parse); the
> authenticated `device_id` passes forward via `huma.WithValue(ctx, key, id)`; middleware errors
> emit RFC 7807 via `huma.WriteErr` (no partial writes). The net/http fallback is a backstop and
> should not be needed.
>
> **Body-size cap (REQUIRED — pre-auth DoS defense):** the middleware buffers the body *before*
> the signature is verified, so the read MUST be bounded — wrap with `http.MaxBytesReader` /
> `io.LimitReader` at a small limit (checkin bodies are a few hundred bytes) and reject oversize
> with **413** before reading fully. Otherwise an unauthenticated attacker can OOM the server with
> a giant body. `GET /agent/v1/self` carries no body (hash of "").

---

## 4. Components

### 4.1 `internal/shared` — HMAC wire contract (stdlib only)

```go
const (
    HeaderDevice    = "X-Diyddns-Device"
    HeaderTimestamp = "X-Diyddns-Timestamp"
    HeaderNonce     = "X-Diyddns-Nonce"
    HeaderSignature = "X-Diyddns-Signature"
)

// BodyHashHex returns lowercase-hex SHA256(body); empty body hashes "".
func BodyHashHex(body []byte) string

// CanonicalRequest builds the newline-joined (LF) signing input:
// METHOD\nPATH\nTIMESTAMP\nNONCE\nBODYHASH
func CanonicalRequest(method, path, timestamp, nonce, bodyHashHex string) string

// Sign returns lowercase-hex HMAC-SHA256(secret, canonical).
func Sign(secret []byte, canonical string) string
```

Pure, deterministic, table-tested to 100%. Both signer (future client) and verifier (server)
call the same builder — one source of truth for the wire format.

### 4.2 `internal/auth`

```go
// password.go — argon2id (params from config: time, memoryKiB, parallelism; min length enforced by caller)
func HashPassword(pw string, p Argon2Params) (string, error)   // encoded PHC string incl. salt
func VerifyPassword(encoded, pw string) (bool, error)

// secret.go — device HMAC secret lifecycle (AEAD at rest, D1)
func GenerateSecret() ([]byte, error)                          // 32 random bytes
func SealSecret(key, secret []byte) (string, error)            // base64(AES-256-GCM: nonce||ct), P2
func OpenSecret(key []byte, sealed string) ([]byte, error)

// hmac.go
type Verifier struct { /* key []byte; skew time.Duration; devices; users; nonces; cache */ }
func NewVerifier(devices DeviceReader, users UserReader, nonces NonceStore, key []byte, skew time.Duration) *Verifier
// Verify authenticates one agent request; returns the device_id on success.
func (v *Verifier) Verify(ctx context.Context, p RequestParts, now int64) (string, error)
// (No Evict method in Plan 04 — the cache is populate-only, see below. The Services plan adds
//  Evict alongside its first caller: rotate/disable/delete. YAGNI: no uncalled exported method now.)

// session.go
type SessionManager struct { /* sessions; users; ttl; slideWindow */ }
func (m *SessionManager) Create(ctx, userID, ip, ua string) (Session, error)   // mints id + rotated csrf
func (m *SessionManager) Authenticate(ctx, sessionID string) (User, Session, error) // + slide expiry
func (m *SessionManager) Destroy(ctx, sessionID string) error
func GenerateCSRFToken() (string, error)
```

Consumer-declared interfaces (`DeviceReader`, `UserReader`, `NonceStore`) are satisfied by the
`internal/store` repos — `internal/auth` depends on the store via narrow interfaces, not
concrete types (parent spec §11: "communication via interfaces declared by the consumer").

The secret **cache** is a `map[string][]byte` + `sync.RWMutex`. **Populate-only in Plan 04:**
secrets never change (rotate deferred), device disable is checked live from the DB each request,
and delete is deferred — so no invalidation is needed. The cache struct itself is the seam; the
`Evict` method lands in the Services plan with its first caller.

**`Verifier.Verify` steps** (D3 ordering):
1. Parse `RequestParts` (device, timestamp, nonce, signature, method, path, body).
2. Load device (`GetByID`); reject on not-found / `device.Disabled`. Load owner
   (`Users.GetByID`); reject on `user.Disabled`.
3. Skew: reject if `|now − ts| > skew` (120 s).
4. Secret: cache hit → bytes; miss → `OpenSecret(key, device.secret_hash)` → cache.
5. `expected = shared.Sign(secret, shared.CanonicalRequest(...))`; **constant-time compare**
   (`hmac.Equal`) to the provided signature; reject on mismatch.
6. `nonces.Insert(signature, ts + nonceTTL)`; `ErrConflict` ⇒ replay ⇒ reject.
7. Return `device.ID`. (IP/`last_seen_at` updates belong to `CheckinService`, not the verifier.)

### 4.3 `internal/server/service`

- **`EnrollmentService`**
  - `CreateCode(ctx, userID, label) (code string, expiresAt int64, err error)` — random URL-safe
    code, TTL from config; `EnrollmentCodes.Create`. (Backs `POST /api/v1/devices`.)
  - `ConsumeCode(ctx, code string, meta ClientMeta) (deviceID string, secret []byte, err error)` —
    `EnrollmentCodes.Get` + validate (unused, unexpired) → `GenerateSecret` → `SealSecret` →
    `Devices.Create` (label + user from the code) → `EnrollmentCodes.Consume(code, device.ID, now)`;
    on `Consume` failure (race/expiry) **compensating-delete** the device and return the error.
    Returns the plaintext secret (shown once).
  - `EnrollCredentials(ctx, email, pw string, meta ClientMeta) (deviceID, secret, err)` —
    `Users.GetByEmail` + `VerifyPassword` (+ not-disabled) → generate/seal secret →
    `Devices.Create` (label derived from `meta.Hostname`/default). No code required.
- **`DeviceService`** — `List(ctx, userID)`, `Get(ctx, userID, id)` (ownership-checked).
- **`CheckinService`** — `Checkin(ctx, deviceID, report)` → `Devices.UpdateIP` + append
  `ip_history` **only when v4/v6 changed** (compare to current row) →
  `{device_id, current_ipv4, current_ipv6, stored}` (parent §4 response shape);
  `Self(ctx, deviceID)` → device view.
- **`AuthService`** — `Login` (uniform *invalid credentials* 401 with **constant-time behavior**:
  on unknown email, run a dummy argon2id verify against a fixed decoy hash so hit and miss cost
  the same — no user-enumeration timing oracle; the `user.login.failed` audit is identical for
  both), `Logout`, `Me`, `ChangePassword` (verify old → hash new → `Users.Update`).
- **`BootstrapService`** — `Startup(ctx)` (env/token paths) and `Consume(ctx, token, email, pw)`
  (see §5.3).

Every mutating service method appends the corresponding `audit_log` event (parent spec §3 event
list): `device.enroll.code`, `device.enroll.credentials`, `device.created`, `user.login.local`,
`user.login.failed`, `user.logout`, `user.password_change`, `bootstrap.consumed`, etc.

### 4.4 `internal/config` — `Auth` section (additive)

```go
type Auth struct {
    Session  SessionCfg   // CookieName, CookieSecure, CookieSameSite, TTL
    HMAC     HMACCfg       // SkewWindow, NonceTTL, SecretKey (base64 → 32 bytes, via ${file:}/${env:})
    Password PasswordCfg   // Argon2 time/memoryKiB/parallelism, MinLength
    Bootstrap BootstrapCfg // AdminEmail, AdminPassword (env-equiv)
}
```

Defaults mirror parent spec §8 (`ttl: 720h`, `skew: 120s`, argon2 `3/65536/2`, `min_length: 12`).
`SecretKey` is **required for agent auth**: empty key ⇒ startup error if any device exists /
before enrollment can seal secrets (fail-closed). It is supplied **base64-encoded and MUST decode
to exactly 32 bytes** (AES-256) — validated at startup as part of the fail-closed check.
`config.Load` also enforces **`nonce_ttl ≥ skew_window`** (else a replay window opens between when
skew still accepts a request and when its nonce row has already expired). Naming note: `secret_key`
is a key-encryption key that seals device HMAC secrets — it is not itself an HMAC key (documented
in code to avoid confusion).

### 4.5 `internal/server` wiring

`Handler`/`New` construct the `Verifier` (from store repos + `auth.hmac.secret_key`) and the
services, pass them into an extended `api.Build(mux, deps)`, and keep the existing net/http
chain unchanged. `serve` (cmd) calls `BootstrapService.Startup(ctx)` **after** `store.Open` and
**before** listening. A minimal background **pruner** goroutine (interval from config, default
1h) prunes `replay_nonces`, expired `sessions`, and expired `enrollment_codes`; it is started in
`Run` and stopped on shutdown. Plan 04 introduces the nonce writes, so it owns their cleanup.

---

## 5. Auth flows

### 5.1 HMAC (agent) — see §4.2 `Verify`. Attaches to `checkin`, `self` only.

### 5.2 Sessions + CSRF (browser)

- `SessionManager.Create` on login: opaque id + rotated `csrf_token`, `expires_at = now + ttl`.
  Cookie `diyddns_session` — `HttpOnly; Secure; SameSite=Lax; Path=/` (Secure forced when TLS is
  active, or when `X-Forwarded-Proto=https` **and the peer is within a configured
  `server.trusted_proxies` CIDR** — forwarded headers are honored only behind a trusted proxy, per
  parent §10).
- **Session middleware** (huma, on all protected `/api/v1` ops) authenticates the cookie and
  slides expiry (`last_seen_at` within slide window extends `expires_at`); stashes user+session
  in `huma.Context`. **Exempt:** `login`, `bootstrap` (pre-session).
- **CSRF middleware** (huma, on mutating `/api/v1` ops — POST/PATCH/DELETE) compares
  `X-CSRF-Token` (constant-time) to `session.csrf_token`; mismatch ⇒ 403. GETs exempt;
  `login`/`bootstrap` exempt (pre-session). `GET /api/v1/auth/me` returns `{user, csrf}`.

### 5.3 Bootstrap admin (applies the nomad-operator ACL idempotency lesson)

**The durable success marker is "an admin user exists," never a pre-written marker.** (Lesson
from the nomad-operator ACL bootstrap bug: gate on a durable confirmation set only *after* the
side-effect succeeds, not on the mere existence of a marker written *before* it.)

- **Startup** (`users` empty):
  - **Env path** (preferred, headless): if `DIYDDNS_BOOTSTRAP_ADMIN_EMAIL` +
    `..._PASSWORD` set → `HashPassword` → `Users.Create` admin → audit `user.created` + log
    `admin created via env`. The created admin **is** the success marker.
  - **Token path** (else): if an unconsumed `bootstrap.token_hash` already exists, log a
    pending reminder (cannot reprint the token). Otherwise generate a 32-byte token →
    `Bootstrap.SetTokenHash(argon2id(token))` → log
    `BOOTSTRAP_TOKEN=<token> visit /bootstrap to claim admin (single use)` to stderr + slog.
- **`POST /api/v1/auth/bootstrap`** `{token, email, password}` — the **atomic `Bootstrap.Consume`
  is the single-use gate**. This closes a concurrent-double-admin race: "check admin exists → then
  create" is not atomic, so two simultaneous requests with the same token + different emails could
  both pass the check and both `Users.Create` (distinct emails don't collide on `UNIQUE(email)`),
  minting two admins from a one-use token. An atomic consume admits exactly one:
  1. **Validate** email/password format up front (so the mutation below won't fail on bad input).
  2. If any admin exists → **410 Gone** (fast pre-filter).
  3. Verify `token` against `Bootstrap.Get().TokenHash` (argon2id); mismatch → 401.
  4. **`Bootstrap.Consume()` — the atomic gate.** `ErrNotFound` (already consumed / lost the race)
     → **410**. Proceed only on success (`RowsAffected == 1`).
  5. `HashPassword(password)` → `Users.Create` (`role=admin`) → audit `user.created` +
     `bootstrap.consumed`; 200 (UI redirects to login).
  - **Residual failure mode (bounded, recoverable):** if `Users.Create` fails *after* Consume
    (rare — inputs are pre-validated and the store is single-writer), bootstrap is closed with no
    admin. Log CRITICAL; recover via the documented path (delete the bootstrap row, or use the env
    path). This is the deliberate trade against the concurrent-double-admin race — a rare,
    recoverable lockout is preferred over a silent duplicate-admin.

Lost-token recovery (delete the bootstrap row / use the env path) is documented, not built.

---

## 6. Endpoints

| Group | Method | Path | Guard |
|---|---|---|---|
| agent | POST | `/agent/v1/enroll/code` | none (mints secret) |
| agent | POST | `/agent/v1/enroll/credentials` | none (password) |
| agent | POST | `/agent/v1/checkin` | HMAC |
| agent | GET  | `/agent/v1/self` | HMAC |
| api   | POST | `/api/v1/auth/login` | none → sets session |
| api   | POST | `/api/v1/auth/logout` | session |
| api   | GET  | `/api/v1/auth/me` | session (returns csrf) |
| api   | POST | `/api/v1/auth/password` | session + CSRF |
| api   | POST | `/api/v1/auth/bootstrap` | none / 410 once admin exists |
| api   | POST | `/api/v1/devices` | session + CSRF (mints code) |
| api   | GET  | `/api/v1/devices` | session |
| api   | GET  | `/api/v1/devices/{id}` | session |

`GET /agent/v1/capabilities` stays as-is (`oidc_enabled` still static `false`).

---

## 7. Data flow

- **Startup:** `serve` → `config.Load` → `store.Open` (migrate) → `BootstrapService.Startup` →
  `server.New` (Verifier+services) → `Run` (listen + pruner).
- **Enroll (code):** client `POST /agent/v1/enroll/code` → `ConsumeCode` → `{device_id, secret}`.
- **Checkin:** client signs → HMAC middleware `Verify` → handler → `CheckinService.Checkin`.
- **Browser:** `login` → session cookie; mutating call → session + CSRF middleware → handler.

## 8. Error handling

huma RFC 7807 problem responses. Canonical codes: 401 (bad HMAC / bad login / bad bootstrap token
/ **invalid-or-expired-or-used enrollment code** — a single 401 avoids leaking which state), 403
(CSRF mismatch), 409 (`ErrConflict` — duplicate label/email), 410 (`/bootstrap` after admin
exists), 413 (checkin body over the HMAC-middleware size cap, §3.2), 422 (validation). Login
returns a uniform "invalid credentials" 401 for both unknown-email and wrong-password (with
timing equalized, §4.3). Auth middleware returns errors **without** partial writes (addresses
follow-up #7 by construction). Startup failures (missing/invalid `secret_key`, `store.Open` error)
→ logged `error`, non-zero exit.

**Canonical `PATH` for HMAC signing** = the request path as `ctx.URL().Path` sees it. If the
server runs behind a path-rewriting proxy, client and server must agree on the path; documented as
a deployment assumption (no prefix stripping in the default `tls.mode=plain` shape).

## 9. Security considerations

- HMAC secret AEAD-encrypted at rest (D1); constant-time compares (`hmac.Equal`) for signature,
  CSRF, and token; replay window + nonce table; sessions HttpOnly/Secure/SameSite; argon2id
  passwords (≥12) + bootstrap token; audit on every auth/lifecycle event; secrets/tokens/cookies
  never logged.
- **DOCUMENTED RISK (deferred to Hardening plan):** `POST /agent/v1/enroll/credentials` and
  `POST /api/v1/auth/login` ship **without per-IP rate-limiting**, so they are a password
  brute-force surface. Per-IP limits (parent spec §4/§10) **MUST** land before v1 release.
  Tracked here so the gap is explicit, not silent.

## 10. Testing (parent spec §9)

Stdlib `testing`, table-driven, `-race`. **100% coverage on `shared` sign, `auth` HMAC verify,
and AEAD seal/open.** httptest integration over a `:memory:` store for every endpoint. Rejection
matrix (parent spec §14): timestamp-skew-out, replayed nonce, disabled device, disabled user,
invalid signature, missing/short password, bad CSRF, expired/used enrollment code, wrong bootstrap
token, `/bootstrap` 410-after-admin, oversize checkin body (413). Bootstrap **env-path** and
**token-path** both covered, plus login timing-equalization (unknown-email path still runs a hash).
Change-only `ip_history` append asserted.

**Middleware guard test (fail-open protection), behavioral:** huma per-op middleware is not
introspectable (`Operation.Middlewares` is `yaml:"-"`, runtime-only), so the guard is a
*behavioral* sweep — hit every protected path with **no credentials** and assert 401/403 (a
fail-open op would return 200/handler behavior). Covers each `/agent/v1` HMAC op and each
mutating `/api/v1` session+CSRF op.

**Folds in open follow-ups where they touch this code:** #6 (strengthen OpenAPI assertion to a
real 3.1 parse; add a serve boot test; `api_test` nil-store → `:memory:`; drop redundant
`strings.ToUpper`); #7 (already-written guard — satisfied by construction; auth middleware never
partial-writes before erroring).

## 11. Seams for later plans (additive)

- **OIDC (Plan 05):** new `internal/auth/oidc.go` + `enroll/oidc/*`, `auth/oidc/*` ops; toggles
  `capabilities.oidc_enabled` dynamic. No change to HMAC/session code.
- **Device CRUD / rotate / history (Services):** the Services plan adds `Verifier.Evict` (invoked
  on rotate/disable/delete) alongside its first caller; the secret-cache struct is already the seam.
- **Rate-limiting (Hardening):** middleware wraps enroll/login/checkin; no handler changes.

## 12. Acceptance criteria (Plan 04 slice of parent spec §14)

1. Fresh server with no users: env-path OR token-path creates the admin; `/bootstrap` returns
   410 once an admin exists.
2. Admin logs in (cookie + CSRF via `me`), mints an enrollment code via `POST /api/v1/devices`.
3. `POST /agent/v1/enroll/code` with that code returns `{device_id, secret}`; a signed
   `POST /agent/v1/checkin` is accepted and appears via `GET /agent/v1/self`; an unchanged
   re-checkin reports `stored:false` and appends no history row.
4. HMAC checkins are rejected on skew-out, replayed nonce, disabled device, and invalid signature.
5. Secret survives a server restart: a device enrolled before restart still checks in after
   (validates AEAD-at-rest repopulation, D1/D2).
6. `credentials` enrollment yields a working device without a pre-created code.
7. `go test ./... -race` passes; `golangci-lint run` clean; client binary still imports no huma.

## 13. Open items / probes (resolve in the implementation plan)

- **P1 / P3 — RESOLVED** (SGE-verified against huma v2.38.0 module source): per-operation
  `huma.Operation.Middlewares`; body buffer+restore via `humago.Unwrap(ctx)` +
  `r.Body = io.NopCloser(bytes.NewReader(buf))`; forward `device_id` via `huma.WithValue`; errors
  via `huma.WriteErr`. Net/http fallback unneeded. (Implementation still writes the probe test.)
- **P2 — DECIDED: AES-256-GCM (stdlib `crypto/cipher`)**, random 96-bit nonce stored `nonce‖ct`,
  base64 into `secret_hash`. XChaCha20-Poly1305 rejected: its 192-bit nonce solves a collision
  problem this scale doesn't have (one seal per enrollment; birthday bound ≈ 2⁴⁸) and adds a dep.
