# DIYDDNS Plan 05 — OIDC Authentication (Design)

- **Type:** Design
- **Feature:** diyddns-05-oidc
- **Date:** 2026-07-13
- **Author:** brainstormed with the user, session of 2026-07-13
- **Base:** `origin/main` @ `373e9b4` (Plan 04 auth merged via PR #8)
- **Parent spec:** `docs/plans/2026-05-01-diyddns-design.md` (§4 endpoints, §5B OIDC, §8 config)
- **Builds on:** `docs/designs/2026-07-12-diyddns-04-auth-machinery-design.md` (§11 seams)

---

## 1. Purpose & scope

Plan 05 adds **OpenID Connect** to diyddns as the auth surface Plan 04 deliberately
deferred. It delivers, **server-side only**:

- **Browser authorization-code flow with PKCE** — `GET /api/v1/auth/oidc/start` +
  `GET /api/v1/auth/oidc/callback`, minting the same cookie session local login does.
- **Agent device-code flow (RFC 8628)** — `POST /agent/v1/enroll/oidc/start` +
  `POST /agent/v1/enroll/oidc/poll`, delegating to the IdP's device authorization grant
  and returning `{device_id, secret}` exactly like the existing enrollment paths.
- **Link/signup policy** — match `(oidc_provider, oidc_subject)` → verified-email auto-link
  → create `role=user`; admins are never auto-created.
- **Dynamic capabilities** — `oidc_enabled` and `oidc_device_enabled` reported live.
- **Config** — the `auth.oidc.*` section sketched in parent spec §8.
- **Issue #13 reconciliation** — `BootstrapService.Startup` gated on admin existence.

Everything attaches **additively** to Plan 04's seams: no change to HMAC sign/verify,
`SessionManager`, CSRF, local login/password/bootstrap ops, or the `users`/`sessions`/
`devices` schemas.

### Decisions locked in this session

| # | Decision | Rationale |
|---|---|---|
| D1 | **Both flows, server-side** (browser + agent device-code) | Matches Plan 04's precedent of building server verticals ahead of the client; keeps the whole OIDC wire contract in one plan. The `enroll --oidc` client consumer is Plan 06. |
| D2 | **Require `email_verified` for auto-link** | Closes the account-takeover vector where an attacker registers a victim's email at the IdP. Hardening beyond the bare spec (spec §5B says link on email match; we additionally gate on the verified claim). |
| D3 | **Defer `hide_local_login_ui` to Plan 07** | YAGNI — only the React UI (Plan 07) consumes it; no present consumer. |
| D4 | **Two capability flags** (`oidc_enabled` + `oidc_device_enabled`) | Browser auth-code and the device grant genuinely diverge (e.g. Kanidm supports the former, not the latter). The Plan 06 client checks `oidc_device_enabled` before offering `enroll --oidc`; `/enroll/oidc/start` returns `501` when unavailable. |
| D5 | **Degrade to local login on discovery failure, `auth.oidc.required=true` opts into fail-closed** | An unreachable IdP must not take the whole DDNS server down; operators who need the guarantee opt in (mirroring the HMAC-key fail-closed). |
| D6 | **Pending device-code flows in a SQLite `oidc_device_flows` table** | Consistent with every other short-lived-token store in the repo (`sessions`, `replay_nonces`, `enrollment_codes` are all DB-backed + swept by `runPruner`); survives a mid-flow restart. |

### Non-goals (explicitly deferred)

- **`enroll --oidc` client** (device-code consumer) → Plan 06 (the client is still a Plan 01 scaffold).
- **`hide_local_login_ui`, admin/server live-tuning, manual link/unlink UI** → Plan 07 / Services plan.
- **Multiple OIDC providers** — the spec commits to a single configurable provider.
- **Broad rate-limiting** → Hardening plan. Plan 05 includes only the device-poll pacing guard (below), which protects the upstream IdP.
- **RP-initiated logout, token refresh, long-lived OIDC token storage** — unneeded: the ID token is consumed once at login/enroll and discarded; the device then uses HMAC and the browser uses the session cookie.

---

## 2. Architecture & package layout

All go-oidc/oauth2 code is confined to a **new dedicated `internal/oidc` package** — *not*
`internal/auth/oidc.go`. This makes `internal/oidc` the only package importing the new
server-only deps, so they can never leak into the client binary even if the Plan 06 client
later imports `internal/auth` for HMAC signing. `internal/oidc` exposes PKCE/state/nonce
**values** and leaves HTTP concerns to its caller: the api layer (which already imports
`internal/auth`) performs the flow-cookie sealing via `auth.SealSecret`/`OpenSecret`, so
`internal/oidc` need not import `internal/auth` at all.

### New files (each isolates one OIDC concern)

| Layer | File | Responsibility |
|---|---|---|
| `internal/oidc` | `manager.go` | `Manager`: provider lifecycle (discovery, JWKS, `oauth2.Config`, device endpoint), ID-token verification, PKCE/state/nonce helpers, device-auth start + single-shot poll. Holds live state behind an atomic pointer for degrade/retry. **Only package importing `x/oauth2`/`go-oidc`.** |
| `internal/server/service` | `oidc.go` | `OIDCService`: the link/signup **policy** (found → verified-email link → signup). Resolves a `store.User`; the caller mints the session (browser) or device (agent). |
| `internal/server/api` | `oidc.go` | Browser ops `GET /api/v1/auth/oidc/start` + `/callback`. Registered from `registerAuthOps`. |
| `internal/server/api` | `enroll_oidc.go` | Agent ops `POST /agent/v1/enroll/oidc/start` + `/poll`. Registered from `registerEnrollOps`. |
| `internal/store` | `oidc_device_flows.go` + migration | Pending device-code flows (§6). |

### Additive edits (siblings otherwise untouched)

- `ServerDeps` gains `OIDC *service.OIDCService` and `OIDCMgr *oidc.Manager`.
- `registerAuthOps` and `registerEnrollOps` each gain one `register…(a, deps)` line.
- `capabilities.go` reads `oidc_enabled`/`oidc_device_enabled` live from the manager
  (takes `deps` instead of just `version.Info`).
- `config.Auth` gains an `OIDC OIDCCfg` field + `keyDefaults` keys + validation.
- `cmd/diyddns-client/deps_test.go` extends the forbidden-imports check to also bar
  `golang.org/x/oauth2` and `github.com/coreos/go-oidc` (defense-in-depth on isolation).
- `BootstrapService.Startup` one-line gate fix (§7).

### Dependencies added (server-only)

- `github.com/coreos/go-oidc/v3`
- `golang.org/x/oauth2`

(`golang.org/x/crypto` is already a direct dep from Plan 04.)

---

## 3. Browser authorization-code flow (PKCE)

### `GET /api/v1/auth/oidc/start`

1. Manager not ready (`oidc_enabled=false`) → `302 /login?error=oidc_unavailable`.
2. Generate `state`, PKCE `code_verifier` (+ S256 `code_challenge`), and OIDC `nonce`
   (all cryptographically random). `next` is an optional `?next=<path>` query param on
   `/start`, defaulting to the UI root — it is where the browser lands after a successful
   callback. **Validation (open-redirect defense):** `url.Parse` must succeed with empty
   `Scheme` and `Host` and a `Path` starting with `/`, and the raw value must not start with
   `//` or `/\` (browsers treat both as scheme-relative → external host). Reject otherwise
   (fall back to UI root).
3. **Seal `{state, verifier, nonce, next}` as JSON into one cookie** `diyddns_oidc_flow`
   via a new **`auth.SealWithAAD(masterKey, json, aad="diyddns/oidc-flow-v1")`** —
   `HttpOnly`, `Secure`, `SameSite=Lax` (Lax lets the cookie ride the top-level GET redirect
   back from the IdP), `Path=/api/v1/auth/oidc`, `MaxAge≈600s`. The **GCM AAD domain-separates**
   the flow cookie from device-secret sealing (`SealSecret` uses `nil` AAD): a blob sealed in
   one context fails to open in the other by construction, not by incidental JSON-unmarshal
   failure. `SealWithAAD`/`OpenWithAAD` are additive siblings of `SealSecret`/`OpenSecret` in
   `internal/auth/secret.go` (existing functions unchanged); the api layer calls them (it
   already imports `internal/auth`). One tamper-proof cookie, no new key, no server-side
   transient state.
4. `302` to the IdP `authorization_endpoint` with `client_id`,
   `redirect_uri = server.base_url + /api/v1/auth/oidc/callback`, `response_type=code`,
   `scope` (configured), `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.

### `GET /api/v1/auth/oidc/callback`

1. If the IdP returned an `error` query param → log server-side, `302 /login?error=…`.
2. `OpenSecret` the `diyddns_oidc_flow` cookie; **constant-time compare** its `state`
   to the `state` query param → mismatch = `400`. (This is the callback CSRF guard.)
3. `oauth2Config.Exchange(code, code_verifier)` at the token endpoint (confidential
   client with `client_secret`).
4. Extract `id_token`; verify with the go-oidc verifier (JWKS signature, `iss`, `aud`,
   `exp`). Then **the handler itself** constant-time-compares `idToken.Nonce` to the
   cookie's nonce — go-oidc does *not* check nonce; the caller must (this is a browser-flow
   check only; the device flow has no nonce, see §4).
5. Extract claims `sub`, `email`, `email_verified`.
6. `OIDCService.LoginOrLink(...)` → `store.User` (§5).
7. `SessionManager.Create(user.ID, ip, ua)` — identical to local login; clear the flow
   cookie; set `diyddns_session` via the existing `sessionCookie()` helper; `302` to
   `next` (default UI root).

Request metadata (`ip`, `ua`, `tls`) for step 7 is captured via the same middleware
pattern `auth.go` already uses for login (`loginMetaMiddleware`), since huma business
handlers receive a plain `context.Context`.

---

## 4. Agent device-code flow (RFC 8628, delegated to the IdP)

Our server is the OIDC client; the agent only ever sees an opaque `flow_id`.

### `POST /agent/v1/enroll/oidc/start`

1. Manager not ready **or** IdP has no `device_authorization_endpoint`
   (`oidc_device_enabled=false`) → **`501 Not Implemented`**.
2. Call the IdP device endpoint (`oauth2.Config.DeviceAuth`) →
   `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}`.
3. Insert an `oidc_device_flows` row:
   `flow_id (opaque random, PK) → {device_code, interval, expires_at, last_polled_at=0, created_at}`.
   The IdP's `device_code` **never leaves the server**.
4. Return to the agent:
   `{flow_id, user_code, verification_uri, verification_uri_complete, expires_in, interval}`.
   The user visits the IdP's verification URL and authenticates directly with the IdP.

### `POST /agent/v1/enroll/oidc/poll`  — body `{flow_id}`

1. Look up the flow → not found / past `expires_at` → **`410 Gone`** (agent restarts).
2. **Pacing guard (atomic, no read-then-write race):** a conditional
   `UPDATE oidc_device_flows SET last_polled_at=? WHERE flow_id=? AND last_polled_at <= ?-interval`.
   0 rows affected → `{status:"slow_down"}` without hitting the IdP (two concurrent polls
   for the same `flow_id` can't both pass). This protects the upstream from a hammering
   agent; full rate-limiting remains the Hardening plan.
3. **Single-shot** token-endpoint POST (`grant_type=urn:ietf:params:oauth:grant-type:device_code`,
   `device_code`, **plus the client credentials** `client_id`/`client_secret` — a
   confidential client must authenticate on the device-code token request too). *Note:* a
   manual one-shot request using the Manager's timeout-bounded HTTP client (§7), **not**
   `oauth2.DeviceAccessToken` (that helper blocks and self-polls, wrong for a per-call
   endpoint). Parse `authorization_pending`/`slow_down` via `oauth2.RetrieveError.ErrorCode`.
   - `authorization_pending` → `{status:"pending"}`
   - `slow_down` → `{status:"slow_down"}` **and bump the stored `interval` by 5s** (RFC 8628 §3.5)
   - `access_denied` / `expired_token` → delete the flow → `4xx`
   - success → tokens (incl. `id_token`)
4. Verify `id_token` with the go-oidc verifier (JWKS/`iss`/`aud`/`exp`) → `sub`, `email`,
   `email_verified`. **No nonce check** — RFC 8628 has no authorization request to carry a
   nonce, so the device-flow ID token has none (this is the one verification difference from
   the browser flow's §3 step 4).
5. **Reuse `OIDCService.LoginOrLink`** — identical found/link/signup policy; admins never created.
6. Mint the device for that user via `EnrollmentService.EnrollForUser(ctx, userID, eventType, meta)`
   — a thin exported entry point over the **already-shared** unexported `createSealedDevice`
   (`enrollment.go`; `EnrollCredentials`/`ConsumeCode` already call it). It creates the
   device, seals the secret, **and writes the audit entry inside the service** (event type
   `device.enroll.oidc`), matching the repo convention that services own auditing. Returns
   `{device_id, secret}` in the existing `enrollResponse` shape (secret base64, shown once).
7. Delete the flow row.

The two flows differ only in **transport**; user resolution (`LoginOrLink`) and device
creation (`EnrollForUser`) are shared.

---

## 5. Link / signup policy (`OIDCService.LoginOrLink`)

Matching order from parent spec §5B, hardened per D2. `provider` = the issuer URL
(stored in `users.oidc_provider`). Every rejection returns the **same generic outcome**
(`302 /login?error=no_account` for the browser, `401` for the agent) and logs the specific
reason server-side (§9) — so an IdP-authenticated caller cannot probe which emails have
diyddns accounts, and no failure mode leaks account existence (Plan 04's uniform-failure
philosophy).

```
1. GetByOIDC(issuer, sub)
     found, not disabled  → login                         (audit user.login.oidc)
     found, disabled      → reject
2. else if email == "":                                    → reject
     (no signup or link is possible without an email; email is NOT NULL UNIQUE)
3. else if email_verified && cfg.auto_link_by_email:
     GetByEmail(email)
       found local, role != admin, not yet OIDC-linked     → link (set oidc_provider/subject) + login
       found local, role == admin                          → reject  (admins are never auto-linked; see below)
       found, already linked to a DIFFERENT sub            → reject
       not found                                           → fall through to step 4
4. else if cfg.allow_oidc_signup:
     Create(email, role=user, oidc_provider=issuer, oidc_subject=sub, password_hash=NULL)
       ErrConflict (email already exists but wasn't linkable above, e.g. unverified email
         or auto_link disabled)                            → reject  (do NOT leak existence)
5. else:
     reject
```

- **Admins are never auto-created *or* auto-linked** via OIDC. Spec §5B forbids
  auto-*creation*; we additionally exclude `role=admin` from auto-*linking* (hardening): an
  IdP account whose verified email matches the admin's must not silently yield an admin
  session. An admin links their own OIDC identity deliberately via the Services-plan admin
  UI. (Residual trust in the IdP's `email_verified` remains, per D2 — this bounds its blast
  radius away from the highest-privilege account.)
- **Empty email** (Kanidm's docs, §12, warn claim presence isn't guaranteed) → reject; we
  never insert `email=""` (the second such insert would collide on `UNIQUE(email)`).
- **`ErrConflict` on `Create`** (email present locally but not linkable in step 3) is mapped
  to the same generic rejection — never surfaced as a 500 and never distinguished from
  "no account".
- The `users` table already carries `oidc_provider`/`oidc_subject` + `UNIQUE(oidc_provider,
  oidc_subject)` and `UserRepo.GetByOIDC`/`Create`/`Update` exist (Plan 02/04) — **no user
  migration is needed**.
- `AuthService.Login` already runs its decoy-timing path for empty-password (OIDC-only)
  accounts, so local login of an OIDC-only account stays indistinguishable in timing —
  Plan 04 pre-wired this.

---

## 6. Persistence — `oidc_device_flows`

A new table + migration; a small repo mirroring `enrollment_codes.go`.

```sql
CREATE TABLE oidc_device_flows (
    flow_id        TEXT PRIMARY KEY,   -- opaque random id handed to the agent
    device_code    TEXT NOT NULL,      -- the IdP's device_code; never exposed to the agent
    interval       INTEGER NOT NULL,   -- min poll interval (s); default 5 when the IdP omits it; bumped +5 on slow_down
    expires_at     INTEGER NOT NULL,   -- unix seconds; past this the flow is 410 Gone
    last_polled_at INTEGER NOT NULL,   -- unix seconds; 0 until first poll (pacing guard, §4 step 2)
    created_at     INTEGER NOT NULL
);
```

- Swept by the existing `runPruner` — this requires adding an `oidc_device_flows` sweep to
  `prune()` in `pruner.go` (an additive edit, listed in §11), matching the
  `sessions`/`replay_nonces`/`enrollment_codes` deletes already there.
- No OIDC tokens are stored — only the transient `device_code` between `/start` and the
  successful `/poll`, after which the row is deleted.

---

## 7. `oidc.Manager` lifecycle & configuration

### Config — `config.Auth` gains `OIDC OIDCCfg`

```go
type OIDCCfg struct {
    Enabled         bool
    Required        bool     // fail-closed startup if discovery fails (default false)
    Issuer          string
    ClientID        string   `mapstructure:"client_id"`
    ClientSecret    string   `mapstructure:"client_secret"`   // env: DIYDDNS_AUTH_OIDC_CLIENT_SECRET; never logged
    Scopes          []string
    AutoLinkByEmail bool     `mapstructure:"auto_link_by_email"`
    AllowOIDCSignup bool     `mapstructure:"allow_oidc_signup"`
    // hide_local_login_ui → Plan 07
}
```

`keyDefaults` additions:

```
auth.oidc.enabled:            false
auth.oidc.required:           false
auth.oidc.issuer:             ""
auth.oidc.client_id:          ""
auth.oidc.client_secret:      ""
auth.oidc.scopes:             ["openid", "profile", "email"]
auth.oidc.auto_link_by_email: true
auth.oidc.allow_oidc_signup:  true
```

**`Load` validation:** when `auth.oidc.enabled`, require non-empty `issuer`, `client_id`,
`client_secret`, **`server.base_url`** (needed to build `redirect_uri`), and **`openid` present
in `scopes`** (without it the IdP returns no `id_token` and every flow fails confusingly at
runtime instead of at `Load`) — else a config error. `client_secret` is supplied via
`DIYDDNS_AUTH_OIDC_CLIENT_SECRET` and never logged.

**Scopes via env caveat:** viper `Unmarshal` delivers a `DIYDDNS_AUTH_OIDC_SCOPES` env value
as a single string, not a `[]string`. Document `scopes` as **YAML/flag-configured only**, or
split on comma/space in `Load`. (The default `[openid, profile, email]` covers the common case;
overriding scopes is rare.)

### Dynamic capabilities

```go
type Capabilities struct {
    ServerVersion     string   `json:"server_version"`
    SkewWindowSeconds int      `json:"skew_window_seconds"`
    AddressFamilies   []string `json:"address_families"`
    OIDCEnabled       bool     `json:"oidc_enabled"`        // browser auth-code ready
    OIDCDeviceEnabled bool     `json:"oidc_device_enabled"` // IdP advertises a device endpoint
}
```

`registerCapabilities` takes `deps` so it can read `deps.OIDCMgr.Enabled()` /
`.DeviceEnabled()`.

### Manager

Holds `atomic.Pointer[state]` where `state = {provider, verifier, oauth2Config, deviceAuthURL}`.
The Manager is **always constructed** (wired into `ServerDeps` unconditionally); `enabled=false`
is simply the permanent not-ready state — `Enabled()==false`, no `RetryLoop` launched — so
`capabilities.go` and every op can dereference `deps.OIDCMgr` without a nil check (no nil-panic
→ Recover-500 class; Plan 04's fail-open guard test exists for exactly this hazard).

- `Enabled()` = state non-nil. `DeviceEnabled()` = state non-nil && `deviceAuthURL != ""`.
- **Owns a timeout-bounded HTTP client** (`Timeout≈10s`, TLS `MinVersion` floor) — go-standards
  §15.1 forbids `http.DefaultClient`. It is injected into every IdP call via
  `oidc.ClientContext(ctx, hc)` (discovery/verification) and `context.WithValue(ctx,
  oauth2.HTTPClient, hc)` (exchange/device), plus a per-call `context.WithTimeout`. Without this
  the callback/poll handlers hang on a wedged IdP for as long as the inbound client waits.
- **`required=true`:** `server.Handler` runs discovery **synchronously**; on failure Handler
  returns an error and the server does not start (mirrors the HMAC-key fail-closed).
- **`required=false` & enabled:** `Handler` performs **no network I/O** (startup never blocks
  on the IdP); `server.Run` launches `go mgr.RetryLoop(ctx)` alongside `runPruner`, which
  owns *every* discovery attempt — backoff-retries until the first success, then exits.
  go-oidc's `RemoteKeySet` auto-refreshes JWKS on unknown `kid` thereafter, so no periodic
  re-discovery is needed once up. Until the first success, `Enabled()` is `false` and local
  login/agent HMAC serve normally. The backoff schedule and clock are **injectable** (as
  `SessionManager.now` is) so the degrade→recovery test (§10) is deterministic, not sleep-flaky.
- Black-box tests that need OIDC ready before the first request use `required=true` against
  the in-process mock IdP (§10), so discovery completes synchronously in `Handler`.
- Discovery = `oidc.NewProvider(ctx, issuer)` → `provider.Verifier(&oidc.Config{ClientID})`,
  `oauth2.Config{ClientID, ClientSecret, Endpoint: provider.Endpoint(), RedirectURL:
  base_url+callback, Scopes}`. `deviceAuthURL` = **`provider.Endpoint().DeviceAuthURL`** —
  go-oidc v3 already parses `device_authorization_endpoint` into `oauth2.Endpoint`, so no manual
  `provider.Claims` struct is needed.

---

## 8. Bootstrap reconciliation (issue #13)

`BootstrapService.Startup` currently returns early on `len(users) > 0`. Change the gate to
admin existence, matching `Consume`/`AdminExists`:

```go
hasAdmin, err := s.AdminExists(ctx)   // was: if len(users) > 0 { return nil }
if err != nil { return fmt.Errorf("service.Startup: %w", err) }
if hasAdmin { return nil }
```

**Why:** once OIDC creates `role=user` accounts, an install can have users but no admin.
The old gate would silently stop bootstrapping and run adminless. The existing
"unconsumed token exists → log pending, don't re-mint" branch still prevents repeated
token minting across restarts.

**New edge case (documented limitation):** env-path bootstrap whose `admin_email` collides
with an OIDC-provisioned account → `Users().Create` hits `UNIQUE(email)` → Startup errors
with a clear message — the operational consequence is a **startup crash-loop until the
operator unsets the colliding env var**. Promoting an existing user to admin is an admin-UI
action (Services plan); the bootstrap admin email must not collide with an OIDC account.

---

## 9. Error handling & logging (issue #9 pattern)

All new OIDC ops **log server-side** — both **infra failures** (token exchange, JWKS fetch,
DB errors) at error level and **policy rejections** (§5: empty email, unverified-email
conflict, admin-not-linked, different-sub conflict, signup disabled) at info/warn — while
returning a single generic user-facing outcome. This is the Plan 04 devices-500 pattern
(`d21ed75`) extended to policy: the caller learns nothing distinguishing (no account probing),
but the operator can still see *why* a login/enroll failed. Transient failures must not be invisible.

**Never logged:** ID/access/refresh tokens, authorization codes, `device_code`, `state`,
PKCE verifier, `client_secret`, device secrets. OIDC tokens are consumed once and discarded.

---

## 10. Testing — in-process mock IdP

A small `httptest.Server` (no live network; `-race`; table-driven; stdlib `testing`) serving:

- `/.well-known/openid-configuration` — discovery whose `issuer` equals the httptest base
  URL (so go-oidc's issuer check passes), advertising the auth/token/JWKS and (optionally)
  device endpoints.
- JWKS — a test signing key whose public half backs the ID-token signatures.
- authorization / token / device endpoints — returning signed ID tokens with configurable
  claims (`sub`, `email`, `email_verified`, `nonce`, `aud`, `exp`).

Coverage:

- **Browser:** start→callback happy path; `state` match **and mismatch**; PKCE round-trip;
  `nonce` match **and mismatch**; `email_verified` true/false; found / link / signup /
  signup-disabled; disabled-user reject; **empty-email reject**; **`ErrConflict`
  (existing-email-not-linkable) → generic reject, not 500**; **admin-email not auto-linked**;
  `next` open-redirect rejection (`//evil`, `/\evil`).
- **Agent device-code:** start→poll pending→success; `slow_down` pacing guard (incl. the
  concurrent-poll atomic-update case) + `interval` bump; expired→`410`;
  IdP-without-device-endpoint→`501`; device token poll sends client credentials.
- **Manager:** degrade on discovery failure (`oidc_enabled=false`) → `RetryLoop` recovery
  (injected clock/backoff, no sleeps); `required=true` fail-closed; **IdP-timeout does not hang
  the handler** (wedged mock endpoint returns within the client timeout).
- **Flow cookie:** a blob sealed with `SealWithAAD("oidc-flow-v1")` fails to `OpenSecret`
  (device-secret context) and vice-versa (domain separation).
- **Config validation**; **dynamic capabilities** values.
- **Issue #13:** OIDC `role=user` present + no admin ⇒ `Startup` still bootstraps.

---

## 11. Seam summary

| Untouched | New / one-line edits |
|---|---|
| HMAC sign/verify, `SessionManager` internals, CSRF middleware, local login/password/bootstrap-consume ops, device mint/list/get, **`users`/`sessions`/`devices` schemas (no user migration)** | **New:** pkg `internal/oidc`; `service/oidc.go`; `api/oidc.go` + `enroll_oidc.go`; `store/oidc_device_flows.go` + 1 migration. **Additive edits to existing files:** `config.OIDCCfg` + keys + validation; `capabilities` +2 fields; `ServerDeps` +2 fields; 2 `register…` lines; `deps_test` +2 forbidden imports; `bootstrap.go` `Startup` 1-line gate fix; `enrollment.go` new exported `EnrollForUser` over the existing `createSealedDevice`; `secret.go` new `SealWithAAD`/`OpenWithAAD` siblings; **`server.go`** (`Handler` constructs the Manager + synchronous discovery when `required`; `Run` adds `go mgr.RetryLoop(ctx)` beside `runPruner`); **`pruner.go`** (`prune()` gains the `oidc_device_flows` sweep) |

Adding a second OIDC provider later, or the `enroll --oidc` client, is a new file plus
wiring — the siblings above are not reopened.

---

## 12. Kanidm compatibility note

Kanidm is a likely IdP for a self-hosted tool like diyddns. Verified 2026-07-13 against
current Kanidm docs:

- **Browser auth-code + PKCE:** fully supported. Kanidm **requires** PKCE `S256` (cannot be
  disabled) — our browser flow does PKCE, so it is a direct fit. Standard OIDC discovery +
  JWKS are published.
- **Issuer is per-client:** Kanidm's issuer URL is
  `https://idm.example.com/oauth2/openid/<client_id>/`, not a bare host. Operators set
  `auth.oidc.issuer` to that client-specific base. Document this.
- **Device grant (RFC 8628):** **not currently a released feature** (Kanidm's device flow is
  a WIP design; the stable OAuth2 docs advertise no `device_authorization_endpoint`). With
  Kanidm, `oidc_device_enabled=false`, `/agent/v1/enroll/oidc/start` → `501`, and agents
  enroll via code/credentials. If Kanidm ships the grant later, our discovery-driven flag
  flips to `true` with no code change.
- **`email_verified`:** emitted with the `email` scope, but Kanidm's docs note claim presence
  is "not guaranteed." Under D2 (require `email_verified` for auto-link), a token lacking the
  claim does **not** link to an existing local account — per §5 it is rejected with the generic
  `no_account` outcome when that email already exists locally (we do not silently create a
  duplicate). Operators must ensure the account/scope emits `email_verified` for auto-link to
  work, or link manually (Services plan).

Sources: [Kanidm OAuth2 integration](https://kanidm.github.io/kanidm/stable/integrations/oauth2.html),
[Kanidm device-flow design (WIP)](https://kanidm.github.io/kanidm/master/developers/designs/oauth2_device_flow.html),
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

---

## 13. Follow-ups closed / touched

- **Closes #13** — `Startup` admin-gate fix (§8).
- **Applies #9's pattern** — server-side logging of infra errors in the new OIDC ops (§9);
  the broader #9 remediation of the existing login/enroll ops is out of scope here.

---

## 14. Review provenance

- **Self-review** (2026-07-13): corrected the `internal/oidc`↔`internal/auth` dependency
  direction, disambiguated the start-error response, sourced the `next` param, and moved all
  degrade-path network I/O out of `Handler`.
- **sr-go-engineer review** (Fable, 2026-07-13, verdict AMEND-BEFORE-PLANNING): all findings
  folded in — completed the §5 policy for empty-email / `ErrConflict` / admin-auto-link and
  collapsed rejection codes (#1, #6, #15); GCM-AAD domain separation for the flow cookie (#2);
  IdP-call timeouts via a Manager-owned HTTP client (#3); Manager always constructed, disabled =
  not-ready (#4); client auth on the device token poll (#5); `Endpoint().DeviceAuthURL` instead
  of `Claims` (#7); caller-checked nonce + no device-flow nonce (#8); atomic pacing update +
  `slow_down` interval bump + default `interval=5` (#9); `next` scheme-relative rejection (#10);
  `server.go`/`pruner.go`/`secret.go` added to the seam table (#11); service-owned OIDC-enroll
  audit over the existing `createSealedDevice` (#12); `openid`-in-scopes validation + scopes
  env-string caveat (#13); injectable backoff/clock for the recovery test (#14). Confirmed
  solid by the reviewer: issue-#13 fix, manual single-shot device poll, library-API composition,
  the additive-seam claims, the `internal/oidc` package split, and the mock-IdP test plan.
