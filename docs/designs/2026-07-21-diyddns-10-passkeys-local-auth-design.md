# DIYDDNS Plan 10 — Multi-passkey WebAuthn local auth — Design

- **Date:** 2026-07-21
- **Type:** Design
- **Status:** SGE-reviewed (Fable, AMEND-BEFORE-PLANNING) — all findings folded; pending user approval
- **Parent spec:** `docs/plans/2026-05-01-diyddns-design.md` (§3 data model, §4 API surface, §5B local auth, §8 config)
- **Builds on:** Plan 04 auth machinery (`docs/designs/2026-07-12-diyddns-04-auth-machinery-design.md`), Plan 05 OIDC (`docs/designs/2026-07-13-diyddns-05-oidc-design.md`), Plan 09 Services (`docs/designs/2026-07-18-diyddns-09-services-design.md`)
- **Cross-dependency:** Web UI direction (`docs/designs/webui-review/RECOMMENDATIONS.md`) — its `login`/`account` screens are placeholders pending this design.

---

## 1. Purpose & Scope

This plan **replaces local password authentication (argon2id) with multi-passkey
WebAuthn.** A user authenticates locally with **one or more passkeys**, or via
**OIDC**. Passwords are removed entirely (clean break — see D1). It must **precede the
Web UI build**, because the Web UI plan's `login`/`account` screens depend on the
credential model, recovery flows, and ceremony endpoints designed here.

It has **no prerequisites** — Plans 01–09 are all merged (`origin/main` @ `ff5cac1`).
There are **no releases/tags** and no deployed password-based installs to migrate.

### Two enabling facts about the current code

1. **`users.password_hash` is already nullable.** OIDC-only accounts already run with
   `password_hash = NULL`. A passkey-only user is structurally the same shape as an
   existing OIDC-only user, so removing passwords requires no data backfill — only the
   deliberate, irreversible choice to drop the now-dead column (D3).
2. **Sessions + CSRF are fully decoupled from credential verification.** A passkey
   login mints a browser session by calling `SessionManager.Create(userID, ip, ua)` —
   byte-for-byte the same cookie + CSRF machinery password login uses today. OIDC,
   `csrfMiddleware`, `adminMiddleware`, and the lockout guards (`enabledAdminCount`)
   are reused unchanged.

### In scope

- **Credential model + migration `00003`**: `webauthn_credentials` table,
  `users.webauthn_handle`, drop `users.password_hash`.
- **Ceremony service + JSON API**: passkey register (begin/finish) and login
  (begin/finish, discoverable), minting the existing cookie session.
- **Passkey management**: list / add / rename / remove, with a last-credential guard.
- **Bootstrap via passkey**: first-run admin claim registers a passkey (no password).
- **Registration grants**: admin **invite** link for new users, admin-issued
  **recovery** link, and self-service email-confirm → admin-notify recovery — one
  single-use hashed-token redeem→register flow, including a **new `internal/email` SMTP
  subsystem**.
- **Remove `enroll --user`** (client flag/op + server `/agent/v1/enroll/credentials`).
- **Minimal server-rendered UI**: `login`, `passkey-register`, `account → Passkeys`
  pages + one vendored JS helper, so local login works the moment this merges. The Web
  UI plan restyles/expands over the same service layer.
- **Config**: drop `auth.password.*` + `auth.bootstrap.admin_password`; add
  `auth.webauthn.*`, `auth.hide_local_login_ui`, and top-level `email.*`.

### Out of scope (deferred)

- Full Web UI (the other ~7 screens: devices, device-detail, enrollment reveal, admin
  users/audit/server) — the Web UI plan owns these; this plan ships only the minimal
  auth screens.
- Client `status`/`rotate` verticals (rest of #26); `PATCH /admin/server`
  live-settings; issue #27 wire-DTO consolidation.
- Async email delivery / retry queue (synchronous best-effort is sufficient at this
  scale — YAGNI).
- Attestation verification / authenticator allow-lists / passkey-count policy knobs.

---

## 2. Decisions

- **D1 — Clean break: passwords are removed, not kept as a fallback.** No dual
  password+passkey mode. There are no password users to migrate (no releases), and a
  transition mode is strictly more code (two live credential types + a cutover UX) for
  zero present benefit (YAGNI). Local credential types become exactly **{passkey,
  OIDC}**, both already modeled by a `NULL` `password_hash`.

- **D2 — Library: `github.com/go-webauthn/webauthn`, pure Go, no CGO.** Confirmed not
  yet a dependency; pinned at plan time. It is a server-only dep confined to the server
  binary — the client `deps_test.go` guard stays green (the client never speaks
  WebAuthn). RP config is derived at startup from `server.base_url`: **RP ID = its
  host**, **expected origin = the full base URL**. Attestation conveyance = **`none`**
  (a self-hosted DDNS must not demand attestation). Resident/discoverable credentials =
  **preferred** (enables usernameless login, D5).

- **D3 — Migration `00003` drops `users.password_hash` (the irreversible choice).**
  SQLite ≥ 3.35 supports `ALTER TABLE … DROP COLUMN`; `modernc.org/sqlite` is current.
  Chosen over "keep the column, always NULL" because leaving a dead credential column
  invites a future accidental local-password path that would survive `hide_local_login_ui`.
  The Down migration re-adds it nullable (schema-reversible; data is not restored — this
  is a one-way credential change, acknowledged).

- **D4 — `webauthn_credentials` FK is `ON DELETE CASCADE`.** A passkey has no meaning
  without its user; deleting a user takes their passkeys with it. Every `ON DELETE`
  action in this migration is chosen deliberately (per the Plan 02 FK-on-delete
  lesson — a bare `REFERENCES` = `NO ACTION` blocks parent deletes with a raw error).

- **D5 — Usernameless (discoverable) login is the primary flow.** "Sign in with a
  passkey" uses discoverable credentials (`BeginDiscoverableLogin` /
  `FinishDiscoverableLogin`); the server resolves the user by the credential's stored
  **`webauthn_handle`** (a stable, opaque, per-user 32-byte random value — *not* the
  email, *not* the DB id — minted lazily on first registration). No email is typed and
  nothing is enumerable. Rejected alternative: username-first (type email → allowed
  credentials) — simpler server-side but worse UX and leaks which emails exist.

- **D6 — WebAuthn challenge is carried in a short-lived sealed cookie, not a table.**
  The ceremony `SessionData` (challenge + context) is serialized into a ~2-minute
  AES-256-GCM sealed cookie via the existing `auth.Seal`/`SealWithAAD` (Plan 05), with a
  distinct AAD domain `diyddns/webauthn-v1` (domain-separated from device-secret sealing
  and the OIDC flow-state cookie). Stateless — no new table, no cleanup job. **Single-use
  is not automatic for a stateless cookie** (SGE M1): without server-side invalidation,
  re-POSTing the same finish request would re-verify and mint a fresh session until the
  TTL lapses (the true bound would be TTL + TLS, not protocol single-use). The challenge
  is therefore made single-use by a **TTL-bounded in-memory used-challenge set** — the
  finish op records the challenge id and rejects a repeat. No table needed. Documented
  upgrade path: a `webauthn_challenges` table (like `oidc_device_flows`) if explicit
  persistence/auditability is later wanted.

- **D7 — A passkey login mints the identical cookie session.** `login/finish` calls
  `SessionManager.Create(userID, ip, ua)` — same cookie name, TTL/slide, CSRF token
  rotation, `sessionMiddleware`/`csrfMiddleware` as today. Nothing downstream of authn
  changes.

- **D8 — Last-credential guard treats an OIDC link as a valid "way in".** Removing a
  passkey is refused (`ErrLastCredential`) only if it would leave the user with **zero
  passkeys AND no OIDC link** — i.e. no remaining login path. An OIDC-linked user may
  drop to zero passkeys safely (OIDC still authenticates them), consistent with today's
  OIDC-only accounts. Mirrors the shape of `AdminService.enabledAdminCount`.

- **D9 — Bootstrap registers a passkey; the token is consumed atomically at
  register-finish, not at claim (SGE I3).** First-run admin claim stays token-gated but
  registers the admin's first passkey instead of setting a password. The token is
  **validated (not consumed) at the claim step**; the target email is carried in the
  sealed challenge cookie; and at register-finish the server **verifies the passkey
  first, then** `Bootstrap.Consume` + creates the admin + stores the credential, in that
  order (re-checking `AdminExists` to keep the double-admin race closed; not a DB
  transaction — the single-connection pool would deadlock, see §6). An abandoned ceremony
  therefore leaves the token intact and reusable — it
  can never burn the token, orphan a credential-less admin, or lock out the sole admin
  (which my earlier consume-at-claim ordering could). The env
  `DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD` path is dropped (a passkey cannot be registered
  headlessly); env bootstrap is removed entirely. Reconciles with the Plan 05
  `AdminExists`-gated `Startup`.

- **D10 — Recovery = a hashed, single-use, expiring re-registration token that
  revokes-all-at-issue.** A new `account_recovery_tokens` table mirrors the
  enrollment-code + bootstrap-token-hash patterns. Issuing a recovery link (admin **or**
  self-service) **immediately revokes all of the user's existing passkeys** (the
  "reset passkeys" / lost-or-stolen-device case); redeeming the link registers a fresh
  passkey. Documented footgun: the user is locked out until they redeem. Recovery does
  **not** touch role/disabled — a last-admin stays admin and simply re-registers, so the
  last-admin guard is not involved.

- **D11 — Self-service recovery requires the new email subsystem AND a pre-existing
  passkey; admin recovery does not.** Admin recovery returns a copy-pasteable link (no
  email). Self-service recovery emails the link to the account address and notifies the
  admin, is only offered when SMTP is configured, and **only proceeds for an account that
  already has ≥1 passkey** (SGE I2). This makes it strictly "recover a *lost* passkey" —
  it can never mint a *first* local credential onto an OIDC-only account via mailbox
  possession alone (which would silently downgrade an OIDC/MFA login to email control).
  OIDC-only users add passkeys through their authenticated `/account` page, never via
  the pre-auth email path. If SMTP is unconfigured, self-service is absent and the admin
  link is the sole recovery route.

- **D12 — Email via stdlib `net/smtp`, synchronous best-effort.** A new `internal/email`
  package: a `Mailer` interface, an `net/smtp` implementation (pure Go, no dep), and a
  disabled/no-op implementation. No queue — a send failure logs server-side and never
  changes the uniform, non-enumerating user-facing response (YAGNI on async).

- **D13 — This plan ships a minimal working browser UI (not backend-only).** Without a
  browser flow, WebAuthn is unreachable and local login would break on merge. This plan
  delivers three server-rendered `html/template` pages + one small vendored JS helper.
  The Web UI plan restyles/expands them over the same `internal/server/service/*` seam
  (No-Wall). This is a present requirement (the feature must function), not scope creep.

- **D14 — OIDC and `hide_local_login_ui` are unchanged in shape.** Passkeys is a third
  credential type; OIDC login/link/signup keep working untouched. `hide_local_login_ui`
  simply omits the passkey block from the login page (OIDC-only), the `/login` route
  stays reachable. Note `hide_local_login_ui` is currently a design-doc-only concept and
  must be added to real config in this plan (SGE M4, §10).

- **D15 — Admin-created users get a first passkey via a registration link, not a
  password (SGE I1).** With passwords gone, `AdminService.CreateUser` creates a
  **credential-less** user (drop `Password` from `CreateUserParams` / `createUserInput`)
  and issues a one-time **registration link** — the same `account_recovery_tokens`
  redeem → register-passkey flow recovery uses, differing only in issuance reason + audit
  event (`passkey.invite_issued`). This unifies "admin invites a user" and "user recovers
  a lost passkey" into one *token-gated passkey registration for user X* concept (genuine
  shared knowledge, DRY-correct — the divergence lives only in the issuance step:
  invite has no existing passkeys to revoke, recovery revokes-all-at-issue).

---

## 3. Data model & migration `00003_passkeys.sql`

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE webauthn_credentials (
    credential_id   BLOB PRIMARY KEY,                 -- raw credential id from the authenticator
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      BLOB NOT NULL,                    -- COSE public key
    sign_count      INTEGER NOT NULL,                 -- signature counter (clone-detection)
    aaguid          BLOB,                             -- authenticator model id (for a UI hint)
    transports      TEXT,                             -- JSON array e.g. ["internal","hybrid"]
    name            TEXT NOT NULL,                    -- user-facing label ("MacBook Touch ID")
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER                           -- NULL until first successful login
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

ALTER TABLE users ADD COLUMN webauthn_handle BLOB;   -- stable per-user WebAuthn user handle (opaque)

-- Single-use, hashed, expiring token backing BOTH admin invites (D15) and
-- account recovery (D10). The redeem→register-passkey flow is identical; the
-- issuance reason differs (invite: nothing to revoke; recovery: revoke-all).
CREATE TABLE account_recovery_tokens (
    token_hash      TEXT PRIMARY KEY,                 -- hash of the single-use token
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL,                    -- 'invite' | 'recovery' (audit/UX only)
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER                           -- NULL until redeemed
);
CREATE INDEX account_recovery_tokens_expires ON account_recovery_tokens(expires_at);

ALTER TABLE users DROP COLUMN password_hash;         -- clean break (D1/D3)
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN password_hash TEXT;     -- schema-reversible; data is NOT restored
DROP TABLE IF EXISTS account_recovery_tokens;
ALTER TABLE users DROP COLUMN webauthn_handle;
DROP TABLE IF EXISTS webauthn_credentials;
-- +goose StatementEnd
```

`webauthn_handle` is `NULL` until the user's first passkey registration, then holds a
32-byte random value stable for the account's lifetime (used to resolve discoverable
logins, D5). It is deliberately distinct from `users.id` so credential identity is not
coupled to the DB primary key.

**New store repos:** `WebAuthnCredentialRepo` (`Create`, `ListByUser`, `GetByID`,
`Rename`, `Delete`, `DeleteAllByUser`, `IncrementSignCount`) and
`AccountRecoveryRepo` (`Create`, `Consume` atomic single-use like `EnrollmentCodes.Consume`,
`PruneExpired`), plus `UserRepo.SetWebAuthnHandle` / handle lookup. All follow the
existing store idioms (`scanX` helpers, `ErrConflict`/`ErrNotFound`, `nullIf*`).

**Removed:** `internal/auth/password.go` (argon2id `HashPassword`/`VerifyPassword`) and
`users.password_hash` scanning in `internal/store/users.go`.

---

## 4. Ceremony service & JSON API

New `internal/server/service/passkey.go` (`PasskeyService`) wraps the `go-webauthn`
library and the store. New `internal/server/api/passkey.go` registers JSON ops on the
existing `/api/v1` huma instance (called via `fetch()` from the pages, since
`navigator.credentials` returns JSON-marshalable objects). All finish-ops set/clear the
sealed challenge cookie (D6).

| Op | Method + path | Guard | Effect |
|---|---|---|---|
| Login begin | `POST /api/v1/auth/passkey/login/begin` | none (pre-session) | discoverable options + sealed challenge cookie |
| Login finish | `POST /api/v1/auth/passkey/login/finish` | none (pre-session) | verify, resolve user by handle, **mint session** (D7), bump `sign_count`+`last_used_at`, audit `user.login.passkey` |
| Register begin | `POST /api/v1/account/passkeys/register/begin` | session | creation options + sealed challenge cookie |
| Register finish | `POST /api/v1/account/passkeys/register/finish` | session + CSRF | verify, mint `webauthn_handle` if absent, store credential, audit `passkey.registered` |
| List | `GET /api/v1/account/passkeys` | session | name / created / last-used / authenticator-hint (never the public key) |
| Rename | `PATCH /api/v1/account/passkeys/{id}` | session + CSRF | rename, audit `passkey.renamed` |
| Remove | `DELETE /api/v1/account/passkeys/{id}` | session + CSRF | last-credential guard (D8), audit `passkey.removed` |

Register begin/finish is also driven by the **bootstrap** (§6), **admin invite** (§7,
D15), and **recovery** (§7) flows via distinct pre-session entry points that supply the
target user out-of-band (a validated token + the target carried in the sealed challenge
cookie) rather than from a session.

**Library integration note (SGE M2):** `go-webauthn`'s `FinishRegistration` /
`FinishDiscoverableLogin` take a `*http.Request`, but huma business handlers receive only
`context.Context`. Recover the request with `humago.Unwrap` (the repo's existing pattern
in `api/auth.go` `loginMetaMiddleware` and `api/oidc.go`), or use the lower-level
`protocol.Parse*ResponseBody` + `ValidateDiscoverableLogin` / `CreateCredential` on parsed
structs. The plan pins one approach up front.

**Sign-count regression (SGE M3):** the library does **not** fail `Finish*` on a counter
regression — it sets `credential.Authenticator.CloneWarning` (via `UpdateCounter`, which
no-ops when both counts are 0, as most platform/hybrid passkeys report). The *caller*
inspects `CloneWarning`, treats it as a verification failure, and audits
`passkey.signcount_anomaly`.

---

## 5. Passkey management & last-credential guard

The account API (§4) is the management surface. The guard (D8), in `PasskeyService.Remove`:

```
count passkeys for user
if removing this one would leave 0 passkeys AND user.OIDCSubject == "":
    return ErrLastCredential   // API → 409
```

An OIDC-linked user is allowed to reach zero passkeys. `ErrLastCredential` maps to `409`
in the api layer's error switch, alongside the existing guard sentinels. The guard keys
off `user.OIDCSubject != ""`, which the admin DTO must be made consistent with (SGE I5,
§12) now that `PasswordHash` is gone.

---

## 6. Bootstrap via passkey (D9)

- `BootstrapService.Startup` mints the single-use token exactly as today (unchanged
  atomic gate, `AdminExists` pre-filter) and emits it via the existing log sink. The env
  `admin_email`/`admin_password` fast-path is removed.
- The `/bootstrap` claim page: submit **token + email** → the server **validates** the
  token hash (constant-time) and the email, but does **not** consume yet. It stashes the
  target email in the sealed challenge cookie and returns register-begin options.
- At **register-finish**, the ordering is **verify-before-consume** (not a DB
  transaction — the store's single-connection pool, `SetMaxOpenConns(1)`, makes a
  `BeginTx` wrapping the pool-based repos self-deadlock; SGE-plan C1): re-check
  `AdminExists` → **verify the passkey** (`FinishRegistration`, credential held in
  memory, no DB write) → `Bootstrap.Consume` (the atomic `consumed_at`-gated single-row
  UPDATE admits exactly one winner) → create the **credential-less** admin
  (`Users().Create(Role:"admin")`) → store the credential + `webauthn_handle`. Verifying
  before consuming means an abandoned ceremony never spends the token (`consumed_at` stays
  NULL) — no orphan admin, no sole-admin lockout (SGE I3). This moves the atomic gate from
  claim to finish without weakening it.
- `Consume`'s password/min-length validation is replaced by email validation only.
- Residual (`BOOTSTRAP CRITICAL`): the only window is a credential INSERT failing *after*
  `Consume` + admin-create succeed (a single local INSERT). Recovery = delete the admin +
  bootstrap rows and restart (Startup re-mints). Full multi-statement atomicity would
  require threading a `*sql.Tx` through every repo — a store-wide change deferred as
  out-of-scope; the verify-before-consume ordering shrinks the residual to this
  documented sub-millisecond case, matching the project's existing bootstrap tolerance.

---

## 7. Registration grants — invites & recovery (D10–D12, D15)

**One token, one redeem flow, three issuers.** `account_recovery_tokens` (§3) is a
single-use, hashed, expiring **registration grant** — random token shown once, stored as
a hash, `reason ∈ {invite, recovery}`, ~1 h expiry, atomic `Consume` (mirrors
`EnrollmentCodes.Consume`: `WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`).
**Redeeming** (any reason) validates the token, then drives register begin/finish to
register a passkey for the token's user (carried in the sealed cookie, not a session).
The three issuers differ only in issuance side-effects:

**Admin invite** (D15, new-user first credential): `AdminService.CreateUser` creates a
credential-less user, mints an `invite` grant, returns the one-time link. **Nothing to
revoke** (no prior passkeys). Audits `user.created` + `passkey.invite_issued`; redeem
audits `passkey.registered`.

**Admin recovery** (replaces "force-reset password"):
`POST /api/v1/admin/users/{id}/recovery` (session + admin + CSRF) → **revoke all existing
passkeys** (`DeleteAllByUser`) + mint a `recovery` grant + return the one-time link. No
email needed. Audits `passkey.recovery_issued`; redeem audits `passkey.recovery_redeemed`.

**Self-service recovery** (pre-auth "Lost your passkey?" on `/login`):
1. `POST /api/v1/auth/recovery/request` `{email}` → **always** responds "if that account
   exists, we've emailed a link" (no enumeration). It proceeds only when the account
   exists, **already has ≥1 passkey** (SGE I2 — never mints a first credential onto an
   OIDC-only account via mailbox possession), *and* SMTP is configured: mint a `recovery`
   grant, revoke existing passkeys, email the link, email the admin(s) a notification.
   Send failures are logged, never surfaced. If any condition fails, the response is
   unchanged (still the uniform "if it exists" message).
2. User clicks the emailed link → redeem page → registers a fresh passkey.

Revoke-all-at-issue (recovery only) is the lost-or-stolen-device model: the lost
authenticator stops working the moment recovery starts. Documented footgun: the user is
locked out until they redeem. Recovery/invite never touches role/disabled, so a last-admin
stays admin and simply re-registers (last-admin guard not involved).

**New `internal/email` package (D12):** `Mailer` interface (`Send(ctx, to, subject, body) error`),
an `net/smtp` SMTP impl (STARTTLS/implicit/none per config), and a disabled no-op impl
selected when `email.enabled = false`. Two `text/template`/`html/template` messages
(recovery link; admin notification). The SMTP password is never logged.

---

## 8. Remove `enroll --user`

- **Client** (`cmd/diyddns-client/`): remove the `--user` flag and its `switch` arm,
  `resolvePassword` (+ `password.go`/`password_test.go`), and
  `enroll.Client.EnrollCredentials`. Drop the `golang.org/x/term` dependency (no other
  user). `enroll --code` and `enroll --oidc` remain — **`--code` and `--oidc` are the
  device-onboarding paths** (both password-free; there is no longer any password path).
  `deps_test.go` stays green.
- **Server**: remove `POST /agent/v1/enroll/credentials` (`internal/server/api/enroll.go`)
  and `EnrollService.EnrollCredentials`. `enroll/code` and `enroll/oidc/*` stand.

---

## 9. Minimal server-rendered UI (D13)

New `internal/server/webui` (or the location the Web UI plan will adopt): three
`html/template` pages over the existing service layer, embedded via `go:embed`, plus one
vendored JS helper (`navigator.credentials.create/get` + base64url ↔ ArrayBuffer).

- **`/login`** — "Sign in with a passkey" (discoverable), an OIDC button (when enabled),
  and a "Lost your passkey?" link (when SMTP configured). Omits the passkey block under
  `hide_local_login_ui` (D14).
- **passkey-register page** — shared by bootstrap, recovery, and "add passkey".
- **`/account` → Passkeys card** — list/rename/remove/add.

**Middleware:** HTML routes need thin stdlib `net/http` equivalents of
`sessionMiddleware`/`adminMiddleware` wrapping the **same** `SessionManager` and role
check (the Web UI review §4 flags this). To keep the "how to authenticate a browser
request" knowledge single-sourced (SGE N2), factor the actual check — cookie →
`SessionManager.Authenticate` → role — into **one framework-agnostic helper** that both
the huma middleware and the stdlib middleware call; only the framework glue is written
twice. **CSRF:** true `<form>` POSTs (recovery request, logout) use a hidden `csrf`
field; the JSON ceremonies use the existing `X-CSRF-Token` header. The service layer and
`SessionManager` are the shared seams.

---

## 10. Config surface

**Removed:** `auth.password.*` (argon2 params + min-length) and
`auth.bootstrap.admin_password` (+ its env alias).

**Added:**

```
auth.webauthn.rp_id            # default "" → derived from server.base_url host
auth.webauthn.rp_origin        # default "" → derived from server.base_url
auth.webauthn.rp_display_name  # default "DIYDDNS"
auth.webauthn.timeout          # ceremony timeout, default 120s
auth.hide_local_login_ui       # default false — omit the passkey block from /login (D14, M4)

email.enabled                  # default false
email.host / email.port
email.username / email.password  # password never logged
email.from
email.tls                      # "starttls" | "implicit" | "none", default "starttls"
```

**`hide_local_login_ui` must be added to real config (SGE M4)** — today it exists only in
design docs, not `internal/config/config.go`.

**"Passkey login enabled" predicate (SGE M4):** local passkey login is *always* available
unless `hide_local_login_ui` is set; there is no separate `auth.webauthn.enabled` toggle
(passkeys is the default local credential). Consequently `server.base_url` becomes
**required whenever passkey login is available** (RP ID/origin derive from it) — today it
is only required for OIDC. Startup **fails closed** if `base_url` is unset and neither an
explicit `auth.webauthn.rp_origin` is configured nor `hide_local_login_ui` is set with
OIDC providing the only login path.

---

## 11. Seams — reused vs. new

**Reused unchanged:** `SessionManager` (`Create`/`Authenticate`), `csrfMiddleware`,
`adminMiddleware`, `sessionMiddleware`, `auth.Seal`/`SealWithAAD` (challenge cookie),
`auth.RandToken` (recovery token), `Bootstrap.Consume` atomic gate, `AuditSink`, the
store idioms, goose embed (`migrations.FS`), the OIDC subsystem.

**New:** `internal/server/service/passkey.go`; `internal/server/api/passkey.go`;
`internal/email` package; `internal/server/webui` (templates + JS + stdlib middleware +
the shared browser-auth helper, N2); store repos `WebAuthnCredentialRepo` +
`AccountRecoveryRepo` + `UserRepo` handle methods; migration `00003`; config
`auth.webauthn.*` + `auth.hide_local_login_ui` + `email.*`; the admin-invite grant path
in `AdminService.CreateUser` (I1).

**Changed:** `newAdminUserView` derives account type from `OIDCSubject != ""`
(`OIDCLinked`), not `PasswordHash == ""` (I5); `createUserInput`/`CreateUserParams` drop
`Password`.

**Removed:** `internal/auth/password.go`; `AuthService.Login` password path + decoy +
`ChangePassword`; `AdminService` password-on-create + password-reset; enroll credentials
(client + server); `auth.password.*` + `auth.bootstrap.admin_password` config;
`golang.org/x/term` client dep. **Not added:** a `passkey_enabled` flag on
`/agent/v1/capabilities` — that endpoint is agent/client-facing and the dep-isolated
client never speaks WebAuthn (SGE M5); the login page reads server config directly.

---

## 12. Error & audit model

**New api sentinels → HTTP:** `ErrLastCredential` → 409; recovery token
invalid/expired/used → uniform 401 (no leak of which); WebAuthn verification failure →
401; self-service recovery request → always 200 with the uniform "if it exists" message.

**New audit events:** `user.login.passkey`, `passkey.registered`, `passkey.renamed`,
`passkey.removed`, `passkey.signcount_anomaly`, `passkey.invite_issued`,
`passkey.recovery_issued`, `passkey.recovery_redeemed`, `email.send_failed` (server-side
diagnostic).

**Removed events:** `user.login.local`, `user.password_change`.

**DTO change (SGE I5):** with `password_hash` dropped, `adminUserView.OIDCOnly`
(derived from `PasswordHash == ""`) is redefined as `OIDCLinked` (from
`OIDCSubject != ""`). Audit every `PasswordHash == ""` site — `service/auth.go:67`
(decoy path, removed with password login), `service/admin.go:176` (password-reset guard,
removed), `service/enrollment.go` (credentials enroll, removed) — and change or delete
each in lockstep with the column drop so the build/tests stay green.

---

## 13. Security notes

- Never log: the SMTP password, recovery tokens (log only their hash context), the
  bootstrap token (existing behavior), session cookies, or the sealed challenge cookie.
  WebAuthn public keys are public; credential ids are not secret but are not printed.
- Recovery tokens: single-use, hashed at rest, short expiry, constant-time verify — same
  discipline as enrollment codes and the bootstrap token.
- Sealed challenge cookie: distinct AAD domain, short TTL, `HttpOnly` + `Secure` (per the
  existing `sessionCookie` policy) + `SameSite`.
- No account enumeration: discoverable login (no username), uniform recovery-request
  response, uniform WebAuthn/recovery failures.
- Origin/RP-ID binding is the phishing defense; derive strictly from `server.base_url`
  and fail closed if it is missing.
- The clean break removes the last local shared-secret (password) from the DB; the only
  local verifier material left is device HMAC secrets (sealed) and session ids.

---

## 14. Testing

Service + store + API-level, mirroring Plan 05 OIDC (which tested the full browser/device
flows against a mock IdP with no real browser). `go-webauthn` ships test helpers that
simulate an authenticator, so register/login ceremonies are exercised end-to-end at the
API layer without a browser. Store repos get table-driven `-race` tests including the FK
cascade (`DeleteAllByUser`, user-delete cascade) and the recovery-token atomic
single-use. `internal/email` tests use a fake SMTP server (or the no-op impl) — no
network. The client `deps_test.go` guard is asserted green (no `webauthn`/`term` in the
client binary). All stdlib `testing`, table-driven, `-race`, `errors` `%w`; full
`golangci-lint` per task.

---

## 15. Execution workflow

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
`docs/plans/2026-07-21-diyddns-10-passkeys-local-auth-implementation.md`.

---

## Review Provenance

- **SGE (sr-go-engineer, Fable) design review, 2026-07-21 — verdict AMEND-BEFORE-PLANNING;
  all findings folded.** The reviewer confirmed the `go-webauthn` API surface (pure-Go;
  `BeginDiscoverableLogin`/`FinishDiscoverableLogin` resolve the user by handle via a
  `DiscoverableUserHandler`; `SessionData` json-serializes; attestation `none`,
  resident-key `preferred`, `CloneWarning` all real), the sealed-cookie forgery-safety,
  the D8 last-credential guard, and the `DROP COLUMN` + FK-cascade discipline.
  - **Important:** I1 — admin-created users need a first-credential path → unified into the
    registration-grant flow (D15, §7). I2 — self-service recovery could mint a first
    credential onto an OIDC-only account (MFA downgrade) → guarded to accounts with ≥1
    existing passkey (D11, §7). I3 — bootstrap consume-before-register could lock out the
    sole admin → inverted to validate-at-claim, consume+create+store atomically at finish
    (D9, §6). I4 — self-service email is a large scope + I2 footgun → user elected to
    **keep** it (fixed input) with the I2 guard applied. I5 — `OIDC-only` DTO must key off
    `OIDCSubject`, not the dropped `PasswordHash` → §12.
  - **Minor:** M1 (challenge single-use via in-memory used-set, D6) · M2 (`humago.Unwrap`
    for `Finish*`, §4) · M3 (`CloneWarning` is caller-checked, §4) · M4
    (`hide_local_login_ui` → real config + enabled predicate, §10) · M5 (no
    `passkey_enabled` on agent capabilities, §11) · M6 (complete Down migration +
    `StatementBegin/End`, §3).
  - **Nit:** N1 (enroll wording — code & oidc, §8) · N2 (single-source browser-auth helper,
    §9). All folded.
- **SGE (Fable) plan review, 2026-07-21** (of the implementation plan) surfaced C1: a
  `BeginTx` wrapping the single-connection pool's repos would self-deadlock, so §6/D9's
  bootstrap-finish was reconciled from "one transaction" to **verify-before-consume**
  ordering (verify passkey → atomic `Bootstrap.Consume` gate → credential-less admin →
  store credential). See the plan's Review Provenance for the full fold.
