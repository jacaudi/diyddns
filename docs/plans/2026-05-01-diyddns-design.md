# DIYDDNS — Design Spec

- **Date:** 2026-05-01
- **Type:** Design
- **Status:** Approved (pending final spec read)

---

## 1. Purpose & Scope

DIYDDNS is a self-hosted, multi-user public-IP tracker. A lightweight client agent
periodically discovers its own public IP from a quorum of independent lookup
providers and reports the result to a central server, which stores per-device IP
history in SQLite and exposes both an API and a web UI.

The system is **not** an authoritative DNS server. It does not publish DNS records.
It is an IP registry: clients check in, the server records, users browse history.

### Non-goals (v1)

- Authoritative DNS publishing (no port-53 service, no NS delegation).
- Pushing updates to third-party DNS providers (no Cloudflare/Route53 integration).
- Federated multi-server deployments.
- Mobile native apps; the web UI must work on mobile but native apps are out of scope.

### Scale target

Family / small-group: tens of clients across a handful of users; one server; multiple
devices per user. Architecture must not foreclose multi-tenant growth, but
operational simplicity wins where it conflicts with theoretical scale.

---

## 2. Architecture & Repo Layout

**Single Go module, two binaries, shared internals, embedded UI.**

```
diyddns/
├── cmd/
│   ├── diyddns-server/main.go
│   └── diyddns-client/main.go
├── internal/
│   ├── auth/                  # HMAC sign/verify, sessions, CSRF, OIDC, password (argon2id)
│   ├── server/
│   │   ├── api/               # huma operations (agent + ui route groups)
│   │   ├── middleware/        # auth, rate-limit, request-id, recover
│   │   └── service/           # device, user, history, audit, enrollment services
│   ├── client/
│   │   ├── poller/            # change-driven polling loop
│   │   ├── ipdiscovery/       # default lookup providers, quorum logic
│   │   └── enroll/            # code-based + user-credential enrollment
│   ├── store/                 # sqlite (modernc.org/sqlite), goose runner
│   ├── config/                # viper loaders for server + client
│   └── shared/                # types shared across cmd/* (HMAC envelope, etc.)
├── ui/                        # Vite + React + TS + antd + pro-components
│   ├── src/
│   ├── package.json
│   └── dist/                  # build output (gitignored)
├── migrations/                # *.sql files embedded via go:embed
├── packaging/
│   ├── systemd/               # server + client units (system-wide and --user)
│   ├── docker/                # Dockerfiles + docker-compose.yaml sample
│   ├── launchd/               # macOS client plist
│   └── proxy/                 # Caddy/nginx/Traefik samples
├── docs/
│   ├── plans/                 # design + implementation specs
│   └── openapi/               # generated specs (api.json, agent.json)
├── Taskfile.yml
├── go.mod
└── .golangci.yml
```

**Shape rules:**

- One Go module, one `go.mod`.
- `cmd/diyddns-server` imports server-only deps (huma, sqlite, OIDC, embedded UI).
  `cmd/diyddns-client` does not — keeps the client binary small and portable.
- `internal/shared` is the only package both binaries import (HMAC signing/verifying,
  request envelope types, capability-discovery types).
- `ui/dist` is built by Vite, embedded into the server via `embed.FS` at build time.
- Two route groups in the server: `/agent/v1/*` (HMAC, no CSRF) and `/api/v1/*`
  (cookie session + CSRF). UI build is served at `/`. OpenAPI at
  `/api/openapi.json` and `/agent/openapi.json`; Scalar UIs at `/api/docs` and
  `/agent/docs`.

### Tech stack

- **Language:** Go (both binaries).
- **CLI:** `spf13/cobra`.
- **Config:** `spf13/viper` (precedence: flags > env > file > defaults).
- **Logging:** stdlib `log/slog`.
- **HTTP server:** stdlib `net/http`.
- **API framework:** `danielgtaylor/huma` v2 (code-first OpenAPI; built-in Scalar UI).
- **SQLite driver:** `modernc.org/sqlite` (pure-Go; no CGO).
- **Migrations:** `pressly/goose` with embedded SQL via `//go:embed`.
- **OIDC:** `coreos/go-oidc` + `golang.org/x/oauth2`.
- **Password hashing:** `golang.org/x/crypto/argon2` (argon2id).
- **TLS / ACME:** `golang.org/x/crypto/acme/autocert`.
- **Lint:** `golangci-lint`.
- **Build/run:** Taskfile.
- **Testing:** stdlib `testing`, table-driven where inputs are enumerable; `-race`
  in CI.
- **Error wrapping:** `fmt.Errorf("%w", err)` (enforced via `errorlint`).
- **Frontend:** Vite + React + TypeScript + `antd` + `@ant-design/pro-components`,
  React Router, TanStack Query.

### Guiding UI rule

Use Ant Design (`antd`) and `@ant-design/pro-components` for **every** UI element.
Reach outside Ant Design only when nothing in those packages covers the need, and
document the reason in a comment.

---

## 3. Data Model (SQLite Schema)

SQLite via `modernc.org/sqlite`. Pragmas applied per connection:
`journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`, `busy_timeout=5000`.
Migrations run at server startup via `pressly/goose` against the embedded SQL files.

All timestamps are unix seconds (`INTEGER`) for portability and cheap indexing.
Identifiers are UUIDv7 stored as `TEXT` unless otherwise noted.

```sql
-- users: local + OIDC, with role
CREATE TABLE users (
  id              TEXT PRIMARY KEY,            -- UUIDv7
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT,                        -- argon2id; NULL if OIDC-only
  role            TEXT NOT NULL CHECK (role IN ('admin','user')),
  oidc_provider   TEXT,                        -- issuer URL when linked
  oidc_subject    TEXT,                        -- sub when linked
  disabled        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (oidc_provider, oidc_subject)
);

-- sessions: web UI cookie sessions
CREATE TABLE sessions (
  id              TEXT PRIMARY KEY,            -- random opaque
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token      TEXT NOT NULL,               -- per-session, rotated on login
  ip              TEXT,
  user_agent      TEXT,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expires ON sessions(expires_at);

-- devices: per-user; HMAC secret stored AES-256-GCM-sealed for cold-storage protection (see §5A; Plan 04 D1)
CREATE TABLE devices (
  id              TEXT PRIMARY KEY,            -- UUIDv7
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label           TEXT NOT NULL,               -- user-supplied
  secret_hash     TEXT NOT NULL,               -- base64(AES-256-GCM(nonce||ct)) of the HMAC secret, under auth.hmac.secret_key
  current_ipv4    TEXT,
  current_ipv6    TEXT,
  hostname        TEXT,                        -- client-reported
  os              TEXT,                        -- client-reported
  client_version  TEXT,                        -- client-reported
  last_seen_at    INTEGER,                     -- v1: time of last *change* seen
  disabled        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (user_id, label)
);
CREATE INDEX devices_user ON devices(user_id);

-- ip_history: append-only on change (v1)
CREATE TABLE ip_history (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ipv4            TEXT,
  ipv6            TEXT,
  observed_at     INTEGER NOT NULL,
  client_version  TEXT
);
CREATE INDEX ip_history_device_observed ON ip_history(device_id, observed_at DESC);

-- enrollment_codes: one-time, short-lived
CREATE TABLE enrollment_codes (
  code            TEXT PRIMARY KEY,            -- short URL-safe random
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label           TEXT NOT NULL,               -- proposed device label
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER,                     -- non-null = consumed
  device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL -- code survives device deletion for audit
);
CREATE INDEX enrollment_codes_expires ON enrollment_codes(expires_at);

-- replay_nonces: short-lived HMAC replay defense
CREATE TABLE replay_nonces (
  signature       TEXT PRIMARY KEY,            -- the X-Diyddns-Signature value
  expires_at      INTEGER NOT NULL
);
CREATE INDEX replay_nonces_expires ON replay_nonces(expires_at);

-- audit_log: auth & lifecycle events
CREATE TABLE audit_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id   TEXT,                        -- nullable (system events)
  event_type      TEXT NOT NULL,               -- e.g. user.login, device.enroll, secret.rotate
  target_type     TEXT,
  target_id       TEXT,
  details_json    TEXT,                        -- structured context
  ip              TEXT,
  user_agent      TEXT,
  created_at      INTEGER NOT NULL
);
CREATE INDEX audit_log_created ON audit_log(created_at DESC);
CREATE INDEX audit_log_actor ON audit_log(actor_user_id, created_at DESC);

-- bootstrap: tracks one-time admin bootstrap state (single-row table)
CREATE TABLE bootstrap (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  token_hash      TEXT,                        -- of the printed bootstrap token; NULL once consumed
  created_at      INTEGER NOT NULL,
  consumed_at     INTEGER
);
```

### Notes on data model

- HMAC secret is **never stored in plaintext** — only AES-256-GCM-sealed under
  the server master key `auth.hmac.secret_key` (Plan 04 D1; argon2id cannot be
  used here because HMAC verification needs the recoverable secret bytes and
  argon2id is one-way). The secret is shown to the client exactly once at enrollment.
- `ip_history` is append-only on change; retention pruning respects "always keep
  latest" by excluding `MAX(id) per device_id` from delete.
- `replay_nonces` self-prunes via a periodic background job (entries expire within
  the HMAC skew window).
- `audit_log` retention is configurable; default 365 days.
- The data model already supports the planned heartbeat upgrade (Section 12,
  "Future Work"): adding a heartbeat endpoint that updates `last_seen_at` without
  appending an `ip_history` row requires no schema change.

### Audit log event types (initial set)

`user.login.local`, `user.login.oidc`, `user.login.failed`, `user.logout`,
`user.password_change`, `user.created`, `user.role_change`, `user.disabled`,
`user.enabled`, `user.deleted`, `device.enroll.code`, `device.enroll.credentials`,
`device.enroll.oidc`, `device.created`, `device.renamed`, `device.disabled`,
`device.enabled`, `device.deleted`, `device.secret.rotated`, `bootstrap.consumed`,
`session.revoked`.

---

## 4. API Surface

Two route groups, no overlap, distinct middleware stacks. All endpoints are
described via huma. Two OpenAPI documents are served (one per group, since the
auth schemes differ).

### `/agent/v1/*` — HMAC-authenticated, no CSRF, no cookies

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/agent/v1/enroll/code` | Exchange one-time enrollment code → `{device_id, secret}` |
| `POST` | `/agent/v1/enroll/credentials` | Username + password → device registration → `{device_id, secret}` |
| `POST` | `/agent/v1/enroll/oidc/start` | Begin OIDC device-code flow (RFC 8628); returns user_code + verification URL |
| `POST` | `/agent/v1/enroll/oidc/poll` | Poll OIDC device-code; on success returns `{device_id, secret}` |
| `POST` | `/agent/v1/checkin` | Report current IP(s) |
| `GET`  | `/agent/v1/self` | Current device's view of itself (label, last record) |
| `GET`  | `/agent/v1/capabilities` | Server features (OIDC enabled? skew window? supported address families?) — unauthenticated |

Enrollment endpoints are **not HMAC-protected** (no secret yet); they are
rate-limited per source IP. `/checkin` and `/self` require the HMAC headers
defined in Section 5A.

`/checkin` request body:
```json
{
  "ipv4": "203.0.113.42",       // optional; omit if unconfirmed
  "ipv6": "2001:db8::1",        // optional
  "hostname": "homelab",        // optional, OS-reported
  "os": "linux",                // optional
  "client_version": "0.1.0"     // optional
}
```

`/checkin` response: `{ "device_id": "...", "current_ipv4": "...", "current_ipv6": "...", "stored": true|false }`. `stored=false` indicates the report was a no-op (no change).

### `/api/v1/*` — Cookie-session + CSRF, browser-facing

**Auth & session:**

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Local username + password login → sets session cookie |
| `POST` | `/api/v1/auth/logout` | Destroy session |
| `GET`  | `/api/v1/auth/oidc/start` | Redirect to OIDC provider |
| `GET`  | `/api/v1/auth/oidc/callback` | OIDC callback → create/find user → session |
| `GET`  | `/api/v1/auth/me` | Current user info + CSRF token |
| `POST` | `/api/v1/auth/password` | Change own password |
| `POST` | `/api/v1/auth/bootstrap` | One-time admin bootstrap (consumes token) |

**Device management (user-scope):**

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/api/v1/devices` | List own devices |
| `POST` | `/api/v1/devices` | Create label + generate enrollment code |
| `GET`  | `/api/v1/devices/{id}` | Get device |
| `PATCH`| `/api/v1/devices/{id}` | Rename, disable/enable |
| `DELETE`| `/api/v1/devices/{id}` | Delete device + its history |
| `POST` | `/api/v1/devices/{id}/rotate-secret` | New enrollment code, invalidates old secret |
| `GET`  | `/api/v1/devices/{id}/history` | Cursor-paginated IP history |

**Admin-scope:**

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/api/v1/admin/users` | List users |
| `POST` | `/api/v1/admin/users` | Create local user |
| `PATCH`| `/api/v1/admin/users/{id}` | Set role, disable/enable, force password reset |
| `DELETE`| `/api/v1/admin/users/{id}` | Delete user (cascades) |
| `GET`  | `/api/v1/admin/devices` | List all devices |
| `GET`  | `/api/v1/admin/audit` | Audit log search |
| `GET`  | `/api/v1/admin/server` | Server info: version, OIDC config (sans secret), retention, TLS mode |
| `PATCH`| `/api/v1/admin/server` | Live-tunable settings (retention, hide_local_login_ui flag) |

**Health:**

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/healthz` | Liveness — unauthenticated, plaintext OK |
| `GET`  | `/readyz`  | Readiness (DB reachable, migrations applied) |

### Conventions

- API version is in the path (`v1`). v2, when needed, lives alongside; v1 stays
  compatible.
- Pagination on history and audit endpoints is **cursor-based** keyed on
  `(observed_at|created_at, id)`. Default page size 50, max 500.
- Errors are returned in huma's RFC 7807 problem format.
- TS types for the React UI are generated build-time from the running server's
  OpenAPI documents via `openapi-typescript` (`task ui:gen-types`).

---

## 5. Auth Model

Three distinct surfaces, each with its own scheme. Middleware ensures no
cross-pollination (CSRF middleware never applies to `/agent`; HMAC middleware
never applies to `/api`).

### A. Device → server (HMAC, on `/agent/v1/*`)

**Headers required on authenticated requests:**

```
X-Diyddns-Device:    <device_id>
X-Diyddns-Timestamp: <unix-seconds>
X-Diyddns-Nonce:     <16+ bytes, url-safe-base64>
X-Diyddns-Signature: <hex HMAC-SHA256>
```

**Canonical signing input** (newline-joined, LF):

```
METHOD\n
PATH\n
TIMESTAMP\n
NONCE\n
SHA256(BODY)        ← lowercase hex; empty body → SHA256("")
```

**Server verification:**

1. Parse `X-Diyddns-Device` → look up device row (and its `disabled`, plus the
   user's `disabled`).
2. Reject if `|now - timestamp| > 120s`.
3. Reject if `replay_nonces` already contains the signature; otherwise insert
   with `expires_at = timestamp + 120s`.
4. Verify HMAC. To keep the hot path fast, the server maintains an in-memory
   per-process cache `device_id → HMAC secret bytes`. The cache is populated
   lazily by **AES-256-GCM-decrypting the stored `secret_hash`** under
   `auth.hmac.secret_key` on cold-start or first use (this repopulates cleanly
   after a restart — Plan 04 D1/D2); entries are evicted on secret rotation and
   device disable. (Plan 04 note: nonce insertion happens **after** a successful
   constant-time signature compare, so forged requests never write `replay_nonces` — D3.)
5. Constant-time compare. On success: update `last_seen_at`; append `ip_history`
   row only if v4 or v6 changed. (A reported family that is empty/omitted is
   treated as "unconfirmed" and preserves the stored value — it never clears it.)

**Why this scheme:**

- Replay-resistant (timestamp + nonce, both bounded by skew window).
- Cold-storage of the secret is protected (AES-256-GCM at rest; a DB copy
  without `auth.hmac.secret_key` yields nothing).
- Hot path is HMAC-SHA256 only — fast even at scale.
- Loss of a device's secret = re-enrollment. Loss of the server master key
  `auth.hmac.secret_key` = all devices must re-enroll; key rotation (re-sealing
  every stored secret) is out-of-scope future work.

### B. Browser → server (cookie sessions + CSRF, on `/api/v1/*`)

**Cookie:**

```
diyddns_session = <opaque session id>   ; HttpOnly; Secure; SameSite=Lax; Path=/
```

**Session lifecycle:**

- Created on local-login or OIDC callback. Row in `sessions` with rotated
  `csrf_token` and 30-day `expires_at`, sliding on activity (`last_seen_at`
  within 7 days extends `expires_at`).
- Logout deletes the row.
- Admin can revoke any session (delete row) via the admin user endpoint.

**CSRF:**

- `GET /api/v1/auth/me` returns `{ user, csrf }`.
- All mutating requests (POST/PATCH/DELETE) under `/api/v1/*` require
  `X-CSRF-Token` matching the session's `csrf_token`. Read-only `GET`s do not.
- `/agent/v1/*` is exempt.

**Local password storage:** argon2id (`time=3, memory=64 MiB, parallelism=2`),
per-user random salt, ≥12-character password minimum.

**OIDC:**

- One configurable provider (issuer URL, client ID, client secret, scopes;
  default scopes `openid profile email`).
- Standard authorization-code flow with PKCE for the browser.
- On callback: match `(oidc_provider, oidc_subject)`; if matched → log in. If
  the `email` claim matches an existing local user → link (admin-configurable:
  auto-link or require admin approval; default auto-link). If neither → create
  new user with `role=user` (admins are never auto-created via OIDC).
- `hide_local_login_ui` config flag: removes the local-login form from the UI;
  the backend route stays live for break-glass.

### C. Bootstrap admin (first run only)

Two paths, env-var wins:

1. **Env-var path** (preferred for headless deploys): on first start, if `users`
   is empty AND `DIYDDNS_BOOTSTRAP_ADMIN_EMAIL` + `DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD`
   are set, create admin and log `"admin created via env"`. On subsequent starts
   these vars are ignored (admins exist).
2. **Bootstrap-token path**: on first start, if `users` is empty AND env-var
   path didn't fire, server generates a random token, stores `argon2id(token)`
   in `bootstrap.token_hash`, prints to stderr and logs (slog) one line:
   ```
   BOOTSTRAP_TOKEN=<token> visit /bootstrap to claim admin (single use)
   ```
   The web UI route `/bootstrap` accepts the token + email + password; server
   consumes (`bootstrap.consumed_at = now`, `token_hash = NULL`), creates admin
   with `role=admin`, redirects to login.

Once any admin exists, `/bootstrap` returns 410 Gone and the bootstrap row stays
consumed.

---

## 6. Client Behavior

Single binary `diyddns-client` with cobra subcommands.

### Subcommands

```
diyddns-client enroll      # one-time enrollment; writes credentials.json
diyddns-client run         # main loop: discover IP, report on change
diyddns-client status      # print current local state, last reported IP, server URL
diyddns-client rotate      # initiate secret rotation (re-enrollment)
diyddns-client version
```

### Storage layout (XDG-conforming)

| Purpose | Linux/macOS path | Windows path | Mode |
|---|---|---|---|
| Config | `$XDG_CONFIG_HOME/diyddns/config.yaml` | `%APPDATA%\diyddns\config.yaml` | 0644 |
| Credentials | `$XDG_CONFIG_HOME/diyddns/credentials.json` | `%LOCALAPPDATA%\diyddns\credentials.json` | **0600** |
| State | `$XDG_STATE_HOME/diyddns/state.json` | `%LOCALAPPDATA%\diyddns\state\state.json` | 0600 |

`credentials.json`: `{server_url, device_id, secret}`.
`state.json`: `{last_ipv4, last_ipv6, last_reported_at}`.

When the client runs under the system-wide systemd unit, paths shift to
`/etc/diyddns/{client.yaml,credentials.json}` and `/var/lib/diyddns/state.json`
via `--config` / `--state-dir` flags. XDG paths remain the default for non-systemd
interactive use; the user-mode systemd unit also uses XDG paths.

### IP discovery — quorum from 9 default providers

| # | Provider | v4 endpoint | v6 endpoint | Operator | Transport |
|---|---|---|---|---|---|
| 1 | ipify | `https://api.ipify.org` | `https://api6.ipify.org` | ipify | HTTPS |
| 2 | icanhazip | `https://ipv4.icanhazip.com` | `https://ipv6.icanhazip.com` | Cloudflare | HTTPS |
| 3 | ifconfig.co | `https://ifconfig.co/ip` (v4-pinned dial) | same (v6-pinned dial) | Martin Trigaux | HTTPS |
| 4 | ident.me | `https://4.ident.me` | `https://6.ident.me` | Pierre Carrier | HTTPS |
| 5 | OpenDNS DNS | DNS A `myip.opendns.com @ resolver1.opendns.com` | DNS AAAA `myip.opendns.com @ resolver1.ipv6-sandbox.opendns.com` | Cisco/OpenDNS | DNS |
| 6 | AWS checkip | `https://checkip.amazonaws.com/` | (v4-only) | Amazon | HTTPS |
| 7 | ipinfo.io | `https://ipinfo.io/ip` | same (returns v6 when reached over v6) | IPinfo | HTTPS |
| 8 | wtfismyip | `https://ipv4.wtfismyip.com/text` | `https://ipv6.wtfismyip.com/text` | independent | HTTPS |
| 9 | seeip | `https://ipv4.seeip.org` | `https://ipv6.seeip.org` | independent | HTTPS |

v6-incapable providers are skipped from the v6 pool automatically.

### Quorum rule (configurable, simple-majority default)

```
k       = number of providers to query each cycle (default: 3)
quorum  = floor(k / 2) + 1     # simple majority

  k=3 → quorum=2
  k=5 → quorum=3
  k=7 → quorum=4
  k=9 → quorum=5
```

**Per cycle, per address family (v4 and v6 tracked independently):**

1. Shuffle the eligible providers for that family.
2. Query the first `k`. Per-request timeout default 5s; non-2xx, parse error,
   or timeout = "no result".
3. If any IP value has ≥`quorum` matching results → confirmed.
4. Otherwise, expand the query set by `+2` (or until exhausted), re-tally with
   the simple-majority rule. Repeat until confirmed or exhausted.
5. If exhausted without quorum → log warning, **no checkin this cycle**.

Operators can override `k`, the provider list/order, the per-request timeout,
and the address family. Per-family policy: report any family that's confirmed
and changed; absence of v6 connectivity is treated as "v6 unconfirmed", not an
error.

### Main loop (`diyddns-client run`)

```
loop:
  poll_interval (default: 5m)
  ├── run quorum discovery for v4 + v6
  ├── compare to state.json
  ├── if changed → POST /agent/v1/checkin (HMAC-signed)
  │       retry on 5xx with exponential backoff (initial 2s, max 5 tries)
  │       then drop and re-try next cycle
  ├── on 2xx → update state.json
  ├── on 401 → log error; do NOT loop-burn; back off to 1h until operator
  │       runs `diyddns-client rotate` or re-enrolls
  └── sleep poll_interval ± 10% jitter
```

Graceful shutdown on SIGTERM/SIGINT.

### Enrollment (`diyddns-client enroll`)

Three modes via flags; mutually exclusive:

```
diyddns-client enroll --server <url> --code <code>             # path A, non-interactive
diyddns-client enroll --server <url> --code -                  # path A, code from stdin
diyddns-client enroll --server <url>                           # path A, interactive prompt
diyddns-client enroll --server <url> --user <email>            # path C, prompts for password
diyddns-client enroll --server <url> --oidc                    # path C, OIDC device-code flow
                                                                #   only when /agent/v1/capabilities
                                                                #   reports OIDC enabled
```

On success: client writes `credentials.json` (0600) and exits.
On failure: clear error message; no partial files written.

---

## 7. Web UI

**Stack:** Vite + React + TypeScript + `antd` + `@ant-design/pro-components`.
Routing: React Router v6+. Data: TanStack Query. Build output → `ui/dist`,
embedded into the server binary via `embed.FS`.

### Page map

```
/                                 → redirects to /devices (auth) or /login (anon)

# Anonymous
/login                            → local username/password (hidden from menu when
                                    config.hide_local_login_ui = true; route stays live)
                                  → "Sign in with <provider>" button when OIDC enabled
/oidc/callback                    → OIDC callback handler
/bootstrap                        → first-run admin claim form (410 once consumed)

# Authenticated (user)
/devices                          → ProTable: my devices
/devices/new                      → drawer/modal: label → enrollment code shown
/devices/:id                      → detail page: current IP(s), metadata, danger zone
/devices/:id/history              → ProTable: paginated IP history
/account                          → profile: change password (if local), linked OIDC info, sessions

# Authenticated (admin) — additional
/admin/users                      → ProTable: users (role, disabled, last login)
/admin/users/new                  → create local user
/admin/users/:id                  → edit: role, disable, force-reset
/admin/devices                    → ProTable: all devices (cross-user)
/admin/audit                      → ProTable + filters: audit log
/admin/server                     → server info + tunable settings
                                    (retention, hide_local_login_ui)
```

### Component usage

- **`ProLayout`** — top/side nav shell. Menu items filtered by role.
- **`ProTable`** — every list view. Built-in search, pagination, column toggles,
  refresh.
- **`ProForm` / `ModalForm` / `DrawerForm`** — every form.
- **`ProDescriptions`** — device detail and user detail readouts.
- **`Statistic` / `StatisticCard`** — admin dashboard counts.
- **`Result`** — empty states, errors, success after enrollment-code generation.
- **`Tag`** — role badges, status (online/stale/disabled).
- **`Modal.confirm`** — destructive action confirmations.
- **`message` / `notification`** — feedback toasts.

### Non-antd UI dependencies (intentional, narrow)

- `react`, `react-dom`, `react-router-dom`
- `@tanstack/react-query`
- `dayjs` (already an antd peer dep — used for time formatting)

No CSS framework. No styled-components. antd's design tokens (`ConfigProvider`
theme) are the only theming layer.

### Auth UX detail

- **Login page**: shows OIDC button if `capabilities.oidc_enabled`. Local form
  is shown unless `capabilities.hide_local_login_ui = true`.
- **Hidden-but-reachable**: `/login` always responds; the menu/UI just doesn't
  link to it.
- **CSRF handling**: A small `apiClient` wrapper reads the CSRF token from
  `/api/v1/auth/me`, attaches `X-CSRF-Token` to every mutating request, refreshes
  on `403-csrf` responses.
- **Session expiry**: TanStack Query's `onError` global handler redirects to
  `/login` on 401.

### Build pipeline (in Taskfile)

```
task ui:install          → npm ci
task ui:gen-types        → openapi-typescript docs/openapi/api.json
                           → ui/src/api/types.gen.ts
task ui:dev              → vite dev server on :5173, proxies /api and /agent to :8080
task ui:lint             → eslint + prettier
task ui:test             → vitest (component tests for non-trivial UI logic)
task ui:build            → vite build → ui/dist
```

UI assets are embedded in the server via:

```go
//go:embed all:dist
var uiFS embed.FS
```

served at `/` with a SPA fallback (any unknown non-`/api` and non-`/agent` path
returns `index.html`).

---

## 8. Configuration & Deployment

### Loader

`viper` with this precedence (highest wins):

```
CLI flags  >  ENV vars (DIYDDNS_*)  >  config file (yaml)  >  built-in defaults
```

Config file paths (searched in order, first found wins):

| Binary | Linux/macOS | Windows | Override |
|---|---|---|---|
| Server | `/etc/diyddns/server.yaml`, `$XDG_CONFIG_HOME/diyddns/server.yaml` | `%PROGRAMDATA%\diyddns\server.yaml`, `%APPDATA%\diyddns\server.yaml` | `--config <path>` |
| Client | `$XDG_CONFIG_HOME/diyddns/config.yaml` | `%APPDATA%\diyddns\config.yaml` | `--config <path>` |

ENV var convention: `DIYDDNS_<SECTION>_<KEY>` (e.g. `DIYDDNS_TLS_MODE=acme`).

**Secret indirection:** any string field accepts `${file:/path}` (read at startup)
or `${env:VAR}` for clean systemd / container patterns.

### Server configuration

```yaml
# /etc/diyddns/server.yaml
server:
  listen: ":8080"               # HTTP listener (when tls.mode=plain)
  base_url: "https://ddns.example.com"   # used in OIDC redirects, bootstrap link, etc.
  trusted_proxies: []           # CIDRs whose X-Forwarded-* headers will be honored

tls:
  mode: plain                   # plain | cert | acme
  # mode=cert
  cert_file: ""
  key_file: ""
  # mode=acme
  acme_domain: ""               # required for acme
  acme_email: ""
  acme_cache_dir: "/var/lib/diyddns/acme"
  acme_listen: ":443"
  acme_http_listen: ":80"       # autocert needs :80 for HTTP-01

database:
  path: "/var/lib/diyddns/diyddns.db"
  busy_timeout: 5s
  wal: true

auth:
  session:
    cookie_name: "diyddns_session"
    cookie_secure: true         # forced true when tls.mode != plain or X-Forwarded-Proto=https
    cookie_samesite: "lax"
    ttl: 720h                   # 30 days, sliding
  hmac:
    skew_window: 120s
    nonce_ttl: 120s              # must be >= skew_window (validated at startup)
    secret_key: ""              # base64 of 32 bytes (AES-256 master key sealing device secrets); required — server fails closed if empty/invalid. Use ${file:} / ${env:}. (Plan 04 D1/D4)
  password:
    argon2id:
      time: 3
      memory_kib: 65536
      parallelism: 2
    min_length: 12
  oidc:
    enabled: false
    issuer: ""
    client_id: ""
    client_secret: ""
    scopes: ["openid", "profile", "email"]
    auto_link_by_email: true
    allow_oidc_signup: true
    hide_local_login_ui: false
  bootstrap:
    admin_email: ""             # equiv to DIYDDNS_BOOTSTRAP_ADMIN_EMAIL
    admin_password: ""          # equiv to DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD

retention:
  ip_history_days: 90           # 0 = unlimited (still respects per_device_max)
  ip_history_per_device_max: 1000
  audit_log_days: 365
  always_keep_latest: true      # locked: latest record per device is never pruned
  prune_interval: 1h

ratelimit:
  agent_checkin_per_device: "60/hour"
  agent_enroll_per_ip: "20/hour"
  ui_login_per_ip: "20/min"
  algorithm: "token_bucket"

logging:
  level: info                   # debug | info | warn | error
  format: json                  # json | text
  output: stderr                # stderr | stdout | <path>

observability:
  request_id_header: "X-Request-Id"
```

### Client configuration

```yaml
# ~/.config/diyddns/config.yaml
server:
  url: "https://ddns.example.com"
  ca_bundle: ""                 # optional, for self-signed in homelab

ipdiscovery:
  query_count: 3                # k
  request_timeout: 5s
  cycle_interval: 5m
  family: both                  # both | ipv4 | ipv6
  providers:                    # ordered; if overridden, replaces defaults entirely
    - ipify
    - icanhazip
    - ifconfig_co
    - ident_me
    - opendns_dns
    - aws_checkip
    - ipinfo
    - wtfismyip
    - seeip

reporting:
  jitter_pct: 10
  retry_max: 5
  retry_initial_backoff: 2s
  reauth_backoff: 1h            # cooldown after persistent 401

logging:
  level: info
  format: text                  # text default for client (interactive); json available
```

### Deployment shapes

#### A. systemd (recommended for Linux servers)

`packaging/systemd/diyddns-server.service`:

```ini
[Unit]
Description=DIYDDNS server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/diyddns-server --config /etc/diyddns/server.yaml
User=diyddns
Group=diyddns
StateDirectory=diyddns
ConfigurationDirectory=diyddns
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
RestartSec=5
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`packaging/systemd/diyddns-client.service` (system-wide):

```ini
[Unit]
Description=DIYDDNS client (public-IP reporter)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/diyddns-client run --config /etc/diyddns/client.yaml
User=diyddns
Group=diyddns
StateDirectory=diyddns
ConfigurationDirectory=diyddns
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestartSec=5
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

A user-mode unit also ships at `packaging/systemd/user/diyddns-client.service`
for `systemctl --user enable diyddns-client` (per-user installs on Linux
desktops); that variant uses XDG paths and runs as the invoking user.

#### B. Docker / OCI image

Two images (separate Dockerfiles):
- `ghcr.io/jacaudi/diyddns-server`
- `ghcr.io/jacaudi/diyddns-client`

Static binaries (pure-Go, no CGO), `scratch` or `distroless/static` base. Volume
for the SQLite DB. `docker-compose.yaml` sample shipped under
`packaging/docker/`.

#### C. Single binaries

Run directly. Useful for quick trials. macOS clients via `launchd` (sample plist
under `packaging/launchd/`).

#### Reverse-proxy samples

Caddy, nginx, and Traefik samples under `packaging/proxy/` for the default
`tls.mode=plain` deployment.

---

## 9. Observability, Testing, Build

### Logging

- **Library:** stdlib `log/slog`. JSON handler in production
  (`format: json`), text handler in dev (`format: text`).
- **Standard fields on every line:** `time`, `level`, `msg`, `request_id`,
  `actor` (user_id or device_id when known), `route`, `remote_ip`.
- **Levels:** `debug` (verbose flow), `info` (lifecycle/auth/checkin), `warn`
  (degraded — quorum miss, rate-limit triggered, config drift), `error`
  (verification failed, DB error, panic-recovered).
- **Server access log** is one structured `info` line per request (request_id,
  method, path, status, duration_ms, bytes_out). Sensitive headers (cookies,
  signature, authorization) are never logged.

### Health & request tracing

- `/healthz` — liveness. Always 200 if process is up.
- `/readyz` — readiness. 200 only when DB is reachable and goose-applied schema
  version ≥ minimum required.
- **Request ID** middleware: honors incoming `X-Request-Id`; generates UUIDv7 if
  absent; echoes in response and includes in every log line and audit row for
  that request.

### Metrics (deferred, but designed-for)

No Prometheus dependency in v1. Internal counters
(`checkin_total{result}`, `auth_login_total{result}`, `quorum_miss_total{family}`)
are tracked as `slog`-emitted fields in v1; a Prometheus collector that
subscribes to the same hooks is a future, additive change.

### Testing

**Library:** stdlib `testing` only. Table-driven where inputs are enumerable.
No `testify`, no `gocheck`. Helpers via `t.Helper()`.

**Layers:**

1. **Unit tests** — pure functions: HMAC sign/verify, quorum tally, retention
   prune SQL, password hashing wrapper, config loader, IP-discovery provider
   parsers. Each lives next to its package as `*_test.go`. Deterministic, no
   I/O.
2. **Integration tests** — `internal/store` against a real `modernc.org/sqlite`
   DB in a temp dir; `internal/server/api` against `httptest.Server` with a
   real DB. Goose migrations applied per test; teardown removes the DB.
3. **End-to-end test (one happy path)** — spin up the server in a goroutine,
   run the client binary via `os/exec`, verify enrollment → checkin → history
   row.
4. **IP-discovery provider tests** — each provider has a `RoundTripper` mock
   that returns fixture bytes. **No live network calls in the default test
   suite.** A separate `task test:net` runs live-network smoke tests (skipped
   by default) for bumping defaults or debugging provider drift.

**Coverage target:** 80% line coverage on `internal/*`, 100% on the HMAC
sign/verify and the retention prune.

**Race detector:** all `go test` invocations in CI use `-race`.

### Linting & formatting

- `golangci-lint` with `.golangci.yml` enabling: `errcheck`, `govet`,
  `staticcheck`, `revive`, `gocritic`, `bodyclose`, `gosec`, `misspell`,
  `errorlint` (catches non-`%w` wrapping mistakes), `nolintlint` (forbids
  unjustified `//nolint`).
- `go fmt` and `goimports` enforced.
- UI: `eslint` (with `@typescript-eslint`, `react`, `react-hooks` plugins) +
  `prettier`. CI fails on lint errors.

### OpenAPI & types

- huma generates the OpenAPI specs at server startup; served at
  `/api/openapi.json` and `/agent/openapi.json` (separate documents).
- Scalar UI mounted at `/api/docs` and `/agent/docs`.
- `task openapi` dumps both specs to `docs/openapi/api.json` and
  `docs/openapi/agent.json` for diffing in PRs and consumption by the UI build.
- `task ui:gen-types` runs `openapi-typescript docs/openapi/api.json -o
  ui/src/api/types.gen.ts`.

### Taskfile (canonical entrypoints)

```
task                       → list tasks (default)
task build                 → ui:build && go build -o bin/ ./cmd/...
task test                  → go test ./... -race
task test:net              → live-network smoke tests (opt-in)
task lint                  → golangci-lint run + ui:lint
task fmt                   → go fmt + goimports + ui:fmt
task openapi               → start server, dump specs to docs/openapi/, stop
task ui:install            → npm ci in ui/
task ui:gen-types          → openapi-typescript → ui/src/api/types.gen.ts
task ui:dev                → vite dev server
task ui:build              → vite build → ui/dist
task ui:test               → vitest
task ui:lint               → eslint + prettier --check
task ui:fmt                → eslint --fix + prettier --write
task migrate:new <name>    → goose -dir migrations create <name> sql
task db:backup <out>       → safely back up the SQLite DB
task release               → cross-compile (linux/darwin/windows × amd64/arm64)
task clean                 → rm -rf ui/dist bin/ docs/openapi/
```

### CI / Release (GitHub Actions)

CI/CD is implemented as thin wrappers that call reusable components from
**`jacaudi/github-actions`**. We do not write custom lint/test/release logic —
we configure the components.

The shared repo documents a **three-stage pipeline** for Go projects (PR → main
→ release-tag). DIYDDNS adopts that pattern:

#### Stage 1 — PR pipeline (`.github/workflows/pr.yml`)

Triggers: `pull_request` against `main`.

Calls (each via `uses: jacaudi/github-actions/.github/workflows/<file>@<ref>`):
- `component-lint.yml` with `go: true`, `yaml: true`, `json: true`,
  `shell: true` — covers Go (`golangci-lint`), workflow YAML, JSON,
  shell scripts.
- `component-test.yml` — runs `go test ./... -race` with coverage.
- `component-container-build.yml` — multi-arch container build for both server
  and client images **without push** (verifies the Dockerfiles still build).

A small repo-local job in `pr.yml` runs `task ui:lint`, `task ui:test`, and
`task ui:build` (the shared components don't cover Vite/React directly), plus
`task build` for the Go cross-compile matrix.

CodeQL runs as a sibling workflow (`.github/workflows/codeql.yml`) — not part
of the shared repo's components.

#### Stage 2 — Main pipeline (`.github/workflows/ci.yml`)

Triggers: `push` to `main` (after squash-merge).

Calls:
- `component-lint.yml` (full set as in PR).
- `component-test.yml`.
- `component-semantic-release.yml` — drives versioning from Conventional
  Commits, creates the tag, creates the GitHub Release, updates
  `CHANGELOG.md`. Requires repo secrets `APP_ID` and `APP_PRIVATE_KEY` (a
  GitHub App so the pushed tag triggers Stage 3 — `GITHUB_TOKEN`-pushed tags
  don't trigger downstream workflows).

#### Stage 3 — Release pipeline (`.github/workflows/release.yml`)

Triggers: `push: tags: ['v*']`.

Calls:
- `component-container-build.yml` (with push) — builds and pushes
  `ghcr.io/jacaudi/diyddns-server` and `ghcr.io/jacaudi/diyddns-client`
  (multi-arch: amd64, arm64).
- `component-pipeline-summary.yml` — produces a single artifact rolling up
  pipeline metadata.

A small repo-local job runs `task release` to produce native binary archives
(linux/darwin/windows × amd64/arm64) and attaches them to the GitHub Release
created in Stage 2.

#### Required repo configuration

Set in **Settings → Secrets and variables → Actions**.

**Variables:**
| Variable | Value | Notes |
|---|---|---|
| `GO_VERSION` | `stable` | shared component default; keep latest stable Go |
| `TEST_PACKAGES` | `./...` | default |
| `COVERAGE_THRESHOLD` | `80` | matches the design's coverage target on `internal/*` |

**Secrets:**
| Secret | Used by | Notes |
|---|---|---|
| `APP_ID` | `component-semantic-release.yml` | GitHub App ID with `contents: write` and `pull-requests: write` |
| `APP_PRIVATE_KEY` | `component-semantic-release.yml` | GitHub App private key |

The shared repo uses **semantic-release**, which manages tags, GitHub Releases,
and `CHANGELOG.md` automatically based on Conventional Commits — so the project
follows Conventional Commits strictly (already specified in Section 13).

---

## 10. Security Considerations

- **HMAC at rest:** device secrets stored AES-256-GCM-sealed under the server
  master key `auth.hmac.secret_key` (never argon2id — HMAC verification needs the
  recoverable secret bytes; Plan 04 D1). In-memory cache populated lazily by
  decrypting the stored ciphertext, evicted on rotation/disable. The server fails
  closed at startup if the master key is missing or not 32 bytes.
- **Replay defense:** timestamp skew window (120 s) + per-signature nonce table
  (also 120 s) on `/agent/v1/*` authenticated routes.
- **Password hashing:** argon2id with explicit parameters; minimum length 12;
  CSRF-protected change endpoint.
- **Session security:** HttpOnly + Secure (forced when TLS active) + SameSite=Lax
  cookies; CSRF tokens on all mutating browser requests; rotated on login.
- **Rate limits:** per-IP on enroll and login; per-device on checkin.
- **OIDC:** PKCE on the browser flow; `state` cookie for CSRF on the auth-code
  callback; admin-controlled auto-link policy.
- **Audit log:** every auth and lifecycle event with actor + IP + UA.
- **Secrets in logs:** cookies, signatures, tokens, and Authorization-style
  headers are never logged.
- **TLS:** the server is designed to work safely behind a TLS-terminating proxy
  (default mode), with native TLS (operator certs or ACME) as opt-in alternatives.
  When a proxy is configured (`server.trusted_proxies`), `X-Forwarded-Proto` and
  `X-Forwarded-For` are respected; otherwise they are ignored to prevent header
  spoofing.

---

## 11. Module / Component Boundaries

| Package | Public surface | Depends on | Notes |
|---|---|---|---|
| `internal/shared` | HMAC envelope types, capability types | (stdlib only) | Imported by both binaries; no I/O |
| `internal/auth` | Sign/Verify, Sessions, CSRF, OIDC, password hashing | `shared`, `store`, `crypto` | Pure logic + DB-backed session store |
| `internal/store` | DB open, migrations, repositories | `modernc.org/sqlite`, `goose` | Repository pattern per aggregate |
| `internal/server/service` | Device, user, history, audit, enrollment services | `auth`, `store` | Application logic; no HTTP types |
| `internal/server/api` | huma operation handlers | `service`, `auth`, `shared` | HTTP/JSON adapter layer |
| `internal/server/middleware` | request-id, auth, rate-limit, recover | `auth`, `slog` | Composable; route-group-specific |
| `internal/client/ipdiscovery` | Provider interface, defaults, quorum tally | (stdlib + `net/http`) | Each provider is a small module; mockable RoundTripper |
| `internal/client/poller` | Run loop | `ipdiscovery`, `auth`, `shared` | Reads/writes state.json |
| `internal/client/enroll` | Enrollment flows | `shared`, `auth` (sign), `net/http` | Code, credentials, OIDC device-code paths |
| `internal/config` | viper loaders for server + client | `viper` | One loader per binary; struct-tagged |

Every component has a single clear purpose. Cross-component communication is
via interfaces declared by the consumer, not the producer.

---

## 12. Future Work (out of scope for v1)

Documented for context; do **not** build in v1.

1. **Heartbeat endpoint** to detect dead clients (move from change-driven to
   change-driven + heartbeat). Schema already supports this; only adds an API
   route and a UI column ("Last seen" vs "Last change").
2. **Prometheus `/metrics` endpoint** wired to existing internal counters.
3. **Multiple OIDC providers** (currently single).
4. **Per-device tags / categories** for filtering in the UI.
5. **Webhooks on IP change** (notify external systems when a device's IP
   changes).
6. **Server-observed IP fallback** for when client-side discovery fails (server
   records the source IP from the TCP connection as a secondary signal).
7. **mTLS option** for device → server authentication as an alternative to HMAC.

---

## 13. Repository Conventions (GitHub)

This project will be hosted on GitHub. The repo follows standard GitHub OSS
conventions.

### Files at repo root

- `README.md` — project pitch, install/run quickstart, screenshots, links to
  `docs/`. Required.
- `LICENSE` — **MIT**.
- `CHANGELOG.md` — managed automatically by semantic-release (driven from
  Conventional Commits); not edited by hand.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 (text-as-is).
- `CONTRIBUTING.md` — how to run locally, run tests, submit PRs, signing
  expectations.
- `SECURITY.md` — disclosure policy and contact (private vulnerability
  reporting via GitHub Security Advisories enabled in repo settings).
- `.gitignore` — covers Go (`bin/`), Node (`node_modules/`, `ui/dist/`), env
  files (`.env`, `.env.*`), IDE artifacts (`.idea/`, `.vscode/` except shared
  parts), OS junk, and the embedded build output.
- `.editorconfig` — for cross-editor consistency.

### `.github/`

- `workflows/pr.yml` — PR pipeline (Section 9, Stage 1).
- `workflows/ci.yml` — main pipeline, semantic-release (Section 9, Stage 2).
- `workflows/release.yml` — tag pipeline (Section 9, Stage 3).
- `workflows/codeql.yml` — CodeQL scanning (Go + JS/TS), weekly + on PR.
- `CODEOWNERS` — owners listed; required-review rules.
- `PULL_REQUEST_TEMPLATE.md` — what changed, why, test plan, screenshots for UI
  changes, links to issues.
- `ISSUE_TEMPLATE/bug_report.md` — repro, expected vs actual, server/client
  version, OS.
- `ISSUE_TEMPLATE/feature_request.md` — problem, proposed solution,
  alternatives.

### Branch & PR conventions

- Default branch: `main`. Protected: PR-only, required reviews from CODEOWNERS,
  required CI checks (lint, test, build matrix, CodeQL), linear history, signed
  commits encouraged.
- Branches: `feat/<topic>`, `fix/<topic>`, `chore/<topic>`,
  `docs/<topic>`.
- Commits: Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`,
  `refactor:`, `test:`, `build:`, `ci:`); `BREAKING CHANGE:` footer when
  applicable. Enables automated changelog generation.
- PR title mirrors a Conventional Commit; squash-merged into `main`.

### Versioning & releases

- SemVer. Tags `vMAJOR.MINOR.PATCH`, generated by **semantic-release** from
  Conventional Commits. Pre-releases use `-rc.N` / `-beta.N` suffixes when
  configured.
- The `jacaudi/github-actions` `component-semantic-release.yml` workflow
  manages tags, GitHub Releases, and `CHANGELOG.md` updates automatically.
  Manual tag creation is not used.
- Release artifacts (per Stage 3 in Section 9): multi-arch container images on
  GHCR plus native binary archives attached to the GitHub Release.
- The shared workflow does not currently emit cosign signatures or SBOMs. If
  those become required they ship as a follow-up — added either to the shared
  repo or as a repo-local addendum job.

---

## 14. Acceptance Criteria for v1

- A new operator can `git clone`, `task build`, run `diyddns-server`, claim the
  bootstrap admin via `/bootstrap`, log in, and create a device — generating an
  enrollment code shown in the UI.
- That code, used by `diyddns-client enroll --code <code> --server <url>`,
  yields a working credentials file. `diyddns-client run` confirms a public IP
  via quorum and posts a check-in that appears in the UI within one cycle.
- Local user auth and OIDC auth (when configured) both produce working web
  sessions; the local-login UI hides cleanly when configured to.
- HMAC-signed checkins are rejected when timestamp is outside the skew window,
  when nonce is replayed, when the device is disabled, and when the signature
  is invalid.
- Retention prune respects `always_keep_latest`: a device with only one history
  row never has it deleted regardless of policy.
- All endpoints appear in the served OpenAPI spec; Scalar UIs render at
  `/api/docs` and `/agent/docs`.
- Cross-compile produces working static binaries for `{linux,darwin,windows}` ×
  `{amd64,arm64}` without a C toolchain (verified by CI matrix).
- `golangci-lint run` is clean; `go test ./... -race` passes; UI lints and
  builds; `openapi-typescript`-generated UI types compile.
