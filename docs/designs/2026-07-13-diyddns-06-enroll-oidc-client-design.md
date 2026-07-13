# DIYDDNS Plan 06 — `enroll --oidc` Client (Design)

- **Type:** Design
- **Feature:** diyddns-06-enroll-oidc-client
- **Date:** 2026-07-13
- **Author:** brainstormed with the user, session of 2026-07-13
- **Base:** `origin/main` @ `d829309` (Plan 05 OIDC merged via PR #17)
- **Parent spec:** `docs/plans/2026-05-01-diyddns-design.md` (§2 layout, §4 endpoints, §6 client, §8 config, §11 boundaries)
- **Builds on:** `docs/designs/2026-07-13-diyddns-05-oidc-design.md` (D1 defers this client to Plan 06; D4 the `oidc_device_enabled` capability + 501-when-unsupported)

---

## 1. Purpose & scope

Plan 05 delivered the **server side** of RFC 8628 device-code enrollment
(`POST /agent/v1/enroll/oidc/start` + `/poll`). Plan 06 builds the **client side**:
the `diyddns-client enroll --oidc` command that drives that flow end to end and
persists the resulting device credentials for future HMAC-signed check-ins.

Concretely, Plan 06 delivers a **single vertical** — the OIDC device-code enrollment
path — plus the minimal client foundation it is the first to require:

- **`enroll --oidc` command** — starts the device flow, prints the `user_code` +
  `verification_uri` for the user to authorize in a browser, polls until the server
  returns `{device_id, secret}`, and writes `credentials.json`.
- **Client CLI foundation** — `spf13/cobra` root + `enroll`/`version` subcommands,
  replacing the current `flag`-based `--version` scaffold.
- **Client config loader** — `spf13/viper` (precedence flags > env > file > defaults),
  binding only the keys this vertical needs today (`server.url`, `server.ca_bundle`,
  `logging.{level,format}`).
- **Credentials store** — `internal/client/credentials`: read/write `credentials.json`
  (`{server_url, device_id, secret}`, mode `0600`, atomic).

### Critical constraint (inherited, non-negotiable)

The client binary stays **free of server-only dependencies** — `huma`,
`golang.org/x/oauth2`, `coreos/go-oidc`, `go-jose`. It performs the device-code flow
with **`net/http` + `encoding/json` only** (plus `crypto/tls`/`crypto/x509` for
`--ca-cert`, and the shared `cobra`/`viper`). **No token verification happens on the
client** — the server owns all OIDC/JWT logic; the client only exchanges the opaque
`flow_id`. `cmd/diyddns-client/deps_test.go` enforces this and must stay green.

### Decisions locked in this session

| # | Decision | Rationale |
|---|---|---|
| D1 | **OIDC-only vertical** — build just `enroll --oidc`; defer the `--code`/`--user` enroll modes and `run`/`status`/`rotate` | YAGNI. OIDC is the capability Plan 05 just delivered server-side; this closes that loop with the smallest coherent slice. Built in the spec's `internal/client/enroll` home so the other modes are additive siblings later (No-Wall). |
| D2 | **cobra + viper foundation now** | Spec §6 mandates cobra subcommands; the deferred `run`/`status`/`rotate` all need both. Establishing the root + config loader now makes those commands additive (new file + wiring). User-approved. |
| D3 | **`credentials` is its own package**, not part of `enroll` | `run`/`status`/`rotate` must *read* credentials without importing enrollment logic. A dedicated package is the clean consumer seam (No-Wall). |
| D4 | **`--ca-cert <path>` flag now** | Homelab servers commonly use self-signed TLS (spec §8 `ca_bundle`). Low-cost, genuinely useful; maps to the `server.ca_bundle` config key. User-approved. |
| D5 | **Refuse to overwrite existing `credentials.json`; require `--force`** | Protects a working device's HMAC secret from an accidental re-enroll clobber. |
| D6 | **Print `user_code`/`verification_uri` to stderr; no browser auto-open** | Device-code flow targets headless / second-screen devices where auto-open is usually wrong or impossible. |
| D7 | **Tolerate transient `502` (bounded); treat `410`/`401`/`501`/`500` as terminal** | A single IdP hiccup (`502`) shouldn't abort a live authorization; a denial/rejection/unsupported/internal error should stop promptly with a clear message. |
| D8 | **No shared `serverapi` HTTP client** — enroll's client is local to `internal/client/enroll` | The future check-in client is **HMAC-signed** and unauthenticated-enroll is not; unifying now would be the wrong abstraction. Unify only when a second consumer proves the shape. |
| D9 | **Client defines its own wire structs; `internal/shared` consolidation deferred** | Spec §11 homes capability/enroll DTOs in `internal/shared` (stdlib, both binaries). Plan 05's server DTOs live in `internal/server/api` (huma-adjacent, client can't import). Rather than pull a server refactor into a client plan, Plan 06 defines the minimal structs it needs locally and files the single-source consolidation as a named follow-up (§8.5). The wire contract is small and pinned by §3 + tests. |

### Non-goals (explicitly deferred)

- **`enroll --code` / `enroll --user` (credentials) modes** → a later client plan; they slot into `internal/client/enroll` additively.
- **`run` (poll loop + IP discovery + HMAC checkin), `status`, `rotate`** → later client plans; `run` will need the HMAC-signing client and `internal/client/{poller,ipdiscovery}` per spec §11.
- **Full client config** (`ipdiscovery`, `reporting` sections) → wired when `run` lands; Plan 06 binds only the enroll-relevant keys.
- **Windows `%LOCALAPPDATA%` credentials path** (spec §6) — Plan 06 uses `os.UserConfigDir()` (→ `%AppData%` on Windows); the Windows-specific divergence is a documented follow-up (see §8).

---

## 2. Architecture & package layout

Homes are those the parent spec already reserves (§2 repo layout, §11 boundaries).

```
cmd/diyddns-client/
  root.go        # cobra root command + viper wiring (flags > env > file > defaults)
  enroll.go      # `enroll` command: flags, orchestration, stderr UX
  version.go     # `version` subcommand (migrated off the flag scaffold)
  main.go        # thin: rootCmd.Execute()
  deps_test.go   # UNCHANGED — still forbids huma/oauth2/go-oidc/go-jose

internal/client/enroll/
  oidc.go        # OIDC device-code driver: Start → poll loop → EnrollResult
  client.go      # unauthenticated net/http client for /agent/v1
                 #   (Capabilities, OIDCDeviceStart, OIDCDevicePoll) + --ca-cert TLS
  errors.go      # typed sentinels (ErrDeviceUnsupported, ErrFlowGone, …)

internal/client/credentials/
  credentials.go # Credentials{ServerURL, DeviceID, Secret}; Load / Save / Path
                 #   (0600, atomic tmp+rename, refuse-exists unless force)

internal/config/
  client.go      # viper client loader — minimal (server.url, server.ca_bundle,
                 #   logging.{level,format}); grows sections as run/status land
```

**Dependency direction:** `cmd/diyddns-client` → `internal/client/enroll`,
`internal/client/credentials`, `internal/config`. `enroll` and `credentials` do **not**
depend on each other — the command layer wires them together. `internal/shared` (HMAC
wire, capability types) is available but **not required by this vertical** (enroll is
unauthenticated; signing arrives with `run`). If `internal/config` reuses the capability
struct, it does so via `internal/shared` (stdlib-only), never `internal/server/api`.

### Why viper (weight trade-off, recorded)

viper pulls a sizeable transitive tree (fsnotify, mapstructure, format parsers), in mild
tension with spec §2's "keep the client binary small and portable." None of those are
in the forbidden-four, so `deps_test` stays green. This is a **user-approved** trade:
establishing the client config loader now makes `run`/`status`/`rotate` additive.
Mitigation: bind only the minimal keys; do not import optional viper format backends.

---

## 3. Wire contract consumed (from Plan 05, verbatim)

The client is a pure consumer of these server endpoints (source of truth:
`internal/server/api/enroll_oidc.go`, `capabilities.go`).

**`GET /agent/v1/capabilities`** → `200`:
```json
{ "server_version": "...", "skew_window_seconds": 120,
  "address_families": ["ipv4","ipv6"],
  "oidc_enabled": true, "oidc_device_enabled": true }
```

**`POST /agent/v1/enroll/oidc/start`** (empty body):
| Status | Meaning | Client action |
|---|---|---|
| `200` `{flow_id, user_code, verification_uri, verification_uri_complete?, expires_in, interval}` | flow started | display + begin polling |
| `501` | device flow unavailable | terminal: "server does not support OIDC device enrollment" |
| `502` | IdP device-start failed | terminal: "could not start OIDC device flow" |
| `500` | server internal error | terminal: generic error |

**`POST /agent/v1/enroll/oidc/poll`** `{flow_id}`:
| Status / body | Meaning | Client action |
|---|---|---|
| `200 {status:"pending"}` | not yet authorized | wait `interval`, poll again |
| `200 {status:"slow_down"}` | poll less often (or polled too fast) | `interval += 5s`, poll again |
| `200 {device_id, secret}` (no `status`, **both non-empty**) | **success** — `secret` is base64 | validate, write credentials, done |
| `410` | flow gone / denied / expired | terminal: "authorization denied or expired" |
| `401` | user resolved but enrollment rejected | terminal: "enrollment not authorized" |
| `502` | IdP poll failed | transient: warn, bump, continue (bounded — D7) |
| `500` | server internal error | terminal: generic error |

Notes: `secret` is base64 on the wire (`base64.StdEncoding`) and is the device's HMAC
key. `flow_id` is an opaque 32-byte token; the underlying IdP `device_code` never
reaches the client.

---

## 4. Data flow — `enroll --oidc`

```
diyddns-client enroll --oidc --server <url> [--ca-cert PATH] [--force]
                       [--credentials-file PATH]

1. Resolve server URL (flag > env > config); require non-empty, scheme http|https;
   trim trailing slash.
2. Build HTTP client: system trust, or a CA pool loaded from --ca-cert /
   server.ca_bundle; per-request timeout (~10s).
3. Guard credentials FIRST: if credentials.json exists and !--force → error & exit,
   BEFORE contacting the server (don't spend an IdP device_code needlessly).
4. Pre-check GET /agent/v1/capabilities:
      oidc_device_enabled == false → clear "not supported" error & exit.
   (If the endpoint itself errors/unreachable → connection error & exit.)
5. POST /agent/v1/enroll/oidc/start:
      200 → {flow_id, user_code, verification_uri, verification_uri_complete,
             expires_in, interval}
      501/502/500 → terminal error & exit.
6. Guard expires_in <= 0 (clock skew / already-expired) → ErrExpired & exit.
   Print to stderr:
      "To authorize this device, visit:  <verification_uri>"
      "and enter code:                    <user_code>"
      "(or open directly:                 <verification_uri_complete>)"   ← only if non-empty
      "Waiting for authorization…"
   deadline = now + expires_in ;  poll_interval = max(interval, 5s)
7. POLL LOOP (honors context cancellation). The server initializes
   last_polled_at=0, so the FIRST poll is allowed immediately — poll first for
   snappy feedback, then sleep between polls:
      loop:
        POST /agent/v1/enroll/oidc/poll {flow_id}
          200 pending            → (fall through to sleep)
          200 slow_down          → poll_interval += 5s
          200 success            → REQUIRE non-empty device_id AND secret;
                                    else ErrProtocol. Else break with them.
          410                    → ErrFlowGone   → stop (terminal)
          401                    → ErrRejected   → stop (terminal)
          500                    → ErrServer     → stop (terminal)
          502                    → warn; poll_interval += 5s;
                                    after 3 CONSECUTIVE 502 → ErrBadGateway (terminal)
        if now >= deadline       → ErrExpired "device code expired; re-run enroll"
        sleep min(poll_interval, deadline-now)   ← capped so we never sleep past expiry
   (poll does NOT return 501 — that is a start-only status.)
8. SUCCESS: decode secret (base64) → write credentials.json
   {server_url, device_id, secret} atomically, mode 0600 (mkdir parent 0700).
   Print "Device <device_id> enrolled." to stderr. Exit 0.
```

**Ordering rationale:** the credentials-exists guard (step 3) runs before `start`
(step 5) so a re-enroll without `--force` fails instantly and never burns an IdP
device authorization. Capabilities pre-check (step 4) gives a clean early error, but
`start` still handles `501` defensively (capability could flip between calls).

---

## 5. Component contracts

### `internal/client/enroll` — the device-code driver

```go
package enroll

// Client is an unauthenticated HTTP client for the server's /agent/v1 enroll
// surface. Constructed with a base URL and optional custom CA.
type Client struct { /* baseURL, *http.Client */ }

func NewClient(baseURL string, opts ClientOptions) (*Client, error) // opts: CACertPath, Timeout

func (c *Client) Capabilities(ctx context.Context) (Capabilities, error)
func (c *Client) OIDCDeviceStart(ctx context.Context) (DeviceStart, error)
func (c *Client) OIDCDevicePoll(ctx context.Context, flowID string) (PollResult, error)

// DeviceCodeEnroll drives the full flow: start → display (via the Prompter) →
// poll loop → returns the minted credentials. It never writes files.
func DeviceCodeEnroll(ctx context.Context, c *Client, p Prompter, clk Clock) (Result, error)

// Prompter renders the user_code / verification_uri to the operator (stderr in
// prod; captured in tests). Clock abstracts sleep/now for hermetic timing tests.
type Prompter interface { ShowUserCode(DeviceStart); Waiting() }
type Clock interface { Now() time.Time; Sleep(ctx context.Context, d time.Duration) error }

type Result struct { DeviceID string; Secret string } // Secret = validated base64, stored verbatim
```

- `PollResult` is a small enum-ish struct: `{Kind: pending|slowDown|complete, DeviceID, Secret}`. On a `complete` poll, `DeviceID` and `Secret` are validated non-empty and the `Secret` base64 is validated by attempting a decode (bytes discarded); the original wire string is carried through verbatim. An empty-but-`200` body is an `ErrProtocol`, not a success.
- Transport-level statuses (`410`/`401`/`500`/`502` on poll; `501`/`502`/`500` on start) surface as the typed sentinels in `errors.go`, wrapped `%w`. `501` is a **start-only** status (`ErrDeviceUnsupported`); the poll handler never returns it.
- The `Clock` seam is what makes the poll-loop tests instant (no real sleeps) and lets `Sleep` return early on `ctx` cancellation.

### `internal/client/credentials`

```go
package credentials

type Credentials struct {
    ServerURL string `json:"server_url"`
    DeviceID  string `json:"device_id"`
    Secret    string `json:"secret"` // base64 (as received on the wire)
}

func DefaultPath() (string, error)                 // os.UserConfigDir()/diyddns/credentials.json
func Load(path string) (Credentials, error)        // ErrNotFound if absent
func Save(path string, c Credentials, force bool) error // 0600, atomic, refuse-exists unless force
```

- `Save`: `mkdir -p` parent (`0700`), write to `path + ".tmp"` (`0600`), `rename` over `path`. If `path` exists and `!force` → `ErrExists` (no write). `Credentials.Secret` holds the **wire base64 string verbatim** — `DeviceCodeEnroll` validates it by attempting a `base64.StdEncoding` decode (bytes discarded) so a malformed secret errors before any file is written, then stores the original string unchanged. No re-encode layer; the stored form is byte-identical to what the server sent, and the future check-in signer decodes it once at load.

### `internal/config` — client loader

```go
func LoadClient(v *viper.Viper) (ClientConfig, error)

type ClientConfig struct {
    Server  struct { URL, CABundle string }
    Logging struct { Level, Format string } // Format default "text" (spec §8)
}
```

- Precedence flags > env > file > defaults. **Carries Plan 03's gotcha:** `SetDefault` outranks an *unchanged* pflag default, so keep pflag defaults empty and set values via `SetDefault`, or bind pflags explicitly. Config file is optional — flags-only usage (`enroll --server … --oidc`) must work with no file present.

---

## 6. Error handling & security

- **No partial writes, ever.** `credentials.json` is written only on `PollComplete`,
  via tmp-file + atomic `rename`, mode `0600`. Every failure path exits non-zero with a
  clear, distinct message and writes nothing.
- **Secret hygiene.** `secret` (base64) is decoded and stored; **never logged, never
  printed**. `flow_id` is never logged (opaque but sensitive). The IdP `device_code`
  never reaches the client. `user_code` / `verification_uri` *are* printed — they are
  meant for the user.
- **Typed sentinels** (`enroll/errors.go`): `ErrDeviceUnsupported` (501, **start-only**),
  `ErrFlowGone` (410), `ErrRejected` (401), `ErrBadGateway` (502-exhausted),
  `ErrServer` (500), `ErrExpired` (deadline / `expires_in<=0`), `ErrProtocol`
  (200 success with empty `device_id`/`secret`, or malformed JSON). The command layer
  maps each to a specific operator message and a non-zero exit.
- **`502` policy (D7):** transient — warn to stderr, bump interval, continue; abort with
  `ErrBadGateway` only after **3 consecutive** `502`s or once `expires_in` elapses.
- **Cancellation.** `SIGINT`/`SIGTERM` cancels the root context; `Clock.Sleep` returns
  the context error, the loop unwinds cleanly, nothing is written.
- **TLS.** Default is the OS trust store. `--ca-cert` (or `server.ca_bundle`) loads a PEM
  into an `x509.CertPool` used as `tls.Config.RootCAs` for the enroll HTTP client. No
  `InsecureSkipVerify` option is exposed (that would be a footgun; a CA file is the safe
  path for self-signed homelab servers).

---

## 7. Testing strategy

- **`httptest.Server`** mock of `capabilities` / `start` / `poll`, driving table-driven
  scenarios through `DeviceCodeEnroll`: `pending→pending→complete`, `slow_down` backoff,
  `410`, `401`, `500`, single-`502`-then-complete, `3×502`-exhausted, deadline
  expiry, `expires_in<=0` at start, `200`-success-with-empty-`device_id`/`secret`
  (→ `ErrProtocol`), and malformed JSON. (`501` is exercised on `start`, not `poll`.)
- **Injected `Clock`** so timing scenarios run instantly and `ctx`-cancel is testable.
  **Captured `Prompter`** to assert the user is shown the code/URI and that the secret is
  never surfaced through it.
- **`credentials`:** assert `0600` perms, atomic write, parent-dir creation, `refuse-exists`,
  `--force` overwrite, round-trip Load/Save, `ErrNotFound`/`ErrExists`.
- **`config`:** viper precedence (flag > env > file > default), the `SetDefault`/pflag
  gotcha, optional-file (no file present) path.
- **`cmd`:** cobra wiring smoke test (`enroll` registered, flags parsed, mutual sanity);
  a `version` subcommand test.
- **`deps_test.go`** stays green — asserts the client's transitive imports exclude
  huma/oauth2/go-oidc/go-jose. (Also confirm at implementation time that viper introduces
  none of the four.)
- Go 1.25 no-CGO; stdlib `testing`, table-driven, `-race`; errors wrapped `%w`.

---

## 8. Follow-ups (documented, non-blocking)

1. **Windows credentials path** — spec §6 puts credentials under `%LOCALAPPDATA%` (config under `%APPDATA%`); `os.UserConfigDir()` returns `%AppData%`. Reconcile when Windows support is a real target.
2. **`enroll --code` / `enroll --user` modes** — additive siblings in `internal/client/enroll`.
3. **`ca_bundle` via config file** end-to-end once the full client config loader lands with `run`.
4. **`--config` / `--state-dir` system-wide flags** (spec §6) — Plan 06 exposes `--credentials-file`; the broader systemd path scheme arrives with `run`.
5. **Consolidate capability + enroll wire DTOs into `internal/shared`** (spec §11) so the server `api` layer and the client import one source instead of hand-syncing the structs across the binary boundary (D9). Deferred to avoid pulling a server refactor into a client plan; the shared contract is small and test-pinned meanwhile.

---

## 9. Acceptance criteria

1. `diyddns-client enroll --oidc --server <url>` drives start → display → poll → writes `credentials.json` (`{server_url, device_id, secret}`, `0600`) on success; exits 0.
2. Poll loop honors `interval`, backs off on `slow_down`, stops on `410`/`401`/`500` (and `501` on `start`), rejects an empty-`200` body, tolerates bounded `502`, and times out at `expires_in` — each with a distinct message.
3. Existing `credentials.json` is not overwritten without `--force`; no partial files on any failure.
4. `--ca-cert <path>` makes the enroll calls trust a self-signed server.
5. The secret and `flow_id` never appear in any log or stdout/stderr output.
6. `cmd/diyddns-client/deps_test.go` passes — no huma/oauth2/go-oidc/go-jose in the client.
7. `go test ./... -race` green; `golangci-lint` clean; `go build ./...` builds both binaries.
8. cobra root + `enroll`/`version` subcommands replace the `flag` scaffold; the viper client config loader is wired with the minimal key set.

---

## 10. Review provenance

- **Self-review** (placeholder / consistency / scope / ambiguity): fixed the secret encode/store inconsistency between the `enroll.Result` and `credentials` contracts.
- **SGE (sr-go-engineer, Fable) design review** — verdict **APPROVE-WITH-NITS**, 0 Critical. Wire contract verified against the merged `enroll_oidc.go` / `capabilities.go` / `oidc_device_flows.go`. All findings folded:
  - *I-1* (shared wire-type duplication) → **D9** + follow-up §8.5 (accept local structs for Plan 06, file `internal/shared` consolidation).
  - *M-1* (`501` wrongly on the poll loop) → removed from §4/§5; kept start-only.
  - *M-2* (empty-`200` misread as success) → require non-empty `device_id`+`secret`; `ErrProtocol` otherwise.
  - *M-3* (`verification_uri_complete` is `omitempty`) → print conditionally.
  - *M-4* (`expires_in<=0` dead deadline) → guard at start.
  - *M-5* (redundant secret re-encode) → store the wire base64 verbatim, validate by trial-decode.
  - *M-6* (sleep-before-poll latency/overshoot) → poll first, then sleep capped to remaining deadline.
