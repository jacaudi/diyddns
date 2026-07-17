# Plan 07 — `diyddns-client run` public-IP reporting loop (design)

**Status:** Design — awaiting user review → `superpowers:writing-plans`.
**Feature:** `client-run-loop`. Pairs with `docs/plans/2026-07-16-diyddns-07-client-run-loop-implementation.md`.
**Base:** `origin/main` @ `bcf670f` (Plans 01–06 merged).
**Issue:** GitHub #26 (the `run` slice specifically; `--code`/`--user` enroll modes and `status`/`rotate` remain separate future slices). Resolves #12 (`last_seen_at` semantics).

---

## 1. Purpose

Plan 06 gave a device the ability to enroll and obtain `credentials.json` (`{server_url, device_id, secret}`). Plan 07 delivers the vertical that finally makes the product work end to end: a `diyddns-client run` command that reads those credentials, discovers the host's public IP from a **quorum of independent lookup providers**, and **HMAC-signs check-ins to `POST /agent/v1/checkin`** so the server records the device's IP history and liveness.

This is the MVP-completing slice: after Plan 07, a device can enroll **and** continuously report its public IP.

---

## 2. Scope

**In scope**
- New `diyddns-client run` cobra command (daemon + `--once`).
- New `internal/client/ipdiscovery` — quorum public-IP discovery (IPv4 + IPv6).
- New `internal/client/checkin` — HMAC-signed `POST /agent/v1/checkin` client.
- New `internal/client/poller` — the scheduled loop (RunOnce + Run).
- Additive `Run` section in `internal/config/client.go`.
- **Bounded server-side #12 fix**: new `Devices().Touch` store method + `CheckinService` advances `last_seen_at` on the no-change branch so it means *last contact*.

**Out of scope (YAGNI — separate future slices)**
- `status`, `rotate`, `self`-reading client subcommands (#26).
- `--code` / `--user` enroll modes (#26).
- Full `/agent/v1` wire-DTO consolidation into `internal/shared` (#27) — see Decision D7.
- Any new HTTP endpoint, migration, or auth change. Rate-limiting stays in the Hardening plan.
- STUN/UPnP/interface-scraping discovery methods — HTTP lookup providers only.

---

## 3. Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| **D1** | **Run mode = both.** Daemon by default; `run --once` does one pass and exits. | The one-shot path is just the loop body invoked once (`RunOnce`), near-zero extra cost; covers cron / systemd-timer / k8s CronJob users while keeping the self-contained daemon for the common homelab case. |
| **D2** | **Majority quorum, 2-of-N per family.** Query N providers concurrently; an IP wins only if ≥ threshold (default 2) agree. No agreement → that family is skipped this cycle. | Delivers the "independent quorum" promise: one wrong / hijacked / stale provider cannot poison the reported IP. Threshold + provider list configurable. |
| **D3** | **Auto address families.** Independent quorum per family each cycle; report whichever reaches quorum; omit the rest (server merge-on-empty preserves stored value). Cycle succeeds if ≥ 1 family reported. | Zero-config for v4-only, dual-stack, and v6 hosts alike — correct for the heterogeneous homelab target. Optional `address_families` config disables a family to save a wasted timeout. |
| **D4** | **Always check in every cycle** (not only on change). | Simplest client (no persistent last-IP state to drift); the server's `stored` flag already signals real change; every contact is a liveness signal. Trivial request volume at homelab scale. |
| **D5** | **Resolve #12 by redefining `last_seen_at` = last contact**, via a new `Devices().Touch`; no schema change. | Makes D4's cadence meaningful (server can tell a stable-IP device from a dead one). "Last change" remains available as the latest `ip_history` row, removing today's redundancy. Minimal, no migration. |
| **D6** | **Fixed interval + exponential backoff + ±10% jitter**, with an injected `Clock` and `rand` seam. Default interval 5m. | Immediate cycle on start, then steady cadence; a failed cycle backs off (30s → … → cap = interval) and resets on success; small jitter decorrelates check-ins. Seams make scheduling deterministically testable (mirrors the enroll `Clock` seam). |
| **D7** | **Client-local checkin wire structs** (keep Plan 06 D9 pattern); defer #27. | The checkin request/response is the *second* `/agent/v1` wire contract; consolidating only it while enroll/capabilities/self stay client-local would be an inconsistent half-measure. #27 remains the holistic place to unify all `/agent/v1` DTOs at once; the cross-binary integration test (#25) guards drift. |
| **D8** | **`checkin` is its own package**, not folded into `poller`. | It is the reuse seam for future authenticated client verticals (`status`/`self`/`rotate`) and keeps `poller` focused on scheduling — the same separation as `enroll` being its own package. (No-Wall: isolate the signed-transport concern now so the next authenticated command is additive.) |
| **D9** | **Client generates its own nonce** via `crypto/rand`; it does **not** import `internal/auth`. | `internal/auth` pulls server auth machinery (argon2 via `x/crypto`); the client stays minimal and self-contained. Nonce generation is a few lines. |

---

## 4. Architecture & package layout

```
cmd/diyddns-client/run.go            NEW  cobra `run` command (sibling of enroll.go)
cmd/diyddns-client/run_test.go       NEW
internal/client/ipdiscovery/         NEW  quorum public-IP discovery (unauthenticated)
internal/client/checkin/             NEW  HMAC-signed POST /agent/v1/checkin
internal/client/poller/              NEW  RunOnce + scheduled Run
internal/config/client.go            EDIT additive Run config section
internal/store/devices.go            EDIT + Devices().Touch(ctx, id, lastSeenAt)   ← #12
internal/store/devices_test.go       EDIT Touch tests
internal/server/service/checkin.go   EDIT no-change branch calls Touch             ← #12
internal/server/service/checkin_test.go  EDIT no-change advances last_seen_at
```

`ipdiscovery/` and `poller/` are the empty placeholder dirs already on `main`.

### 4.1 `internal/client/ipdiscovery`

Owns the "quorum of independent providers" promise.

```go
type Family int
const ( FamilyV4 Family = iota; FamilyV6 )

// Provider looks up the host's public IP for one address family.
type Provider interface {
    Lookup(ctx context.Context) (netip.Addr, error)
}

// httpProvider is the concrete Provider: GET one URL over a family-locked
// transport, parse the plain-text body as a netip.Addr, reject a response
// whose family doesn't match (guards against a dual-stack/misconfigured host).
type httpProvider struct { url string; family Family; http *http.Client }

// Result is the per-family discovery outcome.
type Result struct { Addr netip.Addr; OK bool }

// Discoverer runs each family's provider list concurrently and applies the
// 2-of-N majority quorum.
type Discoverer struct {
    v4, v6  []Provider
    quorum  int
    perReq  time.Duration   // per-provider timeout
}
func (d *Discoverer) Discover(ctx context.Context) (v4, v6 Result)
```

- **Family locking:** each `httpProvider` uses an `http.Client` whose `Transport.DialContext` forces `tcp4` or `tcp6`. Belt-and-suspenders on top of family-specific hostnames, so a v4 query can never return a v6 answer.
- **Parsing:** trim whitespace/newline, `netip.ParseAddr`, then assert `addr.Is4()` (v4) / `addr.Is6() && !addr.Is4In6()` (v6). A mismatch is a provider error (excluded from the tally).
- **Quorum tally:** collect successful responses; the address with the most agreeing votes wins iff its count ≥ `quorum`. **Tie-break (M2):** if two or more addresses tie at the top count, there is **no winner** → family skipped (fail-safe — an attacker controlling half the providers must not win a coin-flip). Otherwise `Result{OK: false}`.
- **Construction validation (M3):** `NewDiscoverer` rejects `quorum < 1` or `quorum > len(providers)` for any enabled family — otherwise a misconfig (e.g. quorum 2 with one provider) silently skips that family forever with no error.
- **Testability:** the `Provider` interface lets tests inject fakes for every quorum scenario (agreement, disagreement, provider-error, wrong-family, timeout, top-count tie) with no real network. The family-locked `httpProvider` gets a thin `httptest` smoke test.

### 4.2 `internal/client/checkin`

Mirrors the `enroll.Client` idiom (net/http, `NewClient(baseURL, opts)`, `--ca-cert` trust via `x509` `RootCAs`, `drainClose`, typed sentinels), and adds request signing.

```go
type Report struct { IPv4, IPv6, Hostname, OS, ClientVersion string }
type Result struct { DeviceID, CurrentIPv4, CurrentIPv6 string; Stored bool }

type Client struct { baseURL, deviceID string; key []byte; clock Clock; http *http.Client }

// NewClient decodes the wire-base64 secret to the raw HMAC key.
func NewClient(baseURL, deviceID, secretB64 string, opts Options) (*Client, error)

func (c *Client) Checkin(ctx context.Context, r Report) (Result, error)
```

**Signing (must match `internal/server/api/authmw.go` exactly):**
1. `body = json.Marshal(checkinRequest{...})` — client-local struct, json tags matching the server (`ipv4,omitempty` … `client_version,omitempty`).
2. `ts = strconv.FormatInt(c.clock.Now().Unix(), 10)`; `nonce = randToken()` (`crypto/rand`, hex).
3. `canonical = shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(body))`.
4. `sig = shared.Sign(c.key, canonical)`; set headers `shared.HeaderDevice/HeaderTimestamp/HeaderNonce/HeaderSignature` + `Content-Type: application/json` (**M1** — not in the canonical, but huma binds the body and a missing Content-Type 4xxs *after* auth passes; mirror `enroll/client.go:160`).
5. `key = base64.StdEncoding.DecodeString(secretB64)` at construction (invalid base64 → constructor error).

> **Acceptance criterion I1 — hash exactly the bytes you send.** The body that is hashed in step 1 MUST be the exact byte slice written to the request (`bytes.NewReader(body)`), never re-serialized. In particular do **not** hash `json.Marshal` output and then send via `json.Encoder.Encode` (which appends a `\n`) — the body-hash would diverge and **every check-in 401s**. Mirror `enroll/client.go:150-156` (`json.Marshal` → `bytes.NewReader`).

Response classification: `200` → decode `checkinResponse` → `Result`; non-2xx → typed sentinel (`ErrUnauthorized` on 401 for a stale/rotated secret, `ErrServer` otherwise). Never logs the secret or key.

### 4.3 `internal/client/poller`

Orchestration only.

```go
type Clock interface { Now() time.Time; Sleep(ctx context.Context, d time.Duration) error }

type Poller struct {
    disc    *ipdiscovery.Discoverer
    chk     *checkin.Client
    interval time.Duration
    clock   Clock
    rand    *rand.Rand   // jitter seam
    log     *slog.Logger
}

func (p *Poller) RunOnce(ctx context.Context) error   // one discover → checkin
func (p *Poller) Run(ctx context.Context) error        // daemon: cycle, schedule, backoff
```

- `RunOnce`: discover → build `Report` (omit families that missed quorum) → `Checkin`. Returns error if **no family reached quorum** or the check-in failed.
- `Run`: cycle immediately; on success sleep `interval·(1 ± 0.10)`; on failure sleep exponential backoff (first step `min(30s, interval)` — **M4** clamp so a short `--interval 10s` never backs off longer than its own cap — doubling up to `interval`), reset on the next success; honor `ctx` cancellation (SIGTERM → clean stop).

---

## 5. Data flow (one cycle)

```
RunOnce(ctx):
  1. Discoverer.Discover(ctx):
        v4: providers over tcp4 → tally → 2-of-N agree → 203.0.113.7  (OK)
        v6: providers over tcp6 → no route / <2 agree      → (not OK)
  2. Report{IPv4:"203.0.113.7"}          // v6 omitted → server preserves stored value
  3. checkin.Client.Checkin → sign + POST /agent/v1/checkin
  4. 200 → Result{Stored:true|false}; log outcome
  cycle succeeds iff (v4.OK || v6.OK) AND checkin returned 2xx

Run(ctx):    // daemon
  cycle now → success: sleep interval·(1±0.1)
            → failure: sleep backoff(30s→…→cap=interval); reset on next success
  ctx cancel / SIGTERM → return nil (clean stop)
```

**Credentials vs config split:** `server_url`, `device_id`, `secret` come from `credentials.json` (the enrolled device already knows its server). Config supplies `ca_bundle`, `interval`, `quorum`, `address_families`, and provider overrides. Thus `run` has **no `--server` flag** — the server URL is authoritative from enrollment.

---

## 6. Server-side #12 fix (bounded)

`last_seen_at` today advances only on an IP *change* (`CheckinService.Checkin` returns early on the no-change branch, writing nothing). With D4 (always check in), that discards the liveness signal. Fix:

```go
// internal/store/devices.go
func (r *DeviceRepo) Touch(ctx context.Context, id string, lastSeenAt int64) error {
    // UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?
    // ErrNotFound if no row matched (mirrors UpdateIP).
}
```

```go
// internal/server/service/checkin.go — no-change branch (was lines 70-77)
if effV4 == dev.CurrentIPv4 && effV6 == dev.CurrentIPv6 {
    if err := s.st.Devices().Touch(ctx, dev.ID, store.NowUnix()); err != nil {
        return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
    }
    return CheckinResult{DeviceID: dev.ID, CurrentIPv4: dev.CurrentIPv4,
        CurrentIPv6: dev.CurrentIPv6, Stored: false}, nil
}
```

The change branch already sets `last_seen_at` via `UpdateIP` (no double-write). `Stored:false` still means "IP unchanged." A `Touch` failure surfaces as a 500, consistent with other check-in error paths. No wire/API change: `last_seen_at` in the `self` response now simply means last contact.

- **M6 (intended):** `Touch` bumps `updated_at = NowUnix()` too, consistent with `UpdateIP`/`Rename`. With D4's always-check-in cadence this advances `updated_at` roughly every interval, converging it toward `last_seen_at` in the `self` response. This is intentional and acceptable (the same field semantics the existing methods use); noted so it isn't read as accidental.
- **M7 (pre-existing, out of scope):** the no-change branch compares IPs only, so a client that changes `client_version`/`hostname`/`os` **without** an IP change won't persist that metadata until the next IP change. This is pre-existing `CheckinService` behavior, not introduced by #12 — but D4 makes stable-IP check-ins the common case, so it's worth a note. Persisting metadata on the no-change path is deliberately **not** in scope here (it would widen `Touch`/the no-change branch beyond the liveness fix); revisit if metadata staleness becomes a real complaint.

---

## 7. Config surface (additive)

```go
type ClientConfig struct {
    Server  ClientServerSection
    Logging LoggingSection
    Run     ClientRunSection   // NEW
}

type ClientRunSection struct {
    Interval        time.Duration `mapstructure:"interval"`         // default 5m
    Quorum          int           `mapstructure:"quorum"`           // default 2
    AddressFamilies []string      `mapstructure:"address_families"` // default ["ipv4","ipv6"]
    ProvidersV4     []string      `mapstructure:"providers_v4"`     // built-in default; override via file
    ProvidersV6     []string      `mapstructure:"providers_v6"`
}
```

Loaded via the existing `LoadClient` idiom (explicit `BindEnv` per key, no `AutomaticEnv`) — new keys join `clientKeyDefaults`. Slice keys (`providers_v4/v6`, `address_families`) default in code; env binding accepts comma-separated values, file override accepts a list. Backoff/jitter magnitudes are code constants (KISS — not config).

**Built-in default providers** — three independent operators per family, so the 2-of-N quorum spans distinct operators:

| Family | Providers (plain-text public-IP endpoints) |
|--------|--------------------------------------------|
| IPv4 | `https://api.ipify.org`, `https://ipv4.icanhazip.com`, `https://4.ident.me` |
| IPv6 | `https://api6.ipify.org`, `https://ipv6.icanhazip.com`, `https://6.ident.me` |

`run` flags: `--once`, `--interval`, `--credentials-file`, `--ca-cert`, `--config`. (`--ca-cert` maps to `server.ca_bundle`, as in enroll.)

---

## 8. Error handling & security

- **Per-provider** failures/timeouts are logged at debug and excluded from the tally; they don't fail the family unless quorum is missed.
- **Per-family** quorum miss is logged at warn; the cycle still succeeds if the other family reported.
- **Whole-cycle** failure (no family reached quorum, or check-in network/5xx) → backoff (daemon) / non-zero exit (`--once`). All errors wrapped `%w`.
- **Secrets:** never log or print the wire secret or the raw HMAC key; log discovered IPs and the `stored` result only. Fresh `crypto/rand` nonce per request (server replay table + 120s skew reject reuse/drift). `--ca-cert` trusts a self-signed homelab CA.
- **Deps guard:** all packages import stdlib + `internal/shared`, `internal/client/credentials`, `internal/config` only. No `huma`/`oauth2`/`go-oidc`/`go-jose` — `cmd/diyddns-client/deps_test.go` stays green **unchanged**. `internal/config` is viper+stdlib (already client-safe).

---

## 9. Testing (TDD, stdlib `testing`, table-driven, `-race`)

| Package | Coverage |
|---------|----------|
| `ipdiscovery` | Injected fake `Provider`s: agreement (quorum met), disagreement (no winner), single provider up (< quorum), provider error/timeout, wrong-family response rejected, exact-threshold boundary. Thin `httptest` smoke test of the family-locked `httpProvider` parse path. |
| `checkin` | `httptest` server that **reconstructs the canonical** with `internal/shared` (client-dep-safe — no server `auth`/`store` in the test binary) and asserts the client's signature/headers/body verify against the known key — catches any signing mismatch. **I2 — tag-parity guard:** the same test decodes the posted body into a struct carrying the **server's** json tags (a copy of `checkinBody`'s tag set) and asserts field-by-field parity with what the client sent, so the D7-duplicated wire contract is locally guarded against tag drift (until #25's cross-binary test lands). Plus: merge-on-empty (omit v6), 401 → `ErrUnauthorized`, 5xx → `ErrServer`, bad-base64 secret → constructor error, `--ca-cert` trust. |
| `poller` | Injected `Clock` + seeded `rand` + fake discoverer/checkin: RunOnce success/failure mapping, always-checkin (unchanged still POSTs), daemon schedules `interval`, jitter within ±10% bound, backoff sequence + reset on success, ctx-cancel clean stop, `--once` exit-code mapping. |
| `config` | **M5** — `Run` section binding: `DIYDDNS_RUN_INTERVAL`/`_QUORUM` scalars; env comma-string `DIYDDNS_RUN_PROVIDERS_V4=a,b,c` → `[]string{a,b,c}` (via viper's default `StringToSliceHookFunc(",")`); file list → slice; code defaults when unset. This env-slice path is load-bearing and currently unasserted. |
| `store` | `Touch` updates `last_seen_at`+`updated_at`; `ErrNotFound` on missing id. |
| `service` | Checkin no-change branch advances `last_seen_at` (Touch called); change branch unchanged; `stored` semantics intact. |
| `cmd` | `run` flag wiring; `deps_test.go` unchanged and green. |

---

## 10. Non-goals recap & follow-ups

- Full `/agent/v1` DTO consolidation → **#27** (D7).
- `status`/`rotate`/`self` client subcommands, `--code`/`--user` enroll → **#26**.
- Cross-binary real-huma integration test → **#25** (would additionally guard the checkin wire).
- Windows creds-path divergence → **#24**.
- Rate-limiting → Hardening plan.

---

## 11. Review provenance

- Author self-review + mandatory critical-thinking double-check (design conclusions stress-tested: server-scope boundedness, discovery testability seam, HMAC signing correctness, `--once` exit semantics, deps guard).
- **`sr-go-engineer` (Fable) design review — verdict APPROVE-WITH-NITS.** The reviewer traced the HMAC secret end-to-end in the actual code (`enrollment.go` `GenerateSecret` → raw bytes; `enroll.go`/`enroll_oidc.go` wire = `base64.StdEncoding`; `auth/hmac.go` `OpenSecret` → same raw bytes as the verify key) and confirmed the client's canonical/headers/secret-decoding **exactly match** the server verify — no Critical signing defect. #12 fix confirmed correct/sufficient (no double-write, no missed path); package boundaries sound (Provider/Clock interfaces each have a present test consumer — seams, not walls); viper slice+`BindEnv` extension confirmed workable without `AutomaticEnv`; deps guard safe; default providers verified plain-text public-IP across three independent operators per family.
- **Findings folded:** I1 (hash-exact-bytes invariant → §4.2 acceptance criterion), I2 (checkin tag-parity guard → §9), M1 (Content-Type → §4.2), M2 (quorum tie-break → §4.1), M3 (`quorum ≤ len(providers)` construction check → §4.1), M4 (initial-backoff clamp → §4.3/§5), M5 (config env-slice test row → §9), M6 (`Touch` `updated_at` intended → §6), M7 (pre-existing metadata-drift observation → §6).
