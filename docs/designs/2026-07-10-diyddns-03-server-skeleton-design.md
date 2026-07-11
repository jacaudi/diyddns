# DIYDDNS Plan 03 — Server Skeleton & OpenAPI (Design)

- **Date:** 2026-07-10
- **Type:** Design
- **Status:** Approved (pending final spec read)
- **Parent spec:** [docs/plans/2026-05-01-diyddns-design.md](../plans/2026-05-01-diyddns-design.md) — §2 (architecture), §4 (API surface), §5 (auth), §7 (web UI), §9 (observability)
- **Builds on:** Plan 02 (merged) — `internal/store` with `store.Open(ctx, path) → *Store`, `store.DB()`, `store.Close()`, migrate-on-open.

---

## 1. Purpose & Scope

Plan 03 replaces the current `--version`-only scaffold in `cmd/diyddns-server/main.go`
with a **runnable, acceptance-testable HTTP server** built on `net/http` + `huma` v2
over the merged `internal/store`. It is a **walking skeleton**: the transport, the
cross-cutting middleware, the two route groups, both served OpenAPI documents with
Scalar UIs, the health endpoints, migrate-on-start, and graceful shutdown — plus
exactly **one** real endpoint (`GET /agent/v1/capabilities`) that exercises the agent
route group end to end.

The skeleton lays the seams that later plans hang work off. It deliberately builds
**no authentication logic, no business endpoints, and no UI serving**.

### In scope

- `cmd/diyddns-server` cobra root with `serve` and `version` subcommands.
- `internal/config` — minimal, additively-shaped viper loader for the server.
- `internal/server` — server assembly (`New`, `Run`) with graceful shutdown.
- `internal/server/middleware` — RequestID, AccessLog, Recover (net/http middleware).
- `internal/server/api` — two `huma.API` instances (agent + api) with Scalar docs,
  the `/agent/v1/capabilities` operation, and plain `/healthz` + `/readyz` handlers.
- Migrate-on-start via `store.Open`.
- Dependencies added (server-only): `huma/v2` (+ `adapters/humago`), `cobra`, `viper`.

### Out of scope (explicit non-goals — seams for later plans)

| Deferred capability | Owning plan (later) |
|---|---|
| HMAC verify, sessions, CSRF, OIDC, bootstrap admin | Auth plan(s) — Plan 04/05 |
| Business endpoints: enroll, checkin, self, devices, users, audit, admin/server | Services plan(s) |
| UI embed (`embed.FS`) + SPA fallback + serving `/` | UI plan |
| TLS `cert`/`acme` modes | Deploy/TLS plan |
| Rate-limiting middleware | Hardening plan |
| Prometheus `/metrics` | Future work (spec §12) |

These attach at documented seams (see §8) without rewriting Plan 03 code.

---

## 2. Architecture

### 2.1 Two `huma.API` instances on one mux

The server builds a single `http.ServeMux`, wraps it in a net/http middleware chain,
and mounts **two independent `huma.API` instances** on it via the `humago` (net/http)
adapter. Each API owns a distinct OpenAPI document and Scalar UI:

| huma API | OpenAPI document | Scalar UI | Operations registered in Plan 03 |
|---|---|---|---|
| `agentAPI` | `/agent/openapi.json` | `/agent/docs` | `GET /agent/v1/capabilities` |
| `apiAPI` | `/api/openapi.json` | `/api/docs` | *(none yet)* |

The two APIs coexist on one `ServeMux` because their operation paths (`/agent/*` vs
`/api/*`) and their doc/openapi paths are disjoint — no route collision.

**Why two instances, not one API with tags:** the parent spec (§4) requires **two
separate OpenAPI documents** because the two groups have different auth schemes (HMAC
vs cookie+CSRF). A single huma API with two tag-groups emits one document and cannot
express this split. Two instances is the supported, idiomatic huma shape.

**Scalar:** huma v2 ships Scalar as a built-in renderer — set on each config:

```go
config.DocsRenderer = huma.DocsRendererScalar
```

No custom docs HTML handler is required. This satisfies the spec's Scalar requirement
(§2, §4) at the cost of one config line per API.

### 2.2 Package layout

Follows the parent spec's intended boundaries (§2, §11). Every package below is
**server-only** — none is imported by `cmd/diyddns-client` or `internal/client/*`,
keeping the client binary free of huma/cobra/viper (spec §2).

```
cmd/diyddns-server/main.go        cobra root + `serve` + `version`
internal/config/                  viper loader for the server (minimal struct)
internal/server/                  Server assembly: New(), Run(ctx) — bootstrap + graceful shutdown
internal/server/middleware/       RequestID, AccessLog, Recover (net/http middleware)
internal/server/api/              huma setup (two APIs), capabilities op, health handlers
```

`internal/server/service/` is **not** created in Plan 03 — no business logic exists to
justify it (YAGNI). Later plans add it as a sibling package (No-Wall: additive).

### 2.3 Dependencies added (server-only)

- `github.com/danielgtaylor/huma/v2` and `github.com/danielgtaylor/huma/v2/adapters/humago`
- `github.com/spf13/cobra`
- `github.com/spf13/viper`

Structured logging uses stdlib `log/slog` (no dependency). These land in the import
graph of `cmd/diyddns-server`, `internal/server/*`, and `internal/config` only.

---

## 3. Components

### 3.1 `internal/config`

```go
type Server struct {
	Server   ServerSection
	Database DatabaseSection
	Logging  LoggingSection
}
type ServerSection   struct { Listen, BaseURL string }
type DatabaseSection struct { Path string }
type LoggingSection  struct { Level, Format, Output string }

func Load(path string) (Server, error)
```

- Loader: `viper`, precedence **flags > env (`DIYDDNS_*`) > file > defaults**
  (spec §8). Env keys follow `DIYDDNS_<SECTION>_<KEY>` (e.g. `DIYDDNS_SERVER_LISTEN`,
  `DIYDDNS_DATABASE_PATH`).
- Defaults: `server.listen=":8080"`, `logging.level="info"`, `logging.format="json"`,
  `logging.output="stderr"`. `database.path` is **required** (error if empty);
  `":memory:"` is accepted (tests, ephemeral runs).
- Nested-struct shape is deliberate: `tls:`, `auth:`, `oidc:`, `retention:`,
  `ratelimit:` sections from spec §8 drop in as new fields/structs later without
  restructuring existing callers.

### 3.2 `internal/server/middleware`

Three `func(http.Handler) http.Handler` values plus a small `Chain` helper.

- **RequestID** — honors an incoming `X-Request-Id`; otherwise generates a UUIDv7
  (`github.com/google/uuid`, already a dependency). Stores the id in the request
  context and echoes it in the `X-Request-Id` response header. (Header name is fixed
  to `X-Request-Id` for the skeleton; spec §8 `observability.request_id_header` becomes
  configurable when that config section lands.)
- **AccessLog** — emits exactly one structured `slog` `info` line per request with
  `request_id`, `method`, `path`, `status`, `duration_ms`, `bytes_out` (spec §9). Wraps
  the `ResponseWriter` to capture status and bytes. Never logs cookies, signatures, or
  authorization headers.
- **Recover** — defers a recover; on panic logs an `error` line (with `request_id`) and
  writes `500`. The request survives; the process does not crash.

**Chain order (outer → inner):** `RequestID → AccessLog → Recover → mux`. RequestID is
outermost so both the access log and any recover log carry the id. Recover is innermost
so a panic is converted to `500` **before** AccessLog's wrapped writer records the
status, and the access line reports `500` correctly. The chain wraps the whole mux, so
it applies uniformly to health endpoints, doc endpoints, and API operations.

### 3.3 `internal/server/api`

```go
func Build(mux *http.ServeMux, log *slog.Logger, st *store.Store, info version.Info) error
```

- Constructs `agentAPI` and `apiAPI` via `humago.New(mux, config)` with per-API config:
  distinct `Title`, `OpenAPIPath` (`/agent/openapi`, `/api/openapi` — huma serves the
  `.json`/`.yaml` suffixes), `DocsPath` (`/agent/docs`, `/api/docs`), **distinct
  `SchemasPath`** (`/agent/schemas`, `/api/schemas`), and
  `DocsRenderer = huma.DocsRendererScalar`.
  - **Distinct `SchemasPath` is mandatory:** both APIs share one `http.ServeMux`, and
    huma registers a route at each config's `SchemasPath` (default `/schemas`). Two APIs
    left at the default would register `/schemas` twice and panic the mux on the second
    registration. Prefixing per group (`/agent/schemas`, `/api/schemas`) — matching the
    already-prefixed `OpenAPIPath`/`DocsPath` — keeps every huma-owned route disjoint.
- Registers the `capabilities` operation on `agentAPI` (see §3.4).
- Registers `/healthz` and `/readyz` as **plain** `http.HandlerFunc` on the mux —
  deliberately **outside** both OpenAPI documents. They are operational, plaintext
  (spec §9), and not part of the API contract.
  - `GET /healthz` → always `200`, body `ok`.
  - `GET /readyz` → `store.DB().PingContext(ctx)` (short timeout). Ok → `200 ready`;
    error → `503`. Migrations are guaranteed applied: the server never starts listening
    unless `store.Open` (which migrates) succeeded.

### 3.4 The `capabilities` operation

`GET /agent/v1/capabilities` — unauthenticated (spec §4). huma operation on `agentAPI`.

```jsonc
// 200 response body
{
  "server_version": "v0.0.0-dev",
  "skew_window_seconds": 120,
  "address_families": ["ipv4", "ipv6"],
  "oidc_enabled": false
}
```

These are the fields the skeleton can honestly populate: `server_version` from
`version.Info`, `skew_window_seconds` from a package constant (`120`, matching spec §5A),
`address_families` static, `oidc_enabled` static `false`. When auth/OIDC config lands
(Plan 04/05), `oidc_enabled` and any `hide_local_login_ui` flag become dynamic —
additive fields/values, no breaking change to the contract.

### 3.5 `internal/server`

```go
type Server struct { /* cfg, store, log, httpServer */ }
func New(cfg config.Server, st *store.Store, log *slog.Logger) (*Server, error)
func (s *Server) Run(ctx context.Context) error
```

- `New` builds the mux, calls `api.Build(mux, log, st, version.Current())` (passing the
  build identity through to the `capabilities` operation), wraps the mux in the
  middleware chain, and constructs `http.Server{Addr: cfg.Server.Listen, Handler: chain}`.
  Threading `version.Info` (rather than having `api.Build` read the package var directly)
  keeps `capabilities` testable with an injected version.
- `Run` starts the listener in a goroutine and blocks until `ctx` is cancelled, then
  calls `httpServer.Shutdown(timeoutCtx)` to drain in-flight requests. Returns the first
  non-`ErrServerClosed` error.

### 3.6 `cmd/diyddns-server`

Cobra root replaces the current `flag`-based scaffold.

- `diyddns-server serve [--config <path>]` — `config.Load` → build `slog.Logger` from
  `logging.*` → `store.Open(ctx, cfg.Database.Path)` → `server.New` →
  `server.Run(signalCtx)` where `signalCtx = signal.NotifyContext(ctx, SIGINT, SIGTERM)`.
  On shutdown, `store.Close()`.
- `diyddns-server version` — prints `version.Current().String()` (preserves current
  behavior).
- Config-file discovery + flag/env binding via viper (spec §8). `--config` overrides the
  search path.

---

## 4. Data flow

**Startup:** `serve` → `config.Load` → logger → `store.Open` (migrations run) →
`server.New` → `server.Run(signalCtx)` listens on `cfg.Server.Listen`.

**Shutdown:** SIGINT/SIGTERM → `signalCtx` cancelled → `http.Server.Shutdown(timeout)`
drains → `store.Close()`.

**Request:** `RequestID → AccessLog → Recover → mux`, then routed to a huma operation
(`/agent/v1/capabilities`), a huma-served doc/openapi path, or a plain health handler.

---

## 5. Error handling

- **Startup failures** (invalid config, `store.Open` error, listener bind error) → logged
  at `error`, non-zero process exit. The server never serves in a partial state.
- **Handler panics** → Recover middleware → `500` + one `error` log line; request
  survives, process continues.
- **huma operation errors** → RFC 7807 `application/problem+json` (huma default, spec §4).

---

## 6. Testing

Stdlib `testing` only, table-driven where inputs enumerate, `-race` in CI (spec §9).

- **`internal/config`** — precedence table (defaults / file / env / flag-override);
  missing-required (`database.path`) error; `:memory:` accepted.
- **`internal/server/middleware`** — RequestID (generates when absent, honors incoming,
  echoes header); AccessLog (one line, expected fields, sensitive headers absent);
  Recover (panic → 500, exactly one error line). Exercised via `httptest`.
- **`internal/server/api` (integration)** — assemble a server over a `:memory:` store
  and drive it via `httptest.Server`:
  - `/healthz` → 200; `/readyz` → 200, and → 503 after `store.Close()`.
  - `/agent/openapi.json` and `/api/openapi.json` each parse as valid OpenAPI 3.1.
  - `/agent/docs` and `/api/docs` return Scalar HTML (200).
  - `/agent/v1/capabilities` returns the expected JSON **and** appears in
    `/agent/openapi.json` but **not** in `/api/openapi.json`.

---

## 7. Acceptance criteria (Plan 03 slice of parent spec §14)

1. `diyddns-server serve` (config via flag/env/file) starts, opens+migrates the DB, and
   logs a startup line.
2. `/healthz` → 200; `/readyz` → 200 when the DB is reachable.
3. `/agent/openapi.json` and `/api/openapi.json` return two distinct, valid OpenAPI 3.1
   documents.
4. `/agent/docs` and `/api/docs` render Scalar.
5. `/agent/v1/capabilities` returns the capabilities JSON and appears only in the agent
   document.
6. SIGINT/SIGTERM drains in-flight requests and closes the store cleanly.
7. `diyddns-server version` prints build identity.
8. `go test ./... -race` passes; `golangci-lint run` is clean.
9. **The client binary does not import huma, cobra, or viper** (verified by an
   import-graph check, e.g. `go list -deps ./cmd/diyddns-client`).

---

## 8. Seams for later plans (how the deferred work attaches additively)

- **Auth (Plan 04/05).** `/agent/v1/*` mixes unauthenticated (capabilities, enroll) and
  HMAC-authenticated (checkin, self) operations, so HMAC is **per-operation**, not a
  blanket group. Plan 04 adds an HMAC middleware in `internal/server/middleware` (or
  `internal/auth`) and attaches it to the authenticated operations; capabilities stays
  open. Cookie+CSRF middleware attaches to `apiAPI`'s mutating operations similarly.
  huma's `huma.NewGroup(api, "/v1").UseMiddleware(...)` is available where a whole
  sub-tree shares a scheme.
- **Business endpoints.** New operations register on the existing `agentAPI`/`apiAPI`
  in new files under `internal/server/api/`, backed by a new `internal/server/service`
  package — siblings, no edits to Plan 03 files.
- **UI serving.** The UI plan adds `//go:embed` of `ui/dist`, a static file handler, and
  the SPA fallback for non-`/api`/non-`/agent` paths on the same mux.
- **Config growth.** New spec §8 sections become new fields/structs in
  `internal/config`; existing sections and callers are untouched.
- **TLS.** `cert`/`acme` modes wrap the listener in `server.Run` behind a new
  `tls` config section; the `plain` path is unchanged.
```
