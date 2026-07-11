# DIYDDNS Plan 03 — Server Skeleton & OpenAPI — Implementation Plan

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

**Goal:** Replace the `--version`-only server scaffold with a runnable, acceptance-testable `net/http` + huma v2 walking skeleton over the merged `internal/store`: two OpenAPI documents + Scalar UIs, cross-cutting middleware, health endpoints, `/agent/v1/capabilities`, cobra `serve`/`version`, minimal viper config, and migrate-on-start.

**Architecture:** One `http.ServeMux` wrapped in a `RequestID → AccessLog → Recover` net/http middleware chain. Two independent `huma.API` instances (`agent`, `api`) mounted on that mux via the `humago` adapter, each with its own OpenAPI/Docs/Schemas paths and the built-in Scalar renderer. Health endpoints are plain handlers outside both documents. cobra drives `serve`/`version`; viper loads a minimal, additively-shaped config.

**Tech Stack:** Go 1.25 (stdlib `net/http`, `log/slog`), `github.com/danielgtaylor/huma/v2` + `/adapters/humago`, `github.com/spf13/cobra`, `github.com/spf13/viper`, `github.com/google/uuid` (already a dep), `modernc.org/sqlite` via the existing `internal/store`.

**Source of truth:** `docs/designs/2026-07-10-diyddns-03-server-skeleton-design.md`.

## Global Constraints

Every task's requirements implicitly include these:

- **Go 1.25.7**, pure-Go, **no CGO** (static binaries must still cross-compile).
- **Pinned deps:** `github.com/danielgtaylor/huma/v2@v2.38.0`, `github.com/spf13/cobra@v1.10.2`, `github.com/spf13/viper@v1.21.0`.
- **Add a dependency only in the task that first imports it** — `go mod tidy` prunes a dep no `.go` file imports yet. viper lands in Task 1, huma in Task 3, cobra in Task 6.
- **Tests:** stdlib `testing` only (no testify/gocheck). Table-driven where inputs enumerate. `t.Helper()` in helpers. CI runs `go test ./... -race`.
- **Errors** wrapped with `%w` (`errorlint`). No `//nolint` without justification (`nolintlint`).
- **Logging:** stdlib `log/slog`. Never log cookies, signatures, or authorization headers.
- **huma is server-only:** `cmd/diyddns-client` and `internal/client/*` must never import `github.com/danielgtaylor/huma/v2`. (`cobra`/`viper` are shared and NOT restricted.)
- **`golangci-lint run`** must be clean; `go fmt`/`goimports` applied.
- **Conventional Commits** (`feat:`, `test:`, `build:`, `refactor:`), squash-merged.
- **Scalar renderer** is `huma.DocsRendererScalar` (confirmed present in huma v2.38.0). If a future bump removes it, fall back to a custom docs handler — not expected at v2.38.0.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/config/config.go` | `Server` config struct + `Load` (viper: defaults→file→env, flags via caller `BindPFlag`) |
| `internal/config/config_test.go` | precedence + validation tests |
| `internal/server/middleware/middleware.go` | `RequestID`, `AccessLog`, `Recover`, `Chain`, `RequestIDFromContext` |
| `internal/server/middleware/middleware_test.go` | per-middleware tests |
| `internal/server/api/api.go` | `Build` — two huma APIs (agent/api) + wiring |
| `internal/server/api/capabilities.go` | `Capabilities` type + `/agent/v1/capabilities` op |
| `internal/server/api/health.go` | `RegisterHealth` — `/healthz`, `/readyz` plain handlers |
| `internal/server/api/api_test.go` | huma-doc + capabilities + health tests |
| `internal/server/logging.go` | `NewLogger(config.LoggingSection)` |
| `internal/server/server.go` | `New`, `Run` (assembly + graceful shutdown), internal `newHandler` |
| `internal/server/server_test.go` | integration test over `:memory:` store; shutdown test |
| `internal/server/logging_test.go` | logger construction tests |
| `cmd/diyddns-server/main.go` | cobra root + `serve` + `version` (replaces scaffold) |
| `cmd/diyddns-server/main_test.go` | `version` output + `serve` error-path tests |
| `cmd/diyddns-client/deps_test.go` | asserts client binary excludes huma |

---

## Task 1: Config loader (`internal/config`)

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`
- Modify: `go.mod`, `go.sum` (adds viper)

**Interfaces:**
- Produces:
  - `type Server struct { Server ServerSection; Database DatabaseSection; Logging LoggingSection }`
  - `type ServerSection struct { Listen string; BaseURL string }`
  - `type DatabaseSection struct { Path string }`
  - `type LoggingSection struct { Level, Format, Output string }`
  - `func Load(v *viper.Viper, configPath string) (Server, error)`

- [ ] **Step 1: Add viper (imported immediately by the test/impl below)**

Run:
```bash
go get github.com/spf13/viper@v1.21.0
```
Expected: `go.mod` gains `github.com/spf13/viper v1.21.0`.

- [ ] **Step 2: Write the failing test**

Create `internal/config/config_test.go`:
```go
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:") // required field
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", cfg.Server.Listen)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" || cfg.Logging.Output != "stderr" {
		t.Errorf("logging defaults = %+v", cfg.Logging)
	}
}

func TestLoad_MissingDatabasePathIsError(t *testing.T) {
	v := viper.New()
	_, err := config.Load(v, "")
	if err == nil {
		t.Fatal("expected error for missing database.path")
	}
}

func TestLoad_FileOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9999\"\ndatabase:\n  path: \"/tmp/x.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	cfg, err := config.Load(v, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("Listen = %q, want :9999", cfg.Server.Listen)
	}
	if cfg.Database.Path != "/tmp/x.db" {
		t.Errorf("Path = %q", cfg.Database.Path)
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9999\"\ndatabase:\n  path: \"/tmp/x.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DIYDDNS_SERVER_LISTEN", ":7000")
	v := viper.New()
	cfg, err := config.Load(v, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":7000" {
		t.Errorf("Listen = %q, want :7000 (env wins over file)", cfg.Server.Listen)
	}
}

func TestLoad_FlagBeatsEnv(t *testing.T) {
	t.Setenv("DIYDDNS_SERVER_LISTEN", ":7000")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("listen", "", "")
	_ = fs.Set("listen", ":6000") // marks the flag Changed
	v := viper.New()
	if err := v.BindPFlag("server.listen", fs.Lookup("listen")); err != nil {
		t.Fatal(err)
	}
	v.Set("database.path", ":memory:")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":6000" {
		t.Errorf("Listen = %q, want :6000 (changed flag wins over env)", cfg.Server.Listen)
	}
}

func TestLoad_BaseURLMapsUnderscoreKey(t *testing.T) {
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "https://ddns.example.com")
	v := viper.New()
	v.Set("database.path", ":memory:")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.BaseURL != "https://ddns.example.com" {
		t.Errorf("BaseURL = %q", cfg.Server.BaseURL)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: FAIL (`config.Load` / `config.Server` undefined).

- [ ] **Step 4: Write the implementation**

Create `internal/config/config.go`:
```go
// Package config loads the diyddns-server configuration from (in precedence
// order) command-line flags, DIYDDNS_* environment variables, an optional YAML
// file, and built-in defaults. The struct is intentionally minimal for the
// Plan 03 skeleton; new sections (tls, auth, oidc, retention) are added as new
// fields without restructuring existing callers.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Server is the fully-resolved server configuration.
type Server struct {
	Server   ServerSection
	Database DatabaseSection
	Logging  LoggingSection
}

// ServerSection holds HTTP listener settings.
type ServerSection struct {
	Listen  string
	BaseURL string `mapstructure:"base_url"`
}

// DatabaseSection holds the SQLite database location.
type DatabaseSection struct {
	Path string
}

// LoggingSection holds structured-logging settings.
type LoggingSection struct {
	Level  string
	Format string
	Output string
}

// keyDefaults enumerates every config key, its default, and its env var. Keys
// with a corresponding CLI flag (server.listen) still carry a SetDefault here;
// viper ranks SetDefault above an unchanged flag's default, so a changed flag
// or an env var still wins.
var keyDefaults = map[string]string{
	"server.listen":   ":8080",
	"server.base_url": "",
	"database.path":   "",
	"logging.level":   "info",
	"logging.format":  "json",
	"logging.output":  "stderr",
}

// Load resolves configuration into a Server. Callers may pre-configure v (e.g.
// viper.BindPFlag for flags) before calling. If configPath is non-empty the
// file is read; a missing/invalid file is an error.
func Load(v *viper.Viper, configPath string) (Server, error) {
	v.SetEnvPrefix("DIYDDNS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for key, def := range keyDefaults {
		v.SetDefault(key, def)
		if err := v.BindEnv(key); err != nil {
			return Server{}, fmt.Errorf("config: bind env %s: %w", key, err)
		}
	}

	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return Server{}, fmt.Errorf("config: read %s: %w", configPath, err)
		}
	}

	var cfg Server
	if err := v.Unmarshal(&cfg); err != nil {
		return Server{}, fmt.Errorf("config: unmarshal: %w", err)
	}
	if cfg.Database.Path == "" {
		return Server{}, fmt.Errorf("config: database.path is required")
	}
	return cfg, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS. (If `TestLoad_BaseURLMapsUnderscoreKey` fails, confirm the `mapstructure:"base_url"` tag and `SetEnvKeyReplacer` are present.)

- [ ] **Step 6: Tidy and commit**

Run: `go mod tidy && go test ./internal/config/ -race`
```bash
git add go.mod go.sum internal/config/
git commit -m "feat(config): add minimal viper server config loader"
```

---

## Task 2: HTTP middleware (`internal/server/middleware`)

**Files:**
- Create: `internal/server/middleware/middleware.go`
- Test: `internal/server/middleware/middleware_test.go`

**Interfaces:**
- Produces:
  - `const RequestIDHeader = "X-Request-Id"`
  - `func RequestIDFromContext(ctx context.Context) string`
  - `func RequestID(next http.Handler) http.Handler`
  - `func AccessLog(log *slog.Logger) func(http.Handler) http.Handler`
  - `func Recover(log *slog.Logger) func(http.Handler) http.Handler`
  - `func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler`
- Consumes: `github.com/google/uuid` (existing dep).

- [ ] **Step 1: Write the failing test**

Create `internal/server/middleware/middleware_test.go`:
```go
package middleware_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/middleware"
)

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var seen string
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" {
		t.Fatal("expected a generated request id in context")
	}
	if got := rec.Header().Get(middleware.RequestIDHeader); got != seen {
		t.Errorf("response header %q, context %q — should match", got, seen)
	}
}

func TestRequestID_HonorsIncoming(t *testing.T) {
	var seen string
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.RequestIDHeader, "incoming-123")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "incoming-123" {
		t.Errorf("request id = %q, want incoming-123", seen)
	}
}

func TestAccessLog_EmitsLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.RequestID(middleware.AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/foo", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log not JSON: %v (%s)", err, buf.String())
	}
	if line["method"] != "GET" || line["path"] != "/foo" {
		t.Errorf("method/path = %v %v", line["method"], line["path"])
	}
	if line["status"].(float64) != 418 {
		t.Errorf("status = %v, want 418", line["status"])
	}
	if line["request_id"] == "" {
		t.Error("request_id missing from access log")
	}
}

func TestRecover_ConvertsPanicTo500(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.Recover(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "panic") {
		t.Errorf("panic not logged: %s", buf.String())
	}
}

func TestChain_OrdersOuterToInner(t *testing.T) {
	var order []string
	mk := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { order = append(order, "handler") })
	h := middleware.Chain(final, mk("a"), mk("b"), mk("c"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	want := []string{"a", "b", "c", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/middleware/ -v`
Expected: FAIL (package/symbols undefined).

- [ ] **Step 3: Write the implementation**

Create `internal/server/middleware/middleware.go`:
```go
// Package middleware provides the cross-cutting net/http middleware wrapped
// around the diyddns-server mux: request-id assignment, structured access
// logging, and panic recovery. Auth middleware (HMAC, session/CSRF) is added by
// later plans and is intentionally absent here.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// RequestIDHeader is the request/response header carrying the correlation id.
const RequestIDHeader = "X-Request-Id"

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request id stored by RequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// RequestID assigns each request a correlation id: it honors an incoming
// X-Request-Id, otherwise generates a UUIDv7. The id is placed in the request
// context and echoed in the response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			if v7, err := uuid.NewV7(); err == nil {
				id = v7.String()
			} else {
				id = uuid.NewString()
			}
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// AccessLog emits exactly one structured info line per request. Sensitive
// headers are never logged.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			log.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.Int("bytes_out", rec.bytes),
			)
		})
	}
}

// Recover converts a handler panic into a 500 and logs it, keeping the process
// alive.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
						slog.String("request_id", RequestIDFromContext(r.Context())),
						slog.Any("panic", rec),
					)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Chain wraps h with mws so that mws[0] is the outermost layer (runs first).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/middleware/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/middleware/
git commit -m "feat(server): add request-id, access-log, and recover middleware"
```

---

## Task 3: huma APIs + capabilities (`internal/server/api`)

**Files:**
- Create: `internal/server/api/api.go`, `internal/server/api/capabilities.go`
- Test: `internal/server/api/api_test.go`
- Modify: `go.mod`, `go.sum` (adds huma)

**Interfaces:**
- Consumes: `internal/version` (`version.Info`, `version.Current`), `internal/store` (later, for health).
- Produces:
  - `func Build(mux *http.ServeMux, log *slog.Logger, st *store.Store, info version.Info)`
  - `type Capabilities struct { ServerVersion string; SkewWindowSeconds int; AddressFamilies []string; OIDCEnabled bool }`
  - internal `agentConfig`, `apiConfig`, `registerCapabilities`.

> NOTE: `Build` gains its `RegisterHealth` call in Task 4. In this task `Build` sets up the two huma APIs and capabilities only; `st` is already in the signature so Task 4 is a pure addition.

- [ ] **Step 1: Add huma (imported immediately below)**

Run:
```bash
go get github.com/danielgtaylor/huma/v2@v2.38.0
```
Expected: `go.mod` gains `github.com/danielgtaylor/huma/v2 v2.38.0`.

- [ ] **Step 2: Write the failing test**

Create `internal/server/api/api_test.go`:
```go
package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/version"
)

// buildTestServer assembles the api package onto a mux (no middleware) for
// black-box HTTP assertions. st is nil here; health (Task 4) tolerates the
// nil-free path because these tests do not hit /readyz.
func newAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	api.Build(mux, discardLogger(), nil, version.Info{Version: "v1.2.3"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCapabilities_Response(t *testing.T) {
	srv := newAPIServer(t)
	resp, err := http.Get(srv.URL + "/agent/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got api.Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ServerVersion != "v1.2.3" {
		t.Errorf("ServerVersion = %q", got.ServerVersion)
	}
	if got.SkewWindowSeconds != 120 {
		t.Errorf("SkewWindowSeconds = %d, want 120", got.SkewWindowSeconds)
	}
	if len(got.AddressFamilies) != 2 {
		t.Errorf("AddressFamilies = %v", got.AddressFamilies)
	}
	if got.OIDCEnabled {
		t.Error("OIDCEnabled should be false in the skeleton")
	}
}

func TestOpenAPIDocs_TwoSeparateDocuments(t *testing.T) {
	srv := newAPIServer(t)
	agentDoc := getBody(t, srv.URL+"/agent/openapi.json")
	apiDoc := getBody(t, srv.URL+"/api/openapi.json")

	if !strings.Contains(agentDoc, "openapi") {
		t.Error("agent doc missing openapi field")
	}
	if !strings.Contains(agentDoc, "/agent/v1/capabilities") {
		t.Error("capabilities should be in the AGENT document")
	}
	if strings.Contains(apiDoc, "/agent/v1/capabilities") {
		t.Error("capabilities must NOT be in the API document")
	}
}

func TestScalarDocs_BothGroups(t *testing.T) {
	srv := newAPIServer(t)
	for _, path := range []string{"/agent/docs", "/api/docs"} {
		body := getBody(t, srv.URL+path)
		if !strings.Contains(strings.ToLower(body), "scalar") {
			t.Errorf("%s did not render Scalar docs", path)
		}
	}
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
```
> Add the `io` and `log/slog` imports the helpers need, plus a `discardLogger` helper:
```go
import (
	"io"
	"log/slog"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/server/api/ -v`
Expected: FAIL (`api.Build` / `api.Capabilities` undefined).

- [ ] **Step 4: Write `capabilities.go`**

Create `internal/server/api/capabilities.go`:
```go
package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/version"
)

// hmacSkewWindowSeconds mirrors the HMAC timestamp skew window from the design
// spec (§5A). Kept as a constant until the auth config section lands.
const hmacSkewWindowSeconds = 120

// Capabilities is the public shape returned by GET /agent/v1/capabilities. The
// client reads it to decide enrollment paths. Fields the skeleton cannot yet
// determine dynamically (OIDCEnabled) are static; later plans make them live.
type Capabilities struct {
	ServerVersion     string   `json:"server_version"`
	SkewWindowSeconds int      `json:"skew_window_seconds"`
	AddressFamilies   []string `json:"address_families"`
	OIDCEnabled       bool     `json:"oidc_enabled"`
}

type capabilitiesOutput struct {
	Body Capabilities
}

func registerCapabilities(a huma.API, info version.Info) {
	huma.Get(a, "/agent/v1/capabilities", func(_ context.Context, _ *struct{}) (*capabilitiesOutput, error) {
		return &capabilitiesOutput{Body: Capabilities{
			ServerVersion:     info.Version,
			SkewWindowSeconds: hmacSkewWindowSeconds,
			AddressFamilies:   []string{"ipv4", "ipv6"},
			OIDCEnabled:       false,
		}}, nil
	})
}
```

- [ ] **Step 5: Write `api.go`**

Create `internal/server/api/api.go`:
```go
// Package api builds the diyddns-server HTTP API: two independent huma APIs
// (one per route group, each with its own OpenAPI document and Scalar UI) plus
// the operational health handlers. Business operations and auth are added by
// later plans onto the same mux/APIs.
package api

import (
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// Build registers both huma APIs and the health handlers onto mux.
func Build(mux *http.ServeMux, log *slog.Logger, st *store.Store, info version.Info) {
	agentAPI := humago.New(mux, groupConfig("DIYDDNS Agent API", "/agent", info.Version))
	registerCapabilities(agentAPI, info)

	// UI-facing API: no operations yet (added by later plans). Registering it
	// now serves an (empty) /api/openapi.json + Scalar docs and reserves the
	// route-group seam.
	humago.New(mux, groupConfig("DIYDDNS UI API", "/api", info.Version))

	RegisterHealth(mux, log, st)
}

// groupConfig returns a huma.Config whose OpenAPI, Docs, and Schemas paths are
// all prefixed under prefix. Distinct SchemasPath per group is REQUIRED: both
// APIs share one ServeMux, and two APIs left at the default "/schemas" would
// register the same route twice and panic the mux.
func groupConfig(title, prefix, ver string) huma.Config {
	cfg := huma.DefaultConfig(title, ver)
	cfg.OpenAPIPath = prefix + "/openapi"
	cfg.DocsPath = prefix + "/docs"
	cfg.SchemasPath = prefix + "/schemas"
	cfg.DocsRenderer = huma.DocsRendererScalar
	return cfg
}
```

> `RegisterHealth` does not exist until Task 4. To keep this task compiling and its tests green **without** hitting `/readyz`, add a temporary stub in `api.go` in THIS task and replace it in Task 4:
```go
// TEMPORARY (replaced in Task 4): keeps Build compiling before health.go exists.
func RegisterHealth(_ *http.ServeMux, _ *slog.Logger, _ *store.Store) {}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -race -v`
Expected: PASS (capabilities, two-documents, Scalar docs).

- [ ] **Step 7: Tidy and commit**

Run: `go mod tidy && go test ./internal/server/api/ -race`
```bash
git add go.mod go.sum internal/server/api/
git commit -m "feat(server): mount two huma APIs with Scalar docs and capabilities op"
```

---

## Task 4: Health endpoints (`internal/server/api/health.go`)

**Files:**
- Create: `internal/server/api/health.go`
- Modify: `internal/server/api/api.go` (remove the temporary `RegisterHealth` stub)
- Test: `internal/server/api/health_test.go`

**Interfaces:**
- Consumes: `internal/store` (`st.DB().PingContext`).
- Produces: `func RegisterHealth(mux *http.ServeMux, log *slog.Logger, st *store.Store)` (real implementation).

- [ ] **Step 1: Write the failing test**

Create `internal/server/api/health_test.go`:
```go
package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/store"
)

func openMemStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestHealthz_OK(t *testing.T) {
	mux := http.NewServeMux()
	api.RegisterHealth(mux, discardLogger(), openMemStore(t))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if body := getBody(t, srv.URL+"/healthz"); body != "ok" {
		t.Errorf("/healthz body = %q, want ok", body)
	}
}

func TestReadyz_ReadyThen503AfterClose(t *testing.T) {
	st := openMemStore(t)
	mux := http.NewServeMux()
	api.RegisterHealth(mux, discardLogger(), st)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if body := getBody(t, srv.URL+"/readyz"); body != "ready" {
		t.Errorf("/readyz body = %q, want ready", body)
	}

	_ = st.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/readyz after close = %d, want 503", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/api/ -run TestHealthz -v`
Expected: FAIL — the temporary stub registers nothing, so `/healthz` 404s.

- [ ] **Step 3: Remove the stub and write `health.go`**

In `internal/server/api/api.go`, delete the temporary `RegisterHealth` stub function (the real one now lives in `health.go`).

Create `internal/server/api/health.go`:
```go
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// RegisterHealth wires the operational health endpoints onto mux. They are
// plain handlers, deliberately outside both OpenAPI documents (plaintext,
// operational, not part of the API contract).
func RegisterHealth(mux *http.ServeMux, log *slog.Logger, st *store.Store) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.DB().PingContext(ctx); err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "readiness check failed", slog.Any("error", err))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready"))
	})
}
```

> The Task 3 `api_test.go` calls `api.Build(mux, log, nil, …)`. Now that `RegisterHealth` dereferences `st` on `/readyz`, ensure those tests never hit `/readyz` (they don't) — registering the handler with a nil `st` is safe; only a request would panic. The integration test in Task 5 uses a real store.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -race -v`
Expected: PASS (health tests + the Task 3 tests still green).

- [ ] **Step 5: Commit**

```bash
git add internal/server/api/
git commit -m "feat(server): add /healthz and /readyz health handlers"
```

---

## Task 5: Server assembly + logger (`internal/server`)

**Files:**
- Create: `internal/server/server.go`, `internal/server/logging.go`
- Test: `internal/server/server_test.go`, `internal/server/logging_test.go`

**Interfaces:**
- Consumes: `internal/config`, `internal/server/api`, `internal/server/middleware`, `internal/store`, `internal/version`.
- Produces:
  - `func NewLogger(cfg config.LoggingSection) (*slog.Logger, error)`
  - `func New(cfg config.Server, st *store.Store, log *slog.Logger) *Server`
  - `func (s *Server) Run(ctx context.Context) error`

- [ ] **Step 1: Write the failing logger test**

Create `internal/server/logging_test.go`:
```go
package server_test

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.LoggingSection
		wantErr bool
	}{
		{"json stderr info", config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, false},
		{"text stdout debug", config.LoggingSection{Level: "debug", Format: "text", Output: "stdout"}, false},
		{"bad level", config.LoggingSection{Level: "loud", Format: "json", Output: "stderr"}, true},
		{"bad format", config.LoggingSection{Level: "info", Format: "xml", Output: "stderr"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := server.NewLogger(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			if log == nil {
				t.Fatal("nil logger")
			}
		})
	}
}
```

- [ ] **Step 2: Write the failing server integration test**

Create `internal/server/server_test.go`:
```go
package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/store"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestServer_AllEndpoints(t *testing.T) {
	srv := httptest.NewServer(server.Handler(discard(), memStore(t)))
	t.Cleanup(srv.Close)

	cases := []struct {
		path       string
		wantStatus int
		contains   string
	}{
		{"/healthz", 200, "ok"},
		{"/readyz", 200, "ready"},
		{"/agent/v1/capabilities", 200, "server_version"},
		{"/agent/openapi.json", 200, "openapi"},
		{"/api/openapi.json", 200, "openapi"},
		{"/agent/docs", 200, "scalar"},
		{"/api/docs", 200, "scalar"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + c.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.wantStatus)
			}
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(strings.ToLower(string(b)), c.contains) {
				t.Errorf("body missing %q", c.contains)
			}
			if resp.Header.Get("X-Request-Id") == "" {
				t.Error("missing X-Request-Id (middleware chain not applied)")
			}
		})
	}
}

func TestServer_RunShutsDownOnCancel(t *testing.T) {
	s := server.New(config.Server{Server: config.ServerSection{Listen: "127.0.0.1:0"}}, memStore(t), discard())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down within 5s")
	}
}
```

> This test uses `server.Handler(log, st)` — an exported constructor for the wrapped handler so it can be black-box tested via `httptest`. `New` uses it internally.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/server/ -v`
Expected: FAIL (`server.NewLogger`, `server.Handler`, `server.New` undefined).

- [ ] **Step 4: Write `logging.go`**

Create `internal/server/logging.go`:
```go
package server

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jacaudi/diyddns/internal/config"
)

// NewLogger builds a slog.Logger from the logging config: level (debug|info|
// warn|error), format (json|text), and output (stderr|stdout|<path>).
func NewLogger(cfg config.LoggingSection) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(cfg.Level))); err != nil {
		return nil, fmt.Errorf("server: log level %q: %w", cfg.Level, err)
	}

	var w io.Writer
	switch cfg.Output {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("server: log output %q: %w", cfg.Output, err)
		}
		w = f
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "", "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("server: log format %q: must be json or text", cfg.Format)
	}
	return slog.New(handler), nil
}
```

- [ ] **Step 5: Write `server.go`**

Create `internal/server/server.go`:
```go
// Package server assembles the diyddns-server HTTP stack (mux + middleware +
// huma APIs) and owns its lifecycle (listen + graceful shutdown).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

const shutdownTimeout = 15 * time.Second

// Server owns the HTTP server lifecycle.
type Server struct {
	httpServer *http.Server
	log        *slog.Logger
}

// Handler builds the fully-wrapped http.Handler: the mux (health + two huma
// APIs) inside the RequestID → AccessLog → Recover middleware chain. Exported
// for black-box testing via httptest.
func Handler(log *slog.Logger, st *store.Store) http.Handler {
	mux := http.NewServeMux()
	api.Build(mux, log, st, version.Current())
	return middleware.Chain(mux,
		middleware.RequestID,
		middleware.AccessLog(log),
		middleware.Recover(log),
	)
}

// New constructs a Server bound to cfg.Server.Listen.
func New(cfg config.Server, st *store.Store, log *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           Handler(log, st),
			ReadHeaderTimeout: 10 * time.Second,
		},
		log: log,
	}
}

// Run starts the listener and blocks until ctx is cancelled, then gracefully
// drains in-flight requests. Returns nil on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.LogAttrs(ctx, slog.LevelInfo, "server listening", slog.String("addr", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server: listen: %w", err)
	case <-ctx.Done():
		s.log.LogAttrs(ctx, slog.LevelInfo, "server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server: shutdown: %w", err)
		}
		return nil
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/server/ -race -v`
Expected: PASS (logger, all-endpoints, shutdown).

- [ ] **Step 7: Commit**

```bash
git add internal/server/server.go internal/server/logging.go internal/server/server_test.go internal/server/logging_test.go
git commit -m "feat(server): assemble HTTP server with graceful shutdown and slog logger"
```

---

## Task 6: cobra CLI (`cmd/diyddns-server`)

**Files:**
- Modify (rewrite): `cmd/diyddns-server/main.go`
- Test: `cmd/diyddns-server/main_test.go`
- Modify: `go.mod`, `go.sum` (adds cobra)

**Interfaces:**
- Consumes: `internal/config`, `internal/server`, `internal/store`, `internal/version`.
- Produces: `func rootCmd() *cobra.Command` (for tests), `main()`.

- [ ] **Step 1: Add cobra (imported immediately below)**

Run:
```bash
go get github.com/spf13/cobra@v1.10.2
```
Expected: `go.mod` gains `github.com/spf13/cobra v1.10.2`.

- [ ] **Step 2: Write the failing test**

Create `cmd/diyddns-server/main_test.go`:
```go
package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "diyddns-server") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestServe_RequiresDatabasePath(t *testing.T) {
	// No --config, no DIYDDNS_DATABASE_PATH → config.Load must error before
	// the server blocks.
	t.Setenv("DIYDDNS_DATABASE_PATH", "")
	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "database.path") {
		t.Fatalf("want database.path error, got %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./cmd/diyddns-server/ -v`
Expected: FAIL (`rootCmd` undefined).

- [ ] **Step 4: Rewrite `main.go`**

Replace `cmd/diyddns-server/main.go` entirely:
```go
// Command diyddns-server is the DIYDDNS HTTP server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "diyddns-server:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "diyddns-server",
		Short:         "DIYDDNS server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(serveCmd(), versionCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "diyddns-server", version.Current().String())
			return nil
		},
	}
}

func serveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viper.New()
			if err := v.BindPFlag("server.listen", cmd.Flags().Lookup("listen")); err != nil {
				return err
			}
			cfg, err := config.Load(v, cfgPath)
			if err != nil {
				return err
			}
			log, err := server.NewLogger(cfg.Logging)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			st, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()

			log.LogAttrs(ctx, slog.LevelInfo, "starting diyddns-server",
				slog.String("version", version.Current().String()),
				slog.String("listen", cfg.Server.Listen),
			)
			return server.New(cfg, st, log).Run(ctx)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to server config file")
	cmd.Flags().String("listen", "", "HTTP listen address (overrides config)")
	return cmd
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/diyddns-server/ -race -v`
Expected: PASS.

- [ ] **Step 6: Manual smoke (optional but recommended)**

Run:
```bash
go run ./cmd/diyddns-server serve --config /dev/stdin <<<'database: {path: ":memory:"}' &
sleep 1
curl -fsS localhost:8080/healthz && echo
curl -fsS localhost:8080/agent/v1/capabilities && echo
curl -fsS localhost:8080/agent/openapi.json | head -c 80 && echo
kill %1
```
Expected: `ok`, a capabilities JSON, and an OpenAPI document prefix.

- [ ] **Step 7: Tidy and commit**

Run: `go mod tidy && go build ./cmd/...`
```bash
git add go.mod go.sum cmd/diyddns-server/
git commit -m "feat(server): add cobra serve/version commands over the HTTP server"
```

---

## Task 7: Client dependency isolation + full verification

**Files:**
- Create: `cmd/diyddns-client/deps_test.go`

**Interfaces:**
- None produced; this task guards the Global Constraint that huma stays server-only.

- [ ] **Step 1: Write the failing test**

Create `cmd/diyddns-client/deps_test.go`:
```go
package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClientExcludesHuma asserts the client binary's transitive imports do not
// include the huma API framework (a server-only dependency per the design).
// cobra/viper are shared and intentionally not checked.
func TestClientExcludesHuma(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	const forbidden = "github.com/danielgtaylor/huma"
	if strings.Contains(string(out), forbidden) {
		t.Errorf("client binary imports server-only dependency %q", forbidden)
	}
}
```

- [ ] **Step 2: Run test to verify it passes (guard already holds)**

Run: `go test ./cmd/diyddns-client/ -run TestClientExcludesHuma -v`
Expected: PASS (nothing in the client imports huma). If it FAILS, a server-only package leaked into the client import graph — fix the leak, do not weaken the test.

- [ ] **Step 3: Full-suite verification (per superpowers:verification-before-completion)**

Run each and confirm real output:
```bash
go build ./cmd/...
go test ./... -race
golangci-lint run
go list -deps ./cmd/diyddns-client | grep -c 'danielgtaylor/huma' # expect 0
```
Expected: build succeeds; all tests pass under `-race`; lint clean; grep count `0`.

- [ ] **Step 4: Commit**

```bash
git add cmd/diyddns-client/deps_test.go
git commit -m "test(client): assert client binary excludes the huma server dependency"
```

---

## Self-Review (completed during authoring)

- **Spec coverage vs design §2–§9:** two huma APIs + Scalar (Task 3) ✓; distinct SchemasPath (Task 3) ✓; middleware RequestID/AccessLog/Recover (Task 2) ✓; plain health outside docs (Task 4) ✓; capabilities (Task 3) ✓; minimal viper config with precedence (Task 1) ✓; cobra serve/version (Task 6) ✓; migrate-on-start via `store.Open` (Task 6) ✓; graceful shutdown (Task 5) ✓; client huma-isolation (Task 7) ✓; `-race` + lint (Task 7) ✓. Non-goals (auth, business endpoints, UI, TLS) correctly excluded.
- **Placeholder scan:** every code/test step contains complete code; no TBD/TODO. The Task 3 temporary `RegisterHealth` stub is explicitly created and explicitly removed in Task 4 (not a placeholder — a compile bridge with a named removal step).
- **Type consistency:** `config.Server`/`ServerSection`/`DatabaseSection`/`LoggingSection`, `config.Load(v, path)`, `middleware.{RequestID,AccessLog,Recover,Chain,RequestIDFromContext,RequestIDHeader}`, `api.Build`/`api.Capabilities`/`api.RegisterHealth`, `server.{Handler,New,Run,NewLogger}`, `version.Info{Version}` — names/signatures match across all tasks.
- **Dependency-ordering:** viper→Task 1, huma→Task 3, cobra→Task 6, each added in its first-importing task (avoids `go mod tidy` pruning).
