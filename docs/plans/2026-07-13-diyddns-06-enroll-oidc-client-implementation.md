# Plan 06 — `enroll --oidc` Client Implementation Plan

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

**Goal:** Implement `diyddns-client enroll --oidc` — a CLI command that drives the server's RFC 8628 device-code enrollment flow (Plan 05) end to end and persists the minted device credentials.

**Architecture:** A single OIDC-only vertical plus the client foundation it is first to need. `internal/client/enroll` holds an unauthenticated `net/http` client for `/agent/v1` and a device-code driver with `Clock`/`Prompter` test seams. `internal/client/credentials` owns `credentials.json` (its own package so future `run`/`status` read it without importing enrollment). `internal/config` gains a minimal viper client loader. `cmd/diyddns-client` becomes a cobra app (`root`/`enroll`/`version`), replacing the `flag` scaffold. The client imports **no** server-only deps.

**Tech Stack:** Go 1.25 (no CGO). `spf13/cobra` v1.10.2 + `spf13/viper` v1.21.0 (already in `go.mod`). Standard library for everything else (`net/http`, `encoding/json`, `crypto/tls`, `crypto/x509`, `encoding/base64`, `os`, `os/signal`). **No new module dependencies.**

**Source of truth:** `docs/designs/2026-07-13-diyddns-06-enroll-oidc-client-design.md`.
**Wire contract source of truth:** `internal/server/api/enroll_oidc.go` + `internal/server/api/capabilities.go` (merged Plan 05).

## Global Constraints

- **Go 1.25, no CGO.** Module path prefix: `github.com/jacaudi/diyddns`.
- **Client stays free of server-only deps:** `github.com/danielgtaylor/huma`, `golang.org/x/oauth2`, `github.com/coreos/go-oidc`, `github.com/go-jose/go-jose` must NEVER appear in the client's transitive imports. Enforced by the existing `cmd/diyddns-client/deps_test.go` — it stays green and **unchanged**.
- **No client-side token verification.** The client only exchanges the opaque `flow_id`; all OIDC/JWT logic is server-side.
- **Never log or print** the `secret`, `flow_id`, or `device_code`. (`user_code` / `verification_uri` are printed — they are for the user.)
- **No partial writes.** `credentials.json` is written only on a successful poll, atomically (tmp + rename), mode `0600`.
- **Errors wrapped with `%w`;** package-qualified messages (`"enroll: <what>: %w"`).
- **Tests:** stdlib `testing`, table-driven where natural, run under `-race`. HTTP is mocked with `net/http/httptest`; timing is driven by an injected fake `Clock` — **no real sleeps in tests**. No live network.
- **Wire contract (verbatim from Plan 05):**
  - `POST /agent/v1/enroll/oidc/start` (empty body) → `200 {flow_id, user_code, verification_uri, verification_uri_complete?, expires_in, interval}` | `501` (unsupported) | `502` (IdP start failed) | `500`.
  - `POST /agent/v1/enroll/oidc/poll {flow_id}` → `200 {status:"pending"}` | `200 {status:"slow_down"}` | `200 {device_id, secret}` (both non-empty; `secret` base64; success) | `410` (gone/denied) | `401` (rejected) | `502` (IdP poll failed) | `500`. **`501` never comes from poll.**
  - `GET /agent/v1/capabilities` → `200 {…, oidc_enabled, oidc_device_enabled}`.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/client/credentials/credentials.go` | `Credentials` struct; `DefaultPath`, `Load`, `Save` (0600, atomic, refuse-exists) |
| `internal/client/credentials/credentials_test.go` | perms, atomic, refuse/force, round-trip, ErrNotFound/ErrExists |
| `internal/config/client.go` | `ClientConfig` + `LoadClient` (viper: `server.url`/`server.ca_bundle`/`logging.*`) |
| `internal/config/client_test.go` | precedence flag>env>file>default; optional-file path |
| `internal/client/enroll/errors.go` | typed sentinels |
| `internal/client/enroll/client.go` | `Client` (net/http, `--ca-cert`), `Capabilities`/`OIDCDeviceStart`/`OIDCDevicePoll`, wire structs |
| `internal/client/enroll/client_test.go` | status→sentinel mapping, empty-200→ErrProtocol, TLS via `httptest.NewTLSServer` |
| `internal/client/enroll/oidc.go` | `Clock`/`Prompter`, `NewSystemClock`, `DeviceCodeEnroll` poll loop, `Result` |
| `internal/client/enroll/oidc_test.go` | loop scenarios via httptest + fake clock |
| `cmd/diyddns-client/root.go` | cobra root command wiring |
| `cmd/diyddns-client/version.go` | `version` subcommand (migrated off `flag`) |
| `cmd/diyddns-client/enroll.go` | `enroll` command: flags, orchestration, stderr `Prompter` |
| `cmd/diyddns-client/main.go` | `signal.NotifyContext` + `rootCmd.ExecuteContext` |
| `cmd/diyddns-client/enroll_test.go` | end-to-end via httptest (success on first poll → no sleep) |
| `cmd/diyddns-client/deps_test.go` | **unchanged** — server-only-dep isolation guard |

**Task dependency order:** T1 (credentials) and T2 (config) are independent. T3 (enroll client) is independent. T4 depends on T3. T5 (cobra scaffold) is independent. T6 depends on T1–T5.

---

## Task 1: `credentials` package

**Files:**
- Create: `internal/client/credentials/credentials.go`
- Test: `internal/client/credentials/credentials_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `type Credentials struct { ServerURL, DeviceID, Secret string }` (JSON tags `server_url`/`device_id`/`secret`); `func DefaultPath() (string, error)`; `func Load(path string) (Credentials, error)`; `func Save(path string, c Credentials, force bool) error`; `var ErrNotFound, ErrExists error`.

- [ ] **Step 1: Write the failing test**

```go
package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveThenLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.json")
	want := Credentials{ServerURL: "https://ddns.example.com", DeviceID: "dev_123", Secret: "c2VjcmV0"}
	if err := Save(path, want, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("round trip: got %+v want %+v", got, want)
	}
}

func TestSavePermissions0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix perms")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := Save(path, Credentials{DeviceID: "d"}, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestSaveRefusesExistingWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := Save(path, Credentials{DeviceID: "first"}, false); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	err := Save(path, Credentials{DeviceID: "second"}, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Save err = %v, want ErrExists", err)
	}
	got, _ := Load(path)
	if got.DeviceID != "first" {
		t.Errorf("file was clobbered: %q", got.DeviceID)
	}
}

func TestSaveForceOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	_ = Save(path, Credentials{DeviceID: "first"}, false)
	if err := Save(path, Credentials{DeviceID: "second"}, true); err != nil {
		t.Fatalf("force Save: %v", err)
	}
	got, _ := Load(path)
	if got.DeviceID != "second" {
		t.Errorf("force did not overwrite: %q", got.DeviceID)
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/credentials/ -run Test -v`
Expected: FAIL — package/symbols undefined (`undefined: Save`).

- [ ] **Step 3: Write minimal implementation**

```go
// Package credentials reads and writes the diyddns-client credentials file
// (credentials.json): the device_id + HMAC secret minted at enrollment, plus
// the server URL. It is deliberately independent of the enrollment logic so
// future commands (run, status, rotate) can read credentials without importing
// the enroll package.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound is returned by Load when the credentials file does not exist.
var ErrNotFound = errors.New("credentials: file not found")

// ErrExists is returned by Save when the file already exists and force is false.
var ErrExists = errors.New("credentials: file already exists")

// Credentials is the on-disk credentials.json shape. Secret is the device HMAC
// key as base64 (exactly as the server delivered it).
type Credentials struct {
	ServerURL string `json:"server_url"`
	DeviceID  string `json:"device_id"`
	Secret    string `json:"secret"`
}

// DefaultPath returns the XDG-conforming default credentials path
// (<user-config-dir>/diyddns/credentials.json).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("credentials: resolve config dir: %w", err)
	}
	return filepath.Join(dir, "diyddns", "credentials.json"), nil
}

// Load reads and parses the credentials file. It returns ErrNotFound if the
// file is absent.
func Load(path string) (Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credentials{}, ErrNotFound
		}
		return Credentials{}, fmt.Errorf("credentials: read %s: %w", path, err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return Credentials{}, fmt.Errorf("credentials: parse %s: %w", path, err)
	}
	return c, nil
}

// Save writes c to path atomically with mode 0600, creating parent dirs (0700).
// If the file already exists and force is false it returns ErrExists without
// writing anything.
func Save(path string, c Credentials, force bool) error {
	if !force {
		switch _, err := os.Stat(path); {
		case err == nil:
			return ErrExists
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("credentials: stat %s: %w", path, err)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("credentials: mkdir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("credentials: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("credentials: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("credentials: rename %s: %w", path, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/credentials/ -race -v`
Expected: PASS (all five tests).

- [ ] **Step 5: Commit**

```bash
git add internal/client/credentials/
git commit -m "feat(client): credentials.json store (0600, atomic, refuse-exists)"
```

---

## Task 2: `config.LoadClient` client config loader

**Files:**
- Create: `internal/config/client.go`
- Test: `internal/config/client_test.go`

**Interfaces:**
- Consumes: existing `config.LoggingSection` (reused).
- Produces: `type ClientConfig struct { Server ClientServerSection; Logging LoggingSection }`; `type ClientServerSection struct { URL string; CABundle string }` (mapstructure `url`/`ca_bundle`); `func LoadClient(v *viper.Viper, configPath string) (ClientConfig, error)`.

Note: mirrors the existing server `Load` (explicit `BindEnv`, no `AutomaticEnv`; `SetDefault` outranks an unchanged pflag default — the Plan 03 gotcha). Reuses `LoggingSection` (already declared in `config.go`).

- [ ] **Step 1: Write the failing test**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestLoadClientDefaults(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Server.URL != "" || cfg.Logging.Level != "info" || cfg.Logging.Format != "text" {
		t.Errorf("defaults wrong: %+v", cfg)
	}
}

func TestLoadClientFileThenEnvThenFlag(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("server:\n  url: https://from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// file wins over default
	cfg, err := LoadClient(viper.New(), file)
	if err != nil {
		t.Fatalf("LoadClient(file): %v", err)
	}
	if cfg.Server.URL != "https://from-file" {
		t.Errorf("file: got %q", cfg.Server.URL)
	}

	// env wins over file
	t.Setenv("DIYDDNS_SERVER_URL", "https://from-env")
	cfg, err = LoadClient(viper.New(), file)
	if err != nil {
		t.Fatalf("LoadClient(env): %v", err)
	}
	if cfg.Server.URL != "https://from-env" {
		t.Errorf("env: got %q", cfg.Server.URL)
	}

	// changed flag wins over env
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.String("server", "", "")
	_ = fs.Set("server", "https://from-flag")
	v := viper.New()
	if err := v.BindPFlag("server.url", fs.Lookup("server")); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadClient(v, file)
	if err != nil {
		t.Fatalf("LoadClient(flag): %v", err)
	}
	if cfg.Server.URL != "https://from-flag" {
		t.Errorf("flag: got %q", cfg.Server.URL)
	}
}

func TestLoadClientMissingFileIsError(t *testing.T) {
	_, err := LoadClient(viper.New(), filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoadClient -v`
Expected: FAIL — `undefined: LoadClient`.

- [ ] **Step 3: Write minimal implementation**

```go
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// ClientConfig is the fully-resolved diyddns-client configuration. Only the
// sections the enroll vertical needs today are present; run/status add fields
// without restructuring existing callers.
type ClientConfig struct {
	Server  ClientServerSection
	Logging LoggingSection
}

// ClientServerSection holds the target server URL and an optional CA bundle
// for self-signed homelab servers.
type ClientServerSection struct {
	URL      string `mapstructure:"url"`
	CABundle string `mapstructure:"ca_bundle"`
}

// clientKeyDefaults enumerates every client config key, its default, and (via
// BindEnv) its DIYDDNS_* env var. As with the server loader there is no
// AutomaticEnv, so every key MUST be listed or its env var is ignored.
var clientKeyDefaults = map[string]any{
	"server.url":       "",
	"server.ca_bundle": "",
	"logging.level":    "info",
	"logging.format":   "text", // spec §8: text default for the interactive client
}

// LoadClient resolves the client configuration. Callers may pre-configure v
// (e.g. viper.BindPFlag for flags) before calling. If configPath is non-empty
// the file is read; a missing/invalid file is an error.
func LoadClient(v *viper.Viper, configPath string) (ClientConfig, error) {
	v.SetEnvPrefix("DIYDDNS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for key, def := range clientKeyDefaults {
		v.SetDefault(key, def)
		if err := v.BindEnv(key); err != nil {
			return ClientConfig{}, fmt.Errorf("config: bind env %s: %w", key, err)
		}
	}
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return ClientConfig{}, fmt.Errorf("config: read %s: %w", configPath, err)
		}
	}
	var cfg ClientConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return ClientConfig{}, fmt.Errorf("config: unmarshal: %w", err)
	}
	return cfg, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -race -run TestLoadClient -v`
Expected: PASS (three tests).

- [ ] **Step 5: Commit**

```bash
git add internal/config/client.go internal/config/client_test.go
git commit -m "feat(client): minimal viper client config loader"
```

---

## Task 3: `enroll` HTTP client, wire types, and sentinels

**Files:**
- Create: `internal/client/enroll/errors.go`
- Create: `internal/client/enroll/client.go`
- Test: `internal/client/enroll/client_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - sentinels `ErrDeviceUnsupported, ErrFlowGone, ErrRejected, ErrBadGateway, ErrServer, ErrExpired, ErrProtocol error`
  - `type Capabilities struct { ServerVersion string; OIDCEnabled bool; OIDCDeviceEnabled bool }`
  - `type DeviceStart struct { FlowID, UserCode, VerificationURI, VerificationURIComplete string; ExpiresIn, Interval int64 }`
  - `type PollResult struct { Kind pollKind; DeviceID, Secret string }` with unexported `pollKind` consts `pollPending, pollSlowDown, pollComplete`
  - `type ClientOptions struct { CACertPath string; Timeout time.Duration }`
  - `type Client struct{…}`; `func NewClient(baseURL string, opts ClientOptions) (*Client, error)`
  - methods `func (c *Client) Capabilities(ctx) (Capabilities, error)`, `func (c *Client) OIDCDeviceStart(ctx) (DeviceStart, error)`, `func (c *Client) OIDCDevicePoll(ctx, flowID string) (PollResult, error)`

- [ ] **Step 1: Write the failing test**

```go
package enroll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	c, err := NewClient(ts.URL, ClientOptions{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "notaurl"} {
		if _, err := NewClient(u, ClientOptions{}); err == nil {
			t.Errorf("NewClient(%q) err = nil, want error", u)
		}
	}
}

func TestDeviceStartStatusMapping(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    error // nil = success
	}{
		{"ok", 200, `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`, nil},
		{"unsupported", 501, `{}`, ErrDeviceUnsupported},
		{"badgateway", 502, `{}`, ErrBadGateway},
		{"server", 500, `{}`, ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			ds, err := c.OIDCDeviceStart(context.Background())
			if tt.want == nil {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if ds.FlowID != "f" || ds.UserCode != "UC" || ds.ExpiresIn != 300 {
					t.Errorf("bad decode: %+v", ds)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDevicePollStatusMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  error
		wantKind pollKind
	}{
		{"pending", 200, `{"status":"pending"}`, nil, pollPending},
		{"slow_down", 200, `{"status":"slow_down"}`, nil, pollSlowDown},
		{"complete", 200, `{"device_id":"dev","secret":"c2VjcmV0"}`, nil, pollComplete},
		{"empty200", 200, `{}`, ErrProtocol, 0},
		{"bad_secret", 200, `{"device_id":"dev","secret":"!!notb64"}`, ErrProtocol, 0},
		{"gone", 410, `{}`, ErrFlowGone, 0},
		{"rejected", 401, `{}`, ErrRejected, 0},
		{"idp", 502, `{}`, ErrBadGateway, 0},
		{"server", 500, `{}`, ErrServer, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/agent/v1/enroll/oidc/poll" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			res, err := c.OIDCDevicePoll(context.Background(), "flow123")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if res.Kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", res.Kind, tt.wantKind)
			}
			if tt.wantKind == pollComplete && (res.DeviceID != "dev" || res.Secret != "c2VjcmV0") {
				t.Errorf("complete payload wrong: %+v", res)
			}
		})
	}
}

func TestCapabilitiesDecode(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"server_version":"1.0","oidc_enabled":true,"oidc_device_enabled":true}`))
	})
	caps, err := c.Capabilities(context.Background())
	if err != nil || !caps.OIDCDeviceEnabled {
		t.Fatalf("caps = %+v err = %v", caps, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/enroll/ -run 'TestNewClient|TestDevice|TestCapabilities' -v`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write `errors.go`**

```go
package enroll

import "errors"

// Sentinel errors classifying a device-code enrollment outcome. The command
// layer maps each to a distinct operator message and a non-zero exit.
var (
	// ErrDeviceUnsupported: server reports OIDC device flow unavailable (501, start-only).
	ErrDeviceUnsupported = errors.New("enroll: server does not support OIDC device enrollment")
	// ErrFlowGone: the device flow is gone, denied, or expired server-side (410).
	ErrFlowGone = errors.New("enroll: device authorization denied or expired")
	// ErrRejected: the user authenticated but enrollment was not authorized (401).
	ErrRejected = errors.New("enroll: enrollment not authorized")
	// ErrBadGateway: the server could not reach the identity provider (502).
	ErrBadGateway = errors.New("enroll: server could not reach the identity provider")
	// ErrServer: server internal error (500 or other unexpected status).
	ErrServer = errors.New("enroll: server error")
	// ErrExpired: the device code expired before the user authorized.
	ErrExpired = errors.New("enroll: device code expired before authorization")
	// ErrProtocol: the server returned a 200 that does not match the contract.
	ErrProtocol = errors.New("enroll: unexpected server response")
)
```

- [ ] **Step 4: Write `client.go`**

```go
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Capabilities is the subset of GET /agent/v1/capabilities the client reads.
type Capabilities struct {
	ServerVersion     string `json:"server_version"`
	OIDCEnabled       bool   `json:"oidc_enabled"`
	OIDCDeviceEnabled bool   `json:"oidc_device_enabled"`
}

// DeviceStart is the 200 body of POST /agent/v1/enroll/oidc/start.
type DeviceStart struct {
	FlowID                  string `json:"flow_id"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type pollKind int

const (
	pollPending pollKind = iota
	pollSlowDown
	pollComplete
)

// PollResult is the classified outcome of one successful (200) poll. On
// pollComplete, DeviceID and Secret are non-empty and Secret is valid base64
// carried verbatim from the wire.
type PollResult struct {
	Kind     pollKind
	DeviceID string
	Secret   string
}

// ClientOptions configures the enroll HTTP client.
type ClientOptions struct {
	CACertPath string        // optional PEM bundle to trust (self-signed servers)
	Timeout    time.Duration // per-request timeout; 0 → 10s
}

// Client is an unauthenticated HTTP client for the server's /agent/v1 enroll
// surface. It never signs requests — enrollment is how a device first obtains
// its secret.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient validates baseURL (http/https), builds an HTTP client, and — if
// opts.CACertPath is set — trusts that CA bundle instead of only the system pool.
func NewClient(baseURL string, opts ClientOptions) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("enroll: server URL must be http(s): %q", baseURL)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("enroll: read ca cert %s: %w", opts.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("enroll: no certificates in %s", opts.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: timeout, Transport: transport}}, nil
}

// Capabilities fetches GET /agent/v1/capabilities.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/agent/v1/capabilities", http.NoBody)
	if err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Capabilities{}, fmt.Errorf("enroll: capabilities: unexpected status %d", resp.StatusCode)
	}
	var caps Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities decode: %w", err)
	}
	return caps, nil
}

// OIDCDeviceStart begins the device-authorization grant (POST .../start).
func (c *Client) OIDCDeviceStart(ctx context.Context) (DeviceStart, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/v1/enroll/oidc/start", http.NoBody)
	if err != nil {
		return DeviceStart{}, fmt.Errorf("enroll: start request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return DeviceStart{}, fmt.Errorf("enroll: start: %w", err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var ds DeviceStart
		if err := json.NewDecoder(resp.Body).Decode(&ds); err != nil {
			return DeviceStart{}, fmt.Errorf("enroll: start decode: %w", err)
		}
		return ds, nil
	case http.StatusNotImplemented:
		return DeviceStart{}, ErrDeviceUnsupported
	case http.StatusBadGateway:
		return DeviceStart{}, ErrBadGateway
	default:
		return DeviceStart{}, fmt.Errorf("%w: start status %d", ErrServer, resp.StatusCode)
	}
}

// OIDCDevicePoll performs one poll (POST .../poll). Terminal transport statuses
// surface as sentinels; 200 bodies classify into a PollResult.
func (c *Client) OIDCDevicePoll(ctx context.Context, flowID string) (PollResult, error) {
	payload, err := json.Marshal(struct {
		FlowID string `json:"flow_id"`
	}{FlowID: flowID})
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/v1/enroll/oidc/poll", bytes.NewReader(payload))
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll: %w", err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var b struct {
			Status   string `json:"status"`
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return PollResult{}, fmt.Errorf("%w: poll decode: %v", ErrProtocol, err)
		}
		switch b.Status {
		case "pending":
			return PollResult{Kind: pollPending}, nil
		case "slow_down":
			return PollResult{Kind: pollSlowDown}, nil
		case "":
			if b.DeviceID == "" || b.Secret == "" {
				return PollResult{}, fmt.Errorf("%w: empty success body", ErrProtocol)
			}
			if _, err := base64.StdEncoding.DecodeString(b.Secret); err != nil {
				return PollResult{}, fmt.Errorf("%w: secret not base64", ErrProtocol)
			}
			return PollResult{Kind: pollComplete, DeviceID: b.DeviceID, Secret: b.Secret}, nil
		default:
			return PollResult{}, fmt.Errorf("%w: unknown status %q", ErrProtocol, b.Status)
		}
	case http.StatusGone:
		return PollResult{}, ErrFlowGone
	case http.StatusUnauthorized:
		return PollResult{}, ErrRejected
	case http.StatusBadGateway:
		return PollResult{}, ErrBadGateway
	default:
		return PollResult{}, fmt.Errorf("%w: poll status %d", ErrServer, resp.StatusCode)
	}
}

// drainClose drains and closes a response body so the connection can be reused.
func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<16))
	_ = rc.Close()
}
```

- [ ] **Step 5: Run tests + a TLS check, verify they pass**

Add this TLS test to `client_test.go` (verifies `--ca-cert` trust):

```go
func TestNewClientCACertTrustsTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"oidc_device_enabled":true}`))
	}))
	t.Cleanup(ts.Close)

	// Without the CA, the self-signed cert is rejected.
	plain, _ := NewClient(ts.URL, ClientOptions{})
	if _, err := plain.Capabilities(context.Background()); err == nil {
		t.Fatal("expected TLS verification failure without CA")
	}

	// Write the server's cert to a PEM file and trust it via --ca-cert.
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	trusting, err := NewClient(ts.URL, ClientOptions{CACertPath: caPath})
	if err != nil {
		t.Fatalf("NewClient(ca): %v", err)
	}
	if _, err := trusting.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities with CA: %v", err)
	}
}
```

**Import merge (required):** step 1 wrote `client_test.go` with its own import block; this test adds `"encoding/pem"`, `"os"`, `"path/filepath"`. **Merge them into the single existing `import (…)` block** — do not add a second import statement, or the file won't compile.

Run: `go test ./internal/client/enroll/ -race -v`
Expected: PASS (all mapping tests + TLS test).

- [ ] **Step 6: Commit**

```bash
git add internal/client/enroll/errors.go internal/client/enroll/client.go internal/client/enroll/client_test.go
git commit -m "feat(client): unauthenticated enroll HTTP client + wire types + sentinels"
```

---

## Task 4: device-code driver (`DeviceCodeEnroll` poll loop)

**Files:**
- Create: `internal/client/enroll/oidc.go`
- Test: `internal/client/enroll/oidc_test.go`

**Interfaces:**
- Consumes (from Task 3): `*Client`, its `OIDCDeviceStart`/`OIDCDevicePoll`, the sentinels, `pollKind` consts.
- Produces:
  - `type Clock interface { Now() time.Time; Sleep(ctx context.Context, d time.Duration) error }`
  - `type Prompter interface { ShowUserCode(DeviceStart); Waiting() }`
  - `func NewSystemClock() Clock`
  - `type Result struct { DeviceID, Secret string }`
  - `func DeviceCodeEnroll(ctx context.Context, c *Client, p Prompter, clk Clock) (Result, error)`

Behavior: poll first (server allows the first poll immediately), then sleep `min(interval, remaining-to-deadline)` between polls. `slow_down` and a non-terminal `502` bump the interval by 5s; 3 consecutive `502`s → `ErrBadGateway`; `410`/`401`/`500`/protocol are terminal; deadline (`expires_in`) → `ErrExpired`; `expires_in<=0` at start → `ErrExpired`.

**Complexity note:** `DeviceCodeEnroll` sits just under `.golangci.yml`'s `gocyclo min-complexity: 15` (≈13–14). If you need to add a branch during implementation, extract the poll-result classification into a small helper rather than inlining it, so the step-6 `golangci-lint` gate stays green.

- [ ] **Step 1: Write the failing test**

```go
package enroll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances virtual time on each Sleep so deadline logic terminates
// without real waiting.
type fakeClock struct {
	now   time.Time
	slept []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.slept = append(f.slept, d)
	f.now = f.now.Add(d)
	return nil
}

type capturePrompter struct {
	shown  bool
	waited bool
}

func (c *capturePrompter) ShowUserCode(DeviceStart) { c.shown = true }
func (c *capturePrompter) Waiting()                  { c.waited = true }

// scriptServer serves a fixed start response, then returns poll responses from
// pollBodies in order (last one repeats).
func scriptServer(t *testing.T, start string, pollBodies []struct {
	status int
	body   string
}) *Client {
	t.Helper()
	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/enroll/oidc/start":
			_, _ = w.Write([]byte(start))
		case "/agent/v1/enroll/oidc/poll":
			i := int(atomic.AddInt64(&n, 1)) - 1
			if i >= len(pollBodies) {
				i = len(pollBodies) - 1
			}
			w.WriteHeader(pollBodies[i].status)
			_, _ = w.Write([]byte(pollBodies[i].body))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	c, err := NewClient(ts.URL, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type pb = struct {
	status int
	body   string
}

const startOK = `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`

func TestDeviceCodeEnrollSuccessAfterPending(t *testing.T) {
	c := scriptServer(t, startOK, []pb{
		{200, `{"status":"pending"}`},
		{200, `{"status":"pending"}`},
		{200, `{"device_id":"dev_9","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	p := &capturePrompter{}
	res, err := DeviceCodeEnroll(context.Background(), c, p, clk)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.DeviceID != "dev_9" || res.Secret != "c2VjcmV0" {
		t.Errorf("result = %+v", res)
	}
	if !p.shown || !p.waited {
		t.Errorf("prompter not called: %+v", p)
	}
	if len(clk.slept) != 2 { // slept between the 3 polls, not before the 1st, not after success
		t.Errorf("slept %d times, want 2", len(clk.slept))
	}
}

func TestDeviceCodeEnrollSlowDownBumpsInterval(t *testing.T) {
	c := scriptServer(t, startOK, []pb{
		{200, `{"status":"slow_down"}`},
		{200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(clk.slept) != 1 || clk.slept[0] != 10*time.Second { // 5s base + 5s bump
		t.Errorf("slept = %v, want [10s]", clk.slept)
	}
}

func TestDeviceCodeEnrollTerminalStatuses(t *testing.T) {
	tests := []struct {
		name string
		poll pb
		want error
	}{
		{"gone", pb{410, `{}`}, ErrFlowGone},
		{"rejected", pb{401, `{}`}, ErrRejected},
		{"server", pb{500, `{}`}, ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := scriptServer(t, startOK, []pb{tt.poll})
			clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			_, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDeviceCodeEnrollBadGatewayToleratedThenExhausted(t *testing.T) {
	// Two 502s then success → tolerated.
	c := scriptServer(t, startOK, []pb{
		{502, `{}`}, {502, `{}`}, {200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("tolerated 502 failed: %v", err)
	}
	// Three consecutive 502s → ErrBadGateway.
	c = scriptServer(t, startOK, []pb{{502, `{}`}})
	clk = &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrBadGateway) {
		t.Errorf("err = %v, want ErrBadGateway", err)
	}
}

func TestDeviceCodeEnrollExpires(t *testing.T) {
	// expires_in small, always pending → deadline reached → ErrExpired.
	start := `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":7,"interval":5}`
	c := scriptServer(t, start, []pb{{200, `{"status":"pending"}`}})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestDeviceCodeEnrollExpiresInNonPositive(t *testing.T) {
	start := `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":0,"interval":5}`
	c := scriptServer(t, start, []pb{{200, `{"status":"pending"}`}})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestDeviceCodeEnrollContextCancel(t *testing.T) {
	c := scriptServer(t, startOK, []pb{{200, `{"status":"pending"}`}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(ctx, c, &capturePrompter{}, clk); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/enroll/ -run TestDeviceCodeEnroll -v`
Expected: FAIL — `undefined: DeviceCodeEnroll` / `Clock` / `Prompter`.

- [ ] **Step 3: Write `oidc.go`**

```go
package enroll

import (
	"context"
	"errors"
	"time"
)

// Clock abstracts time so the poll loop is testable without real sleeps. Sleep
// returns the context error if ctx is cancelled while waiting.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// Prompter renders the user_code / verification_uri to the operator.
type Prompter interface {
	ShowUserCode(DeviceStart)
	Waiting()
}

// Result is the outcome of a completed device-code enrollment. Secret is the
// device HMAC key as wire base64 (verbatim).
type Result struct {
	DeviceID string
	Secret   string
}

const (
	minIntervalSeconds       = 5
	slowDownBumpSeconds      = 5
	maxConsecutiveBadGateway = 3
)

// DeviceCodeEnroll drives the RFC 8628 flow: start → display → poll loop →
// minted credentials. It writes no files. The first poll happens immediately
// (the server allows it); subsequent polls wait min(interval, time-to-deadline).
func DeviceCodeEnroll(ctx context.Context, c *Client, p Prompter, clk Clock) (Result, error) {
	ds, err := c.OIDCDeviceStart(ctx)
	if err != nil {
		return Result{}, err
	}
	if ds.ExpiresIn <= 0 {
		return Result{}, ErrExpired
	}
	p.ShowUserCode(ds)
	p.Waiting()

	deadline := clk.Now().Add(time.Duration(ds.ExpiresIn) * time.Second)
	intervalSecs := ds.Interval
	if intervalSecs < minIntervalSeconds {
		intervalSecs = minIntervalSeconds
	}
	interval := time.Duration(intervalSecs) * time.Second

	consecutive502 := 0
	for {
		res, err := c.OIDCDevicePoll(ctx, ds.FlowID)
		switch {
		case err == nil:
			consecutive502 = 0
			switch res.Kind {
			case pollComplete:
				return Result{DeviceID: res.DeviceID, Secret: res.Secret}, nil
			case pollSlowDown:
				interval += slowDownBumpSeconds * time.Second
			case pollPending:
			}
		case isBadGateway(err):
			consecutive502++
			if consecutive502 >= maxConsecutiveBadGateway {
				return Result{}, ErrBadGateway
			}
			interval += slowDownBumpSeconds * time.Second
		default:
			return Result{}, err // 410/401/500/protocol → terminal
		}

		now := clk.Now()
		if !now.Before(deadline) {
			return Result{}, ErrExpired
		}
		wait := interval
		if remaining := deadline.Sub(now); remaining < wait {
			wait = remaining
		}
		if err := clk.Sleep(ctx, wait); err != nil {
			return Result{}, err
		}
	}
}

func isBadGateway(err error) bool {
	return errors.Is(err, ErrBadGateway)
}

// NewSystemClock returns a Clock backed by the real wall clock. Sleep unblocks
// early (returning ctx.Err()) if ctx is cancelled — e.g. on SIGINT/SIGTERM.
func NewSystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/enroll/ -race -v`
Expected: PASS (all Task 3 + Task 4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/client/enroll/oidc.go internal/client/enroll/oidc_test.go
git commit -m "feat(client): RFC 8628 device-code poll loop with Clock/Prompter seams"
```

---

## Task 5: cobra scaffold (`root`, `version`, `main`)

**Files:**
- Create: `cmd/diyddns-client/root.go`
- Create: `cmd/diyddns-client/version.go`
- Rewrite: `cmd/diyddns-client/main.go`
- Test: `cmd/diyddns-client/root_test.go`

**Interfaces:**
- Consumes: `internal/version` (existing), `cobra`.
- Produces: `func newRootCmd() *cobra.Command` (adds `version` + `enroll` subcommands). `main` wires `signal.NotifyContext` → `ExecuteContext`.

Note: `newRootCmd` references `newEnrollCmd()` (Task 6). To keep this task compiling on its own, Task 5 adds `version` only and Task 6 adds the `newEnrollCmd()` registration line. **In this task, register only `newVersionCmd()`.** Task 6 adds `newEnrollCmd()`.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHasVersionSubcommand(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "version" {
			found = true
		}
	}
	if !found {
		t.Fatal("version subcommand not registered")
	}
}

func TestVersionSubcommandPrints(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "diyddns-client") {
		t.Errorf("output = %q", out.String())
	}
}

func TestVersionSubcommandJSON(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), `"Version"`) {
		t.Errorf("json output = %q", out.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run 'TestRoot|TestVersion' -v`
Expected: FAIL — `undefined: newRootCmd` (and the old `flag`-based `main.go` still present).

- [ ] **Step 3: Write `root.go`**

```go
package main

import "github.com/spf13/cobra"

// newRootCmd builds the diyddns-client root command and registers subcommands.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "diyddns-client",
		Short:         "DIYDDNS reporting agent",
		SilenceUsage:  true, // don't dump usage on a runtime error
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd())
	return root
}
```

- [ ] **Step 4: Write `version.go`**

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jacaudi/diyddns/internal/version"
)

// newVersionCmd prints the build identity and exits. --json emits the machine
// form (go-standards §9.2: version available in both text and JSON).
func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(version.Current())
			}
			fmt.Fprintln(cmd.OutOrStdout(), "diyddns-client", version.Current().String())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print version as JSON")
	return cmd
}
```

- [ ] **Step 5: Rewrite `main.go`**

```go
// Command diyddns-client is the DIYDDNS reporting agent.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
```

- [ ] **Step 6: Run tests to verify they pass, and confirm the isolation guard still holds**

Run: `go test ./cmd/diyddns-client/ -race -v`
Expected: PASS — `TestRootHasVersionSubcommand`, `TestVersionSubcommandPrints`, and the **existing** `TestClientExcludesServerOnlyDeps` (cobra is allowed; no forbidden deps yet).

- [ ] **Step 7: Commit**

```bash
git add cmd/diyddns-client/root.go cmd/diyddns-client/version.go cmd/diyddns-client/main.go cmd/diyddns-client/root_test.go
git commit -m "feat(client): cobra root + version subcommand (replaces flag scaffold)"
```

---

## Task 6: `enroll --oidc` command + end-to-end wiring

**Files:**
- Create: `cmd/diyddns-client/enroll.go`
- Modify: `cmd/diyddns-client/root.go` (register `newEnrollCmd()`)
- Test: `cmd/diyddns-client/enroll_test.go`

**Interfaces:**
- Consumes: `credentials` (T1), `config.LoadClient` (T2), `enroll.NewClient`/`DeviceCodeEnroll`/`NewSystemClock`/`ClientOptions`/`DeviceStart`/`Result` (T3–T4), `viper`, `cobra`.
- Produces: `func newEnrollCmd() *cobra.Command`.

Behavior (design §4): guard credentials-exists first → resolve server (flag>env>file) → `NewClient` (with `--ca-cert`) → `Capabilities` gate on `oidc_device_enabled` → `DeviceCodeEnroll` (stderr prompter, system clock) → `credentials.Save`. All UX to stderr. The end-to-end test's mock returns success on the **first** poll, so `NewSystemClock` never sleeps.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/client/credentials"
)

// oidcMockServer answers capabilities + start + (first-poll) success.
func oidcMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/capabilities":
			_, _ = w.Write([]byte(`{"oidc_enabled":true,"oidc_device_enabled":true}`))
		case "/agent/v1/enroll/oidc/start":
			_, _ = w.Write([]byte(`{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`))
		case "/agent/v1/enroll/oidc/poll":
			_, _ = w.Write([]byte(`{"device_id":"dev_42","secret":"c2VjcmV0"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func runEnroll(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCmd()
	root.SetOut(&nopWriter{})
	root.SetErr(&nopWriter{})
	root.SetArgs(args)
	return root.Execute()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestEnrollOIDCEndToEnd(t *testing.T) {
	ts := oidcMockServer(t)
	credPath := filepath.Join(t.TempDir(), "credentials.json")

	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	got, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DeviceID != "dev_42" || got.Secret != "c2VjcmV0" || got.ServerURL != ts.URL {
		t.Errorf("credentials = %+v", got)
	}
}

func TestEnrollRefusesExistingCredentials(t *testing.T) {
	ts := oidcMockServer(t)
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credPath, []byte(`{"device_id":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err == nil {
		t.Fatal("expected refusal without --force")
	}
	got, _ := credentials.Load(credPath)
	if got.DeviceID != "old" {
		t.Errorf("existing credentials clobbered: %+v", got)
	}
}

func TestEnrollDeviceDisabledCapability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"oidc_enabled":true,"oidc_device_enabled":false}`))
	}))
	t.Cleanup(ts.Close)
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err == nil {
		t.Fatal("expected error when oidc_device_enabled=false")
	}
	if _, statErr := os.Stat(credPath); statErr == nil {
		t.Error("credentials written despite capability gate")
	}
}

func TestEnrollRequiresOIDCFlag(t *testing.T) {
	err := runEnroll(t, "enroll", "--server", "https://x")
	if err == nil {
		t.Fatal("expected error without --oidc")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run TestEnroll -v`
Expected: FAIL — `enroll` command not registered / `newEnrollCmd` undefined.

- [ ] **Step 3: Write `enroll.go`**

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/enroll"
	"github.com/jacaudi/diyddns/internal/config"
)

// newEnrollCmd builds the `enroll` command. Only --oidc mode is implemented in
// Plan 06; --code/--user are future additive modes.
func newEnrollCmd() *cobra.Command {
	var (
		useOIDC    bool
		serverFlag string
		caCert     string
		force      bool
		credFile   string
		configFile string
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device with a diyddns server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !useOIDC {
				return fmt.Errorf("only --oidc enrollment is supported in this version")
			}
			v := viper.New()
			if err := v.BindPFlag("server.url", cmd.Flags().Lookup("server")); err != nil {
				return err
			}
			if err := v.BindPFlag("server.ca_bundle", cmd.Flags().Lookup("ca-cert")); err != nil {
				return err
			}
			cfg, err := config.LoadClient(v, configFile)
			if err != nil {
				return err
			}
			return runOIDCEnroll(cmd.Context(), enrollParams{
				out:      cmd.ErrOrStderr(),
				server:   cfg.Server.URL,
				caCert:   cfg.Server.CABundle,
				force:    force,
				credFile: credFile,
			})
		},
	}
	cmd.Flags().BoolVar(&useOIDC, "oidc", false, "use OIDC device-code enrollment")
	cmd.Flags().StringVar(&serverFlag, "server", "", "diyddns server base URL")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "PEM CA bundle to trust (self-signed servers)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing credentials.json")
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to client config.yaml")
	return cmd
}

type enrollParams struct {
	out      io.Writer
	server   string
	caCert   string
	force    bool
	credFile string
}

func runOIDCEnroll(ctx context.Context, p enrollParams) error {
	credPath := p.credFile
	if credPath == "" {
		dp, err := credentials.DefaultPath()
		if err != nil {
			return err
		}
		credPath = dp
	}

	// Guard existing credentials BEFORE contacting the server, so a re-enroll
	// without --force never spends an IdP device authorization.
	if !p.force {
		switch _, err := credentials.Load(credPath); {
		case err == nil:
			return fmt.Errorf("credentials already exist at %s (use --force to overwrite)", credPath)
		case !errors.Is(err, credentials.ErrNotFound):
			return err
		}
	}

	// Normalize once so the persisted ServerURL matches the URL requests use
	// (the future check-in client reads this field).
	p.server = strings.TrimRight(p.server, "/")
	if p.server == "" {
		return fmt.Errorf("server URL is required (--server or config server.url)")
	}
	c, err := enroll.NewClient(p.server, enroll.ClientOptions{CACertPath: p.caCert})
	if err != nil {
		return err
	}
	caps, err := c.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("contacting server: %w", err)
	}
	if !caps.OIDCDeviceEnabled {
		return fmt.Errorf("server does not support OIDC device enrollment")
	}

	res, err := enroll.DeviceCodeEnroll(ctx, c, stderrPrompter{w: p.out}, enroll.NewSystemClock())
	if err != nil {
		return err
	}
	if err := credentials.Save(credPath, credentials.Credentials{
		ServerURL: p.server,
		DeviceID:  res.DeviceID,
		Secret:    res.Secret,
	}, p.force); err != nil {
		return err
	}
	fmt.Fprintf(p.out, "Device %s enrolled. Credentials written to %s\n", res.DeviceID, credPath)
	return nil
}

// stderrPrompter renders the device-code prompt for the operator. It never
// prints the flow_id or the secret.
type stderrPrompter struct{ w io.Writer }

func (s stderrPrompter) ShowUserCode(ds enroll.DeviceStart) {
	fmt.Fprintf(s.w, "To authorize this device, visit:\n    %s\n", ds.VerificationURI)
	fmt.Fprintf(s.w, "and enter code: %s\n", ds.UserCode)
	if ds.VerificationURIComplete != "" {
		fmt.Fprintf(s.w, "(or open directly: %s)\n", ds.VerificationURIComplete)
	}
}

func (s stderrPrompter) Waiting() {
	fmt.Fprintln(s.w, "Waiting for authorization…")
}
```

- [ ] **Step 4: Register the command in `root.go`**

Change the `AddCommand` line:

```go
	root.AddCommand(newVersionCmd(), newEnrollCmd())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/diyddns-client/ -race -v`
Expected: PASS — all Task 5 + Task 6 tests, plus the unchanged `TestClientExcludesServerOnlyDeps`.

- [ ] **Step 6: Whole-vertical verification**

```bash
go build ./...
go test ./... -race
go vet ./...
golangci-lint run
go test ./cmd/diyddns-client/ -run TestClientExcludesServerOnlyDeps -v
```

Expected: build succeeds (both binaries); all tests pass under `-race`; vet clean; lint clean; the isolation guard confirms the client's transitive imports still exclude huma/oauth2/go-oidc/go-jose.

- [ ] **Step 7: Commit**

```bash
git add cmd/diyddns-client/enroll.go cmd/diyddns-client/root.go cmd/diyddns-client/enroll_test.go
git commit -m "feat(client): enroll --oidc command drives device-code flow end to end"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** design §1 scope → T1–T6; §2 layout → File Structure + task files; §3 wire contract → T3 status mapping + Global Constraints; §4 data flow → T4 loop + T6 orchestration; §5 component contracts → T1/T3/T4 Interfaces; §6 error handling → T3 sentinels + T4 loop + `credentials` atomic write; §7 testing → each task's tests + T6 step 6 gate; §8 follow-ups → not built (correct); §9 acceptance → covered (AC1 T6 e2e, AC2 T4, AC3 T1+T6, AC4 T3 TLS test, AC5 stderrPrompter/no-secret-log, AC6 unchanged deps_test, AC7 T6 step 6, AC8 T5/T2).
- **Placeholder scan:** the only intentional placeholder is the `errorsIs`→`errors.Is` correction called out explicitly in T4 step 3 (a teaching note, resolved in the same step). No `TODO`/`TBD`.
- **Type consistency:** `DeviceStart`, `PollResult`, `pollKind` consts, `Result`, `Clock`, `Prompter`, `ClientOptions`, `Credentials`, `ClientConfig` names match across T3→T4→T6. `enroll.NewSystemClock`, `enroll.NewClient`, `config.LoadClient`, `credentials.Save/Load/DefaultPath` referenced consistently.

**Plan review provenance:** SGE (sr-go-engineer, Fable) reviewed this plan — verdict **APPROVE-WITH-NITS**, 0 Critical (compile order, every status→sentinel mapping vs `enroll_oidc.go`, the poll-first sleep arithmetic, the `pb` alias, the TLS CA-extraction test, and the `deps_test` guarantee all verified). Folded: I-1 (`version --json` per go-standards §9.2 → T5), M-1 (persist trimmed `ServerURL` → T6 `runOIDCEnroll`), M-2 (prominent import-merge caution → T3 step 5), M-3 (`gocyclo` heads-up → T4). N-1 (manual `--oidc`/`--server` validation) accepted as justified (mode selector + env/config-sourced flag; `MarkFlagRequired` can't express it).

---

## Execution Handoff

Base off `origin/main` @ `d829309` (the local `main` checkout HEAD is stale at `677646a` — fast-forward it, or branch the execution worktree directly from `origin/main`). Plan 05 worktree `.claude/worktrees/plan-05-oidc` may be removed (PR #17 merged).
