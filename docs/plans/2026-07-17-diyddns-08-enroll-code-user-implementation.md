# Plan 08 — `diyddns-client enroll --code` / `--user` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

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

**Goal:** Add `diyddns-client enroll --code <code>` and `enroll --user <email>` (email+password) modes to the client CLI, completing the code-based enroll path (v1 §14 criterion #2) and the client half of issue #26.

**Architecture:** Additive. Two new methods on the existing unauthenticated `internal/client/enroll.Client` (sharing one private `doEnroll` response handler), one new sentinel, a secure password-input seam, a shared `finishEnroll` orchestrator that all three modes (existing `--oidc` + new `--code`/`--user`) route through, and declarative cobra mode-selection. One new module dependency (`golang.org/x/term`).

**Tech Stack:** Go 1.25 (no CGO), stdlib `net/http`/`encoding/json`/`bufio`, `golang.org/x/term` (hidden password read), cobra/viper (already present), stdlib `testing` (table-driven, `-race`).

**Design:** `docs/designs/2026-07-17-diyddns-08-enroll-code-user-design.md` (user-approved; SGE `sr-go-engineer` review AMEND-BEFORE-PLANNING, all findings folded).

## Global Constraints

- **Go 1.25, no CGO.** Errors wrapped with `%w`.
- **Client dependency guard:** the client binary must NOT import `huma`, `golang.org/x/oauth2`, `coreos/go-oidc`, or `go-jose`. `cmd/diyddns-client/deps_test.go` must stay green **unchanged**. Adding `golang.org/x/term` is allowed (it is not on the forbidden list). Do **not** import `internal/auth`, `internal/server/*`, or `internal/store` from the client.
- **Never log, echo, or print** the device secret or the enrollment password, and never place either in an error string. `x/term` reads the password with no echo.
- **Reuse the existing `enroll.Result`** (`{DeviceID, Secret string}`, declared in `internal/client/enroll/oidc.go`) — do NOT redeclare it (a second identical declaration in package `enroll` is a compile error).
- **Wire base64:** the device secret is carried verbatim as `base64.StdEncoding` on the wire; validate it decodes (else `ErrProtocol`), but store it verbatim.
- **Uniform 401:** both enroll endpoints return the same 401 for every failure; map it to the single `ErrEnrollUnauthorized` — never try to distinguish bad-code vs bad-password vs unknown-user.
- **ONE new module dependency** (`golang.org/x/term`); no others. Add it in the task that first imports it (Task 5), then `go mod tidy`.
- **Tests:** stdlib `testing`, table-driven where natural, run with `-race`. Per-task lint: run the whole-module `golangci-lint run` (not just `go vet`) — gosec/other findings surface at module scope.

## Test Harness Reference (real, in-tree idioms — use exactly)

| Package | Helper / idiom |
|---------|----------------|
| `internal/client/enroll` (`*_test.go`, package `enroll`) | White-box. Build a client with `NewClient(srv.URL, ClientOptions{})`; drive against `httptest.NewServer`. Decode request bodies server-side to assert wire tags. Sentinels checked with `errors.Is`. Existing tests in `client_test.go` follow this shape. |
| `cmd/diyddns-client` (package `main`) | Command built by `newEnrollCmd()`; drive via `cmd.SetArgs(...)`, `cmd.SetErr(...)`, `cmd.ExecuteContext(ctx)`. `credentials.json` written under `t.TempDir()` via `--credentials-file`. Env via `t.Setenv`. `deps_test.go` stays unchanged. |

## Task dependency order

```
T1 doEnroll + EnrollCode + sentinel ─► T2 EnrollCredentials + Meta ─┐
T3 resolvePassword seam ────────────────────────────────────────────┤
T4 finishEnroll orchestrator (refactor runOIDCEnroll) ─────────────────┼─► T5 mode dispatch + flags + x/term + e2e
```
Independent starts: **T1, T3, T4.** Order for TodoWrite seeding: T1, T2, T3, T4, T5.

---

### Task 1: `doEnroll` + `EnrollCode` + `ErrEnrollUnauthorized`

**Files:**
- Modify: `internal/client/enroll/errors.go` (add `ErrEnrollUnauthorized`)
- Modify: `internal/client/enroll/client.go` (add `doEnroll`, `EnrollCode`)
- Test: `internal/client/enroll/client_test.go` (add code-enroll tests)

**Interfaces:**
- Consumes: existing `Client`, `Result` (from `oidc.go`), `drainClose`, `ErrProtocol`, `ErrServer`.
- Produces:
  - `ErrEnrollUnauthorized error`
  - `func (c *Client) EnrollCode(ctx context.Context, code string) (Result, error)`
  - `func (c *Client) doEnroll(ctx context.Context, path string, payload []byte) (Result, error)` — shared 200/401/other response handler for both enroll endpoints.

- [ ] **Step 1: Write the failing test**

```go
// internal/client/enroll/client_test.go — add these tests. The file currently
// imports context, encoding/pem, errors, net/http, net/http/httptest, os,
// path/filepath, testing. These tests additionally need encoding/base64 and
// encoding/json — ADD both to the import block.

func TestClient_EnrollCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/enroll/code" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Code != "ABC-123" {
			t.Errorf("code = %q, want ABC-123", body.Code)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev-1",
			"secret":    base64.StdEncoding.EncodeToString([]byte("rawsecret")),
		})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, ClientOptions{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	res, err := c.EnrollCode(context.Background(), "ABC-123")
	if err != nil {
		t.Fatalf("EnrollCode: %v", err)
	}
	if res.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q, want dev-1", res.DeviceID)
	}
	if _, err := base64.StdEncoding.DecodeString(res.Secret); err != nil {
		t.Errorf("Secret is not valid base64: %v", err)
	}
}

func TestClient_EnrollCode_StatusMapping(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr error
	}{
		{"unauthorized", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, ErrEnrollUnauthorized},
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, ErrServer},
		{"bad base64 secret", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"device_id": "d", "secret": "!!!not-base64!!!"})
		}, ErrProtocol},
		{"empty body", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"device_id": "", "secret": ""})
		}, ErrProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			c, _ := NewClient(srv.URL, ClientOptions{})
			if _, err := c.EnrollCode(context.Background(), "x"); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/enroll/ -run TestClient_EnrollCode -v`
Expected: FAIL — `c.EnrollCode undefined` / `ErrEnrollUnauthorized undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/enroll/errors.go — add to the var block:

	// ErrEnrollUnauthorized: the server rejected a code or credential
	// enrollment (uniform 401 — never distinguishes an invalid/expired/used
	// code from an unknown email, wrong password, or disabled account).
	ErrEnrollUnauthorized = errors.New("enroll: invalid enrollment code or credentials")
```

```go
// internal/client/enroll/client.go — add these methods. bytes, encoding/base64,
// encoding/json, fmt, net/http are already imported by this file.

// EnrollCode enrolls this device with a one-time enrollment code
// (POST /agent/v1/enroll/code). On success it returns the new device id and
// its HMAC secret (wire base64, carried verbatim).
func (c *Client) EnrollCode(ctx context.Context, code string) (Result, error) {
	payload, err := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	if err != nil {
		return Result{}, fmt.Errorf("enroll: code marshal: %w", err)
	}
	return c.doEnroll(ctx, "/agent/v1/enroll/code", payload)
}

// doEnroll POSTs a JSON enrollment request and classifies the response. Both
// code and credential enrollment share this contract: 200 →
// {device_id, secret(base64)}; a uniform 401 → ErrEnrollUnauthorized; any
// other non-2xx → ErrServer.
func (c *Client) doEnroll(ctx context.Context, path string, payload []byte) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return Result{}, fmt.Errorf("enroll: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req) //nolint:bodyclose // resp.Body IS closed, inside drainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return Result{}, fmt.Errorf("enroll: post %s: %w", path, err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var b struct {
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return Result{}, fmt.Errorf("%w: enroll decode: %w", ErrProtocol, err)
		}
		if b.DeviceID == "" || b.Secret == "" {
			return Result{}, fmt.Errorf("%w: empty success body", ErrProtocol)
		}
		if _, err := base64.StdEncoding.DecodeString(b.Secret); err != nil {
			return Result{}, fmt.Errorf("%w: secret not base64", ErrProtocol)
		}
		return Result{DeviceID: b.DeviceID, Secret: b.Secret}, nil
	case http.StatusUnauthorized:
		return Result{}, ErrEnrollUnauthorized
	default:
		return Result{}, fmt.Errorf("%w: enroll status %d", ErrServer, resp.StatusCode)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/enroll/ -run TestClient_EnrollCode -race -v`
Expected: PASS. Then whole-module: `golangci-lint run`.

- [ ] **Step 5: Commit**

```bash
git add internal/client/enroll/errors.go internal/client/enroll/client.go internal/client/enroll/client_test.go
git commit -m "feat(enroll): add EnrollCode client method + shared doEnroll response handler"
```

---

### Task 2: `EnrollCredentials` + `Meta`

**Files:**
- Modify: `internal/client/enroll/client.go` (add `Meta`, `EnrollCredentials`)
- Test: `internal/client/enroll/client_test.go` (add credential-enroll tests)

**Interfaces:**
- Consumes: `doEnroll` (Task 1), `Result`, `ErrEnrollUnauthorized`.
- Produces:
  - `type Meta struct{ Hostname, OS, ClientVersion string }`
  - `func (c *Client) EnrollCredentials(ctx context.Context, email, password string, meta Meta) (Result, error)`

- [ ] **Step 1: Write the failing test**

```go
// internal/client/enroll/client_test.go

func TestClient_EnrollCredentials_SendsFieldsAndParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/enroll/credentials" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		// Decode with the SERVER's tag set (mirrors internal/server/api/enroll.go)
		// to guard the wire contract against drift.
		var body struct {
			Email         string `json:"email"`
			Password      string `json:"password"`
			Hostname      string `json:"hostname"`
			OS            string `json:"os"`
			ClientVersion string `json:"client_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Email != "me@example.com" || body.Password != "s3cret" {
			t.Errorf("email/password = %q/%q", body.Email, body.Password)
		}
		if body.Hostname != "box" || body.OS != "linux" || body.ClientVersion != "1.2.3" {
			t.Errorf("meta = %+v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev-9",
			"secret":    base64.StdEncoding.EncodeToString([]byte("k")),
		})
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, ClientOptions{})
	res, err := c.EnrollCredentials(context.Background(), "me@example.com", "s3cret",
		Meta{Hostname: "box", OS: "linux", ClientVersion: "1.2.3"})
	if err != nil {
		t.Fatalf("EnrollCredentials: %v", err)
	}
	if res.DeviceID != "dev-9" {
		t.Errorf("DeviceID = %q, want dev-9", res.DeviceID)
	}
}

func TestClient_EnrollCredentials_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, ClientOptions{})
	_, err := c.EnrollCredentials(context.Background(), "me@example.com", "wrong", Meta{})
	if !errors.Is(err, ErrEnrollUnauthorized) {
		t.Errorf("err = %v, want ErrEnrollUnauthorized", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/enroll/ -run TestClient_EnrollCredentials -v`
Expected: FAIL — `Meta` / `c.EnrollCredentials` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/enroll/client.go

// Meta is optional device metadata sent with credential enrollment so the
// device row is populated before its first check-in. Empty fields are omitted.
type Meta struct{ Hostname, OS, ClientVersion string }

// EnrollCredentials enrolls this device with a user's email + password
// (POST /agent/v1/enroll/credentials), sending optional device metadata. On
// success it returns the new device id and its HMAC secret (wire base64).
func (c *Client) EnrollCredentials(ctx context.Context, email, password string, meta Meta) (Result, error) {
	payload, err := json.Marshal(struct {
		Email         string `json:"email"`
		Password      string `json:"password"`
		Hostname      string `json:"hostname,omitempty"`
		OS            string `json:"os,omitempty"`
		ClientVersion string `json:"client_version,omitempty"`
	}{
		Email:         email,
		Password:      password,
		Hostname:      meta.Hostname,
		OS:            meta.OS,
		ClientVersion: meta.ClientVersion,
	})
	if err != nil {
		return Result{}, fmt.Errorf("enroll: credentials marshal: %w", err)
	}
	return c.doEnroll(ctx, "/agent/v1/enroll/credentials", payload)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/enroll/ -race -v`
Expected: PASS (all enroll tests). Then whole-module `golangci-lint run`.

- [ ] **Step 5: Commit**

```bash
git add internal/client/enroll/client.go internal/client/enroll/client_test.go
git commit -m "feat(enroll): add EnrollCredentials client method with device metadata"
```

---

### Task 3: `resolvePassword` seam

**Files:**
- Create: `cmd/diyddns-client/password.go`
- Test: `cmd/diyddns-client/password_test.go`

**Interfaces:**
- Consumes: stdlib only (`bufio`, `errors`, `fmt`, `io`, `strings`).
- Produces:
  - `func resolvePassword(env string, stdin io.Reader, stderr io.Writer, isTTY func() bool, readHidden func() (string, error)) (string, error)` — env → piped stdin → hidden TTY prompt; empty result is an error. Never echoes.

- [ ] **Step 1: Write the failing test**

```go
// cmd/diyddns-client/password_test.go
package main

import (
	"errors"
	"strings"
	"testing"
)

func TestResolvePassword(t *testing.T) {
	neverTTY := func() bool { return false }
	yesTTY := func() bool { return true }
	failHidden := func() (string, error) { return "", errors.New("no terminal") }

	tests := []struct {
		name       string
		env        string
		stdin      string
		isTTY      func() bool
		readHidden func() (string, error)
		want       string
		wantErr    bool
	}{
		{"env wins", "envpw", "ignored\n", yesTTY, func() (string, error) { return "hiddenpw", nil }, "envpw", false},
		{"piped stdin when not a tty", "", "pipedpw\n", neverTTY, failHidden, "pipedpw", false},
		{"piped strips CRLF", "", "pw\r\n", neverTTY, failHidden, "pw", false},
		{"hidden prompt on a tty", "", "", yesTTY, func() (string, error) { return "hiddenpw", nil }, "hiddenpw", false},
		{"empty resolved password errors", "", "\n", neverTTY, failHidden, "", true},
		{"hidden read error propagates", "", "", yesTTY, failHidden, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePassword(tt.env, strings.NewReader(tt.stdin), &strings.Builder{}, tt.isTTY, tt.readHidden)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (got %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePassword: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
```

> `stderr` is `*strings.Builder` here only to satisfy the `io.Writer` seam — the test does not assert on prompt text (and MUST never see the password, which `resolvePassword` never writes to `stderr`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run TestResolvePassword -v`
Expected: FAIL — `resolvePassword` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// cmd/diyddns-client/password.go
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// resolvePassword acquires the enrollment password without ever echoing it:
// the DIYDDNS_ENROLL_PASSWORD value (via env) first for automation, else a
// single piped stdin line when stdin is not a terminal, else a hidden no-echo
// terminal prompt. Every external effect (TTY test, hidden read) is injected so
// all branches are testable without a real terminal. An empty resolved password
// is an error. The password is never written to stderr or into an error string.
func resolvePassword(env string, stdin io.Reader, stderr io.Writer, isTTY func() bool, readHidden func() (string, error)) (string, error) {
	if env != "" {
		return env, nil
	}
	var pw string
	if isTTY() {
		_, _ = fmt.Fprint(stderr, "Password: ")
		p, err := readHidden()
		_, _ = fmt.Fprintln(stderr) // terminate the prompt line
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw = p
	} else {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if pw == "" {
		return "", errors.New("password required (set DIYDDNS_ENROLL_PASSWORD, pipe it on stdin, or type it at the prompt)")
	}
	return pw, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/diyddns-client/ -run TestResolvePassword -race -v`
Expected: PASS. Then whole-module `golangci-lint run`.

- [ ] **Step 5: Commit**

```bash
git add cmd/diyddns-client/password.go cmd/diyddns-client/password_test.go
git commit -m "feat(client): add resolvePassword seam (env / piped stdin / hidden prompt)"
```

---

### Task 4: `finishEnroll` orchestrator (refactor `runOIDCEnroll`)

**Files:**
- Modify: `cmd/diyddns-client/enroll.go` (extract `finishEnroll`; rewrite `runOIDCEnroll` to call it)
- Modify (APPEND): `cmd/diyddns-client/enroll_test.go`

> **This test file ALREADY EXISTS** (created in Plan 06, ~125 lines). It contains
> 5 OIDC tests (`TestEnrollOIDCEndToEnd`, `TestEnrollTrimsTrailingSlashInServerURL`,
> `TestEnrollRefusesExistingCredentials`, `TestEnrollDeviceDisabledCapability`,
> `TestEnrollRequiresOIDCFlag`), a command-driver **test helper**
> `func runEnroll(t *testing.T, args ...string) error`, and a `type nopWriter
> struct{}` (an `io.Writer` sink). **APPEND** the new tests; do NOT overwrite or
> remove any of these. The production orchestrator is named `finishEnroll`
> precisely so it does not collide with the existing `runEnroll` test helper.
> Reuse the existing `nopWriter` for the `io.Writer` seam (do not add a
> duplicate sink type).

**Interfaces:**
- Consumes: existing `enrollParams`, `credentials.{DefaultPath,Load,Save,ErrNotFound}`, `enroll.{NewClient,ClientOptions,Result}`; existing test helper `nopWriter`.
- Produces:
  - `func finishEnroll(ctx context.Context, p enrollParams, do func(context.Context, *enroll.Client) (enroll.Result, error)) error` — resolves cred path; **refuses to overwrite existing credentials before any server contact** unless `--force`; normalizes+requires the server URL; builds the client; runs `do`; saves credentials; prints a success line. `runOIDCEnroll` becomes a thin caller.

> **Refactor note (behavior-preserving):** the guard-before-contact, server
> normalization, and `Save` logic currently inline in `runOIDCEnroll`
> (enroll.go) move verbatim into `finishEnroll`. The OIDC-specific capabilities
> check + device-code flow become the `do` closure. Because the guard runs
> *before* `do`, callers may safely resolve a password *inside* `do` (Task 5)
> without prompting on a re-enroll that the guard will reject.

- [ ] **Step 1: Write the failing test**

Append these to the existing `cmd/diyddns-client/enroll_test.go` (its imports
already include `context`, `path/filepath`, `testing`, and the `credentials`
and `enroll` packages — the OIDC tests use them; add none). Reuse the existing
`nopWriter` sink; do **not** add a duplicate writer type.

```go
func TestFinishEnroll_GuardsBeforeContact(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	// Pre-existing credentials.
	if err := credentials.Save(credPath, credentials.Credentials{
		ServerURL: "https://old", DeviceID: "old", Secret: "old",
	}, false); err != nil {
		t.Fatal(err)
	}

	called := false
	p := enrollParams{out: &nopWriter{}, server: "https://x", credFile: credPath, force: false}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		called = true
		return enroll.Result{}, nil
	})
	if err == nil {
		t.Fatal("want error when credentials already exist and --force is not set")
	}
	if called {
		t.Error("do() was called — guard must refuse BEFORE contacting the server")
	}
}

func TestFinishEnroll_RequiresServer(t *testing.T) {
	dir := t.TempDir()
	p := enrollParams{out: &nopWriter{}, server: "", credFile: filepath.Join(dir, "credentials.json")}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		return enroll.Result{}, nil
	})
	if err == nil {
		t.Fatal("want error when server URL is empty")
	}
}

func TestFinishEnroll_SavesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	p := enrollParams{out: &nopWriter{}, server: "https://srv/", credFile: credPath}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		return enroll.Result{DeviceID: "dev-1", Secret: "c2VjcmV0"}, nil
	})
	if err != nil {
		t.Fatalf("finishEnroll: %v", err)
	}
	got, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DeviceID != "dev-1" || got.Secret != "c2VjcmV0" {
		t.Errorf("saved creds = %+v", got)
	}
	if got.ServerURL != "https://srv" { // trailing slash normalized off
		t.Errorf("ServerURL = %q, want https://srv", got.ServerURL)
	}
}
```

> `nopWriter` is the existing sink type in `enroll_test.go`; `&nopWriter{}`
> satisfies the `io.Writer` seam regardless of its receiver style.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run TestFinishEnroll -v`
Expected: FAIL — `finishEnroll` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// cmd/diyddns-client/enroll.go — add finishEnroll and rewrite runOIDCEnroll.
// (context, errors, fmt, strings, credentials, enroll are already imported.)

// finishEnroll is the shared orchestration for every enroll mode. It resolves the
// credentials path and refuses to overwrite existing credentials BEFORE any
// server contact (so a re-enroll without --force spends nothing), normalizes
// and requires the server URL, builds the enroll client, runs the mode-specific
// operation, and persists the resulting credentials.
func finishEnroll(ctx context.Context, p enrollParams, do func(context.Context, *enroll.Client) (enroll.Result, error)) error {
	credPath := p.credFile
	if credPath == "" {
		dp, err := credentials.DefaultPath()
		if err != nil {
			return err
		}
		credPath = dp
	}

	// Guard existing credentials BEFORE contacting the server, so a re-enroll
	// without --force never spends a code/login and never prompts for input.
	if !p.force {
		switch _, err := credentials.Load(credPath); {
		case err == nil:
			return fmt.Errorf("credentials already exist at %s (use --force to overwrite)", credPath)
		case !errors.Is(err, credentials.ErrNotFound):
			return err
		}
	}

	// Normalize once so the persisted ServerURL matches the URL requests use.
	p.server = strings.TrimRight(p.server, "/")
	if p.server == "" {
		return fmt.Errorf("server URL is required (--server or config server.url)")
	}
	c, err := enroll.NewClient(p.server, enroll.ClientOptions{CACertPath: p.caCert})
	if err != nil {
		return err
	}
	res, err := do(ctx, c)
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
	_, _ = fmt.Fprintf(p.out, "Device %s enrolled. Credentials written to %s\n", res.DeviceID, credPath)
	return nil
}

// runOIDCEnroll runs the OIDC device-code flow through the shared orchestrator.
func runOIDCEnroll(ctx context.Context, p enrollParams) error {
	return finishEnroll(ctx, p, func(ctx context.Context, c *enroll.Client) (enroll.Result, error) {
		caps, err := c.Capabilities(ctx)
		if err != nil {
			return enroll.Result{}, fmt.Errorf("contacting server: %w", err)
		}
		if !caps.OIDCDeviceEnabled {
			return enroll.Result{}, fmt.Errorf("server does not support OIDC device enrollment")
		}
		return enroll.DeviceCodeEnroll(ctx, c, stderrPrompter{w: p.out}, enroll.NewSystemClock())
	})
}
```

> Delete the now-duplicated body of the old `runOIDCEnroll` (the inline
> credPath/guard/normalize/NewClient/Capabilities/Save sequence) — it is fully
> replaced by the closure above. `stderrPrompter` and `enrollParams` are
> unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/diyddns-client/ -run TestFinishEnroll -race -v`
Expected: PASS. Also run the full client package to confirm the OIDC refactor didn't regress: `go test ./cmd/diyddns-client/ -race`. Then whole-module `golangci-lint run`.

- [ ] **Step 5: Commit**

```bash
git add cmd/diyddns-client/enroll.go cmd/diyddns-client/enroll_test.go
git commit -m "refactor(client): extract shared finishEnroll orchestrator from runOIDCEnroll"
```

---

### Task 5: mode dispatch + `--code`/`--user` flags + `x/term` wiring

**Files:**
- Modify: `cmd/diyddns-client/enroll.go` (add `--code`/`--user` flags, mode dispatch, x/term password wiring, metadata)
- Modify: `go.mod` / `go.sum` (add `golang.org/x/term`)
- Test: `cmd/diyddns-client/enroll_test.go` (add end-to-end `--code` / `--user` + mode-selection tests)

**Interfaces:**
- Consumes: `finishEnroll` (Task 4), `enroll.{EnrollCode,EnrollCredentials,Meta}` (Tasks 1-2), `resolvePassword` (Task 3), `config.LoadClient`, `version.Current`.
- Produces: `newEnrollCmd()` gains `--code`/`--user` modes with declarative mutual-exclusion; no exported signature change.

- [ ] **Step 1: Write the failing test**

```go
// APPEND to the existing cmd/diyddns-client/enroll_test.go. Ensure these
// imports are present (the OIDC tests may already import some — net/http,
// net/http/httptest): "encoding/base64", "encoding/json", "net/http",
// "net/http/httptest", "os". Reuse the existing nopWriter sink.

func TestEnrollCmd_Code_EndToEnd(t *testing.T) {
	var gotCode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotCode = body.Code
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev-code", "secret": base64.StdEncoding.EncodeToString([]byte("k")),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	cmd := newEnrollCmd()
	cmd.SetArgs([]string{"--code", "ABC-123", "--server", srv.URL, "--credentials-file", credPath})
	cmd.SetErr(&nopWriter{})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("enroll --code: %v", err)
	}
	if gotCode != "ABC-123" {
		t.Errorf("server saw code %q, want ABC-123", gotCode)
	}
	creds, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if creds.DeviceID != "dev-code" {
		t.Errorf("DeviceID = %q, want dev-code", creds.DeviceID)
	}
}

func TestEnrollCmd_User_EndToEnd_EnvPassword(t *testing.T) {
	t.Setenv("DIYDDNS_ENROLL_PASSWORD", "s3cret")
	var gotEmail, gotPassword, gotOS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			OS       string `json:"os"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotEmail, gotPassword, gotOS = body.Email, body.Password, body.OS
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev-user", "secret": base64.StdEncoding.EncodeToString([]byte("k")),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	cmd := newEnrollCmd()
	cmd.SetArgs([]string{"--user", "me@example.com", "--server", srv.URL, "--credentials-file", credPath})
	cmd.SetErr(&nopWriter{})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("enroll --user: %v", err)
	}
	if gotEmail != "me@example.com" || gotPassword != "s3cret" {
		t.Errorf("server saw %q/%q", gotEmail, gotPassword)
	}
	if gotOS == "" {
		t.Error("expected OS metadata to be sent (runtime.GOOS)")
	}
	if _, err := credentials.Load(credPath); err != nil {
		t.Errorf("credentials not written: %v", err)
	}
}

func TestEnrollCmd_ModeSelection(t *testing.T) {
	t.Run("mutually exclusive", func(t *testing.T) {
		cmd := newEnrollCmd()
		cmd.SetArgs([]string{"--code", "x", "--user", "me@example.com", "--server", "https://x"})
		cmd.SetErr(&nopWriter{})
		if err := cmd.ExecuteContext(context.Background()); err == nil {
			t.Fatal("want error when two modes are set")
		}
	})
	t.Run("one required", func(t *testing.T) {
		cmd := newEnrollCmd()
		cmd.SetArgs([]string{"--server", "https://x"})
		cmd.SetErr(&nopWriter{})
		if err := cmd.ExecuteContext(context.Background()); err == nil {
			t.Fatal("want error when no mode is set")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run TestEnrollCmd -v`
Expected: FAIL — `--code`/`--user` unknown flags / dispatch not implemented.

- [ ] **Step 3: Add the dependency**

```bash
go get golang.org/x/term@latest
```
Expected: `go.mod` gains `golang.org/x/term` (and `go.sum` its checksums); `golang.org/x/sys` stays as-is (already present).

- [ ] **Step 4: Write minimal implementation**

```go
// cmd/diyddns-client/enroll.go
//
// 1) Add imports: "os", "runtime", "golang.org/x/term",
//    "github.com/jacaudi/diyddns/internal/version".
// 2) Add mode-flag vars and flags; declare mutual-exclusion + one-required.
// 3) Replace the RunE body's "only --oidc" stub with mode dispatch.

// --- vars (add alongside the existing useOIDC/serverFlag/... block) ---
	var (
		code  string
		email string
	)

// --- flags (add alongside the existing cmd.Flags() calls) ---
	cmd.Flags().StringVar(&code, "code", "", "enroll with a one-time enrollment code")
	cmd.Flags().StringVar(&email, "user", "", "enroll with a user email + password (password via prompt, stdin, or DIYDDNS_ENROLL_PASSWORD)")
	cmd.MarkFlagsMutuallyExclusive("oidc", "code", "user")
	cmd.MarkFlagsOneRequired("oidc", "code", "user")

// --- RunE body (replace the whole existing func body) ---
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			p := enrollParams{
				out:      cmd.ErrOrStderr(),
				server:   cfg.Server.URL,
				caCert:   cfg.Server.CABundle,
				force:    force,
				credFile: credFile,
			}
			switch {
			case useOIDC:
				return runOIDCEnroll(cmd.Context(), p)
			case code != "":
				return finishEnroll(cmd.Context(), p, func(ctx context.Context, c *enroll.Client) (enroll.Result, error) {
					return c.EnrollCode(ctx, code)
				})
			case email != "":
				return finishEnroll(cmd.Context(), p, func(ctx context.Context, c *enroll.Client) (enroll.Result, error) {
					// Resolve the password INSIDE the op so the credential guard
					// (which runs before this) can refuse a re-enroll without ever
					// prompting. Never echoed; never logged.
					fd := int(os.Stdin.Fd())
					password, err := resolvePassword(
						os.Getenv("DIYDDNS_ENROLL_PASSWORD"),
						os.Stdin,
						p.out,
						func() bool { return term.IsTerminal(fd) },
						func() (string, error) { b, err := term.ReadPassword(fd); return string(b), err },
					)
					if err != nil {
						return enroll.Result{}, err
					}
					host, _ := os.Hostname()
					meta := enroll.Meta{Hostname: host, OS: runtime.GOOS, ClientVersion: version.Current().Version}
					return c.EnrollCredentials(ctx, email, password, meta)
				})
			default:
				// Unreachable in normal use (MarkFlagsOneRequired enforces a mode);
				// defensive for the degenerate --oidc=false case.
				return fmt.Errorf("choose an enrollment mode: --oidc, --code, or --user")
			}
		},
```

> Remove the old `if !useOIDC { return fmt.Errorf("only --oidc ...") }` guard
> and the old inline OIDC body — they are replaced by the switch. Keep the
> existing shared flags (`--server`, `--ca-cert`, `--force`,
> `--credentials-file`, `--config`) and `enrollParams`/`stderrPrompter`.
>
> **Existing test note:** `TestEnrollRequiresOIDCFlag` (Plan 06) still passes —
> `enroll --server …` with no mode now errors via `MarkFlagsOneRequired` instead
> of the old `if !useOIDC` guard. Keep the test (it still asserts a no-mode
> error); optionally rename it to reflect "a mode is required" rather than
> "--oidc required". Do not delete it.

- [ ] **Step 5: Run tests + deps guard**

Run: `go test ./cmd/diyddns-client/ -race -v`
Expected: PASS — including the unchanged `deps_test.go`.
Run the client dependency guard:
```bash
go list -deps ./cmd/diyddns-client | grep -E 'huma|oauth2|go-oidc|go-jose'   # must be EMPTY
git diff --stat cmd/diyddns-client/deps_test.go                              # must be EMPTY (unchanged)
```
Then the full module: `go build ./...`, `go vet ./...`, `gofmt -l .` (no output), `golangci-lint run` (0 issues), `go test ./... -race`.

- [ ] **Step 6: Commit**

```bash
git add cmd/diyddns-client/enroll.go go.mod go.sum cmd/diyddns-client/enroll_test.go
git commit -m "feat(client): add enroll --code and --user modes with secure password input"
```

---

## Final verification (after all tasks)

- [ ] `go build ./...` — clean.
- [ ] `go vet ./...` — clean.
- [ ] `gofmt -l .` — no output.
- [ ] `golangci-lint run` — 0 issues (whole module).
- [ ] `go test ./... -race` — all pass.
- [ ] Client deps guard: `go list -deps ./cmd/diyddns-client | grep -E 'huma|oauth2|go-oidc|go-jose'` → empty; `cmd/diyddns-client/deps_test.go` unchanged and green.
- [ ] One new *direct* module dependency — `golang.org/x/term` — in `git diff origin/main -- go.mod`. (Adding it may also promote the already-vendored `golang.org/x/sys` from `// indirect` to a direct require, or bump its version; that is benign. The real gate is the forbidden-dep grep above being empty and no huma/oauth2/go-oidc/go-jose appearing.)
- [ ] Manual smoke (optional): `printf 'pw\n' | diyddns-client enroll --user me@example.com --server <url>` and `diyddns-client enroll --code <code> --server <url>` each write `credentials.json`; the password never appears in `ps`/history.

## Self-review — spec coverage map

| Design element | Task |
|----------------|------|
| D1 both modes (`--code` + `--user`) | T1/T2 (client) + T5 (command) |
| D2 secure password (env/stdin/hidden, no `--password`) | T3 (`resolvePassword`) + T5 (x/term wiring) |
| D3 `--user` auto-metadata; `--code` none | T5 (`enroll.Meta` from host/GOOS/version) |
| D4 extend, no new package | T1/T2 (methods on existing `Client`) |
| D5 declarative mutual-exclusion + one-required | T5 (`MarkFlagsMutuallyExclusive`+`MarkFlagsOneRequired`) |
| D6 `ErrEnrollUnauthorized` for uniform 401 | T1 (sentinel + `doEnroll` mapping) |
| D7 shared `finishEnroll`/orchestrator (guard-before-contact + save) | T4 (`finishEnroll`, refactor `runOIDCEnroll`) |
| D8 no capabilities pre-check for code/creds | T1/T2 (`doEnroll` just POSTs) |
| Reuse existing `enroll.Result` | T1 (only `Meta` added) |
| One new dep `golang.org/x/term`; `deps_test.go` unchanged | T5 |

## Review provenance

- Author self-review (spec-coverage map above; type-consistency scan: `Result` reused not redeclared; `doEnroll`/`finishEnroll`/`resolvePassword`/`Meta` signatures consistent across tasks; password resolved inside the `--user` op so the guard precedes the prompt).
- Design SGE (`sr-go-engineer`, Fable) review folded (AMEND-BEFORE-PLANNING: reuse `enroll.Result`; declarative flag groups; fd-bound password closures; `--server` required; huma 400/422 bucketing note).
- Implementation-plan SGE (`sr-go-engineer`, Fable) review — **AMEND-BEFORE-EXECUTION**, all findings folded. (Important, F1) the production orchestrator was renamed `runEnroll` → **`finishEnroll`** because `cmd/diyddns-client/enroll_test.go` already exists with a `runEnroll(t, args...)` *test helper* (a redeclaration collision in package `main`); the test file's task verb changed create → **modify/append** so the 5 existing Plan-06 OIDC tests + the `runEnroll` helper + `nopWriter` are preserved, not overwritten. (Minor) reuse the existing `nopWriter` sink (dropped the duplicate `discardWriter`); corrected the T1 `client_test.go` import claim (base64/json must be added); noted `TestEnrollRequiresOIDCFlag` is retained (now passes via `MarkFlagsOneRequired`); loosened the go.mod verification so a benign `x/sys` indirect→direct promotion doesn't read as a violation. The reviewer ground-truthed every task's code against the real APIs (client methods, wire tags, cobra 1.10.2 flag-group helpers, `credentials`/`version` signatures, `x/term` footprint) — all confirmed to compile/pass as written once F1 is applied.

## Execution handoff

Recommended: `superpowers:subagent-driven-development` — fresh `sr-go-engineer` per task (TDD), per-task review, then an independent whole-branch review before finishing. Seed TodoWrite one item per task in dependency order (T1→T5); independent starts T1, T3, T4. Execute in a worktree off the merged `origin/main`.
