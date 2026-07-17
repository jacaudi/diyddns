# Plan 08 — `diyddns-client enroll --code` / `--user` — Design

**Status:** Design (user-approved section-by-section; SGE review pending).

**Goal:** Add the two remaining device-enrollment modes to the client CLI —
`enroll --code <code>` (enrollment code) and `enroll --user <email>`
(email + password) — completing the code-based enroll path named in the v1
acceptance criteria (§14 criterion #2) and finishing the client half of
issue #26. Both server endpoints already exist (Plan 04); this is a small,
additive client vertical.

## 1. Context — what exists, what's missing

The `enroll` cobra command exists but implements **only** `--oidc` (Plan 06):
its `RunE` short-circuits with `"only --oidc enrollment is supported in this
version"` for any other mode. The unauthenticated enroll HTTP driver
`internal/client/enroll.Client` currently exposes `Capabilities`,
`OIDCDeviceStart`, and `OIDCDevicePoll`; the `credentials` package writes
`credentials.json` (atomic, 0600, refuse-overwrite unless `--force`).

The **server side is already built** (Plan 04, on `main`), both
unauthenticated on the `/agent/v1` surface:

- `POST /agent/v1/enroll/code` — body `{code}` → `200 {device_id, secret}`
  (secret base64) or a **uniform `401 "invalid enrollment code or
  credentials"`** on any failure.
- `POST /agent/v1/enroll/credentials` — body
  `{email, password, hostname?, os?, client_version?}` →
  `200 {device_id, secret}` or the same uniform 401.

The uniform 401 is deliberate (server design §8): a client can never
distinguish an invalid/expired/used code from an unknown email, disabled
account, or wrong password.

Missing: the client methods to call these two endpoints, and the command-layer
wiring (mode dispatch + secure password input) to drive them.

## 2. Decisions

- **D1 — Deliver both modes.** `--code` and `--user`/password. Both server
  endpoints already exist, so both are cheap; this fully completes the client
  enroll story rather than deferring `--user` again.
- **D2 — Secure password input via `golang.org/x/term`, with non-interactive
  fallback, no `--password` flag.** Resolution order (first match wins):
  (1) `DIYDDNS_ENROLL_PASSWORD` env; (2) stdin-not-a-TTY → read one piped line;
  (3) stdin-is-a-TTY → hidden no-echo prompt via `term.ReadPassword`. No
  `--password` flag (avoids leaking the password into `ps` / shell history).
  The password is never logged, echoed, or placed in an error string; an empty
  resolved password is an error.
- **D3 — `--user` auto-sends device metadata; `--code` does not.** Only the
  `/enroll/credentials` endpoint accepts `hostname/os/client_version`; `--user`
  populates them (`os.Hostname()`, `runtime.GOOS`, `version.Current().Version`)
  so the device row is meaningful before its first check-in. The `/enroll/code`
  body is just `{code}`.
- **D4 — Extend, don't add packages.** Two methods on the existing
  `enroll.Client` + mode dispatch in the existing `enroll.go` command. No new
  package (that would fragment the enroll client Plan 06 kept as one unit).
- **D5 — Three mutually-exclusive modes.** Exactly one of
  `--oidc` / `--code` / `--user` is required (cobra
  `MarkFlagsMutuallyExclusive` + an explicit "choose one mode" error when none
  is given). All shared flags (`--server`, `--ca-cert`, `--force`,
  `--credentials-file`, `--config`) are reused unchanged across modes.
- **D6 — One new sentinel, `ErrEnrollUnauthorized`, for the uniform 401.**
  Other sentinels (`ErrServer`, `ErrProtocol`) are reused. The command maps
  `ErrEnrollUnauthorized` to a friendly non-zero-exit message.
- **D7 — Extract a shared `finishEnroll` helper.** Normalize `--server`, guard
  existing credentials **before contacting the server** (so a re-enroll without
  `--force` never spends a code or a login), then `credentials.Save`. This
  logic is identical across all three modes (a real three-caller DRY, not a
  speculative abstraction); `runOIDCEnroll` is refactored to call it too.
- **D8 — No capabilities pre-check for `--code`/`--user`.** Unlike OIDC (gated
  on `oidc_device_enabled`), the code/credentials endpoints are core and always
  available; the client just POSTs and maps the response.

## 3. Architecture

### 3.1 Command shape

```
diyddns-client enroll --oidc          --server <url>   (existing)
diyddns-client enroll --code <code>   --server <url>   (new)
diyddns-client enroll --user <email>  --server <url>   (new)
```

`RunE` selects the mode (exactly one required), loads client config (reusing
the existing viper `--server`/`--ca-cert` binding), then dispatches:

- `--code`  → `client.EnrollCode(ctx, code)`
- `--user`  → resolve password (D2) → `client.EnrollCredentials(ctx, email, password, meta)`
- `--oidc`  → existing device-code flow

All three end in the shared `finishEnroll` path (D7).

### 3.2 Client methods (`internal/client/enroll`)

Mirroring the existing OIDC methods' shape (build request via
`json.Marshal`→`bytes.NewReader`, POST, `switch` on status, `drainClose`):

```go
type Result struct{ DeviceID, Secret string } // Secret is wire base64, verbatim
type Meta struct{ Hostname, OS, ClientVersion string }

func (c *Client) EnrollCode(ctx context.Context, code string) (Result, error)
func (c *Client) EnrollCredentials(ctx context.Context, email, password string, meta Meta) (Result, error)
```

New sentinel (rest reused):

```go
ErrEnrollUnauthorized = errors.New("enroll: invalid enrollment code or credentials")
```

Status mapping (both methods):

| Status | Result |
|--------|--------|
| 200 + valid body | `Result{DeviceID, Secret}` (Secret validated base64-decodable, else `ErrProtocol`) |
| 200 empty/undecodable | `ErrProtocol` |
| 401 | `ErrEnrollUnauthorized` (uniform — never distinguishes failure mode) |
| other non-2xx | `ErrServer` (wrapped with status) |
| transport error | wrapped `%w` |

### 3.3 Password-input seam (`cmd/diyddns-client`)

Password acquisition is behind an injectable pure function so all branches are
unit-testable without a real terminal (mirrors Plan 06's `Clock`/`Prompter`
seams):

```go
func resolvePassword(env string, stdin io.Reader, stderr io.Writer,
                     isTTY func() bool, readHidden func() (string, error)) (string, error)
```

Production wiring: `env = os.Getenv("DIYDDNS_ENROLL_PASSWORD")`,
`stdin = os.Stdin`, `isTTY = term.IsTerminal(fd)`,
`readHidden = term.ReadPassword(fd)`. `x/term` supplies both TTY detection and
the no-echo read, so it is the only new dependency; its lone transitive dep
`x/sys` is already vendored.

### 3.4 Error handling

The command maps sentinels to distinct operator messages with non-zero exit:
`ErrEnrollUnauthorized` → "invalid enrollment code or credentials";
`ErrServer` → "server error"; transport errors surface wrapped. Never prints
the password or the device secret.

## 4. File-change map

| File | Change |
|------|--------|
| `internal/client/enroll/client.go` | + `EnrollCode`, `EnrollCredentials`, `Result`, `Meta` |
| `internal/client/enroll/errors.go` | + `ErrEnrollUnauthorized` |
| `internal/client/enroll/client_test.go` | + method tests |
| `cmd/diyddns-client/enroll.go` | mode dispatch; `resolvePassword`; auto metadata; mutual-exclusivity; extract shared `finishEnroll` (refactor `runOIDCEnroll` onto it) |
| `cmd/diyddns-client/enroll_test.go` | + command & `resolvePassword` tests |
| `go.mod` / `go.sum` | + `golang.org/x/term` |
| `cmd/diyddns-client/deps_test.go` | **unchanged** (x/term is allowed; verify green) |

## 5. Testing

All stdlib `testing`, table-driven, `-race`, TDD.

- **`internal/client/enroll/client_test.go`** — httptest server for both
  methods: success (secret base64 verbatim); uniform **401 →
  `ErrEnrollUnauthorized`**; malformed/empty 200 and bad-base64 secret →
  `ErrProtocol`; other non-2xx → `ErrServer`. Assert the **request bodies**:
  `/enroll/code` sends exactly `{code}`; `/enroll/credentials` sends
  `{email,password,hostname,os,client_version}` (decode server-side to guard
  wire-tag drift).
- **`cmd/diyddns-client/enroll_test.go`** — mode dispatch (exactly-one-mode
  enforced); end-to-end `--code` and `--user` against httptest (guard-before-
  contact honored, `credentials.json` written, `--force` overwrite);
  `resolvePassword` covering env / piped-stdin / TTY-hidden-fake / empty→error.
- **`cmd/diyddns-client/deps_test.go`** — unchanged and green.

## 6. Constraints & non-goals

**Constraints:** client stays free of `huma`/`oauth2`/`go-oidc`/`go-jose`
(`deps_test.go` unchanged); never log/echo the password or device secret;
errors wrapped `%w`; Go 1.25 no-CGO; `golangci-lint run` clean (whole module)
per task. The one new module dependency is `golang.org/x/term`.

**Non-goals:** `status`/`rotate` client verticals (separate future work); any
change to the server enroll endpoints (they already exist and are unchanged);
`/agent/v1` wire-DTO consolidation (#27).

## 7. Acceptance criteria

- `diyddns-client enroll --code <code> --server <url>` writes a working
  `credentials.json`; a subsequent `run --once` posts a check-in (satisfies §14
  criterion #2's code-enroll path end to end).
- `diyddns-client enroll --user <email> --server <url>` reads the password
  securely (hidden prompt on a TTY; env/stdin non-interactively), enrolls, and
  writes credentials; the created device carries hostname/os/client_version.
- A wrong code, wrong password, unknown email, or disabled account all surface
  the same uniform "invalid enrollment code or credentials" message.
- Exactly one of `--oidc`/`--code`/`--user` is accepted; none → a clear error.
- Re-enroll without `--force` refuses **before** contacting the server; the
  password is never logged, echoed, or shown in `ps`.
- `go build`/`go vet`/`gofmt` clean; `golangci-lint run` 0 issues;
  `go test ./... -race` passes; client deps guard empty and `deps_test.go`
  unchanged; the only new module dep is `golang.org/x/term`.

## 8. Review provenance

- Author brainstorm with the user (section-by-section approval): approach &
  command shape (D4/D5); client methods, sentinel & error mapping (D6);
  password-input seam (D2); testing & file map. Decisions D1 (both modes) and
  D2 (secure hidden prompt via x/term, no `--password` flag) were explicit user
  choices via popups.
- SGE (`sr-go-engineer`, Fable) design review — pending.
