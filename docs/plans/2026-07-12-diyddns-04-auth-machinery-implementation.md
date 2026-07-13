# DIYDDNS Plan 04 — Auth Machinery & Agent Device-Auth Vertical — Implementation Plan

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

**Goal:** Add the authentication layer (device→server HMAC, browser cookie-sessions + CSRF, argon2id passwords, bootstrap admin) plus the agent device-auth vertical (enroll → checkin → self), attaching additively to the Plan 03 huma skeleton.

**Architecture:** New packages `internal/shared` (HMAC wire contract, stdlib-only), `internal/auth` (Verifier + secret cache, sessions/CSRF, argon2id, AES-GCM secret sealing), and `internal/server/service` (enrollment/device/checkin/auth/bootstrap). Auth checks are **huma per-operation middleware** attached to exactly the ops that need them; the device HMAC secret is stored **AES-256-GCM-encrypted** in the existing `secret_hash` column (no schema change). Everything wires through an extended `api.Build(mux, ServerDeps)`.

**Tech Stack:** Go 1.25.7 (no CGO), huma v2.38.0, cobra v1.10.2, viper v1.21.0, `golang.org/x/crypto/argon2` (new), stdlib `crypto/aes`+`crypto/cipher`+`crypto/hmac`+`crypto/subtle`, `modernc.org/sqlite` store (Plan 02).

**Parent design:** [docs/designs/2026-07-12-diyddns-04-auth-machinery-design.md](../designs/2026-07-12-diyddns-04-auth-machinery-design.md) — SGE-reviewed. Read it before starting; it holds the rationale for every decision (esp. D1 AEAD, the bootstrap atomic-gate, the login timing-equalization).

---

## Global Constraints

Every task's requirements implicitly include these. Exact values, verbatim:

- **Go 1.25.7, CGO disabled.** Pure-Go only.
- **Deps pinned:** huma `v2.38.0`, cobra `v1.10.2`, viper `v1.21.0`. **New direct dep:** `golang.org/x/crypto` (for `argon2`). Add it in the first task that imports it (Task 2) — `go mod tidy` prunes an unimported dep, so only add when code imports it.
- **huma stays server-only.** No `internal/shared`, `internal/auth`, or `internal/server/*` code may be imported by `cmd/diyddns-client`. `internal/shared` must be **stdlib-only** (the future client will import it). The existing import-graph test (`cmd/diyddns-client/deps_test.go`) must stay green.
- **Errors wrapped with `%w`** (`errorlint` enforced). Sentinel errors from `internal/store`: `store.ErrNotFound`, `store.ErrConflict`.
- **Tests:** stdlib `testing` only, table-driven where inputs enumerate, `-race` in CI. **100% line coverage** on `shared.Sign`/`CanonicalRequest`/`BodyHashHex`, `auth.Verifier.Verify`, and `auth.SealSecret`/`OpenSecret`.
- **Constant-time compares:** `hmac.Equal` for signatures; `subtle.ConstantTimeCompare` for CSRF tokens and the bootstrap token hash comparison path.
- **Never log** secrets, HMAC signatures, session cookies, CSRF tokens, or bootstrap tokens.
- **Conventional Commits** (`feat:`, `test:`, `refactor:`, `docs:`). One commit per task minimum.
- **Timestamps** are unix seconds (`int64`); IDs are UUIDv7 via `store.NewID()`.

---

## Shared Contracts (types/signatures pinned once; tasks reference these)

These are the cross-task interfaces. A task's Interfaces block cites them; do not rename.

```go
// internal/shared (Task 1)
const (
    HeaderDevice    = "X-Diyddns-Device"
    HeaderTimestamp = "X-Diyddns-Timestamp"
    HeaderNonce     = "X-Diyddns-Nonce"
    HeaderSignature = "X-Diyddns-Signature"
)
func BodyHashHex(body []byte) string
func CanonicalRequest(method, path, timestamp, nonce, bodyHashHex string) string
func Sign(secret []byte, canonical string) string   // lowercase-hex HMAC-SHA256

// internal/auth (Tasks 2–4)
type Argon2Params struct{ Time, MemoryKiB uint32; Parallelism uint8 }
func HashPassword(pw string, p Argon2Params) (string, error)   // PHC-encoded, embeds salt+params
func VerifyPassword(encoded, pw string) (bool, error)
func GenerateSecret() ([]byte, error)                          // 32 random bytes
func SealSecret(key, secret []byte) (string, error)            // base64(nonce||AES-256-GCM ct)
func OpenSecret(key []byte, sealed string) ([]byte, error)

type DeviceReader interface{ GetByID(ctx context.Context, id string) (store.Device, error) }
type UserReader   interface{ GetByID(ctx context.Context, id string) (store.User, error) }
type NonceInserter interface{ Insert(ctx context.Context, signature string, expiresAt int64) error }
type RequestParts struct{ Device, Timestamp, Nonce, Signature, Method, Path string; Body []byte }
type Verifier struct{ /* unexported */ }
func NewVerifier(d DeviceReader, u UserReader, n NonceInserter, key []byte, skew, nonceTTL time.Duration) *Verifier
func (v *Verifier) Verify(ctx context.Context, p RequestParts, now int64) (deviceID string, err error)

type SessionStore interface {
    Create(ctx context.Context, s store.Session) (store.Session, error)
    GetByID(ctx context.Context, id string) (store.Session, error)
    Touch(ctx context.Context, id string, expiresAt int64) error
    Delete(ctx context.Context, id string) error
}
type SessionManager struct{ /* unexported */ }
func NewSessionManager(s SessionStore, u UserReader, ttl, slide time.Duration) *SessionManager
func (m *SessionManager) Create(ctx context.Context, userID, ip, ua string) (store.Session, error)
func (m *SessionManager) Authenticate(ctx context.Context, sessionID string) (store.User, store.Session, error)
func (m *SessionManager) Destroy(ctx context.Context, sessionID string) error
func GenerateCSRFToken() (string, error)
func RandToken(n int) (string, error)   // exported: URL-safe random token; used by service pkg (enrollment codes, bootstrap token)

// internal/server/service (Tasks 6–9)
type ClientMeta struct{ Hostname, OS, ClientVersion string }
type EnrollResult struct{ DeviceID string; Secret []byte }
type CheckinReport struct{ IPv4, IPv6, Hostname, OS, ClientVersion string }
type CheckinResult struct{ DeviceID, CurrentIPv4, CurrentIPv6 string; Stored bool }

// internal/server/api (Task 11)
type ServerDeps struct {
    Log       *slog.Logger
    Store     *store.Store
    Verifier  *auth.Verifier
    Sessions  *auth.SessionManager
    Enroll    *service.EnrollmentService
    Devices   *service.DeviceService
    Checkin   *service.CheckinService
    Auth      *service.AuthService
    Bootstrap *service.BootstrapService
    Cfg       config.Auth
    Info      version.Info
}
func Build(mux *http.ServeMux, deps ServerDeps)
```

---

## Task Dependency Order (seed TodoWrite from this, one item per task)

```
T1  shared HMAC wire ........... no deps
T2  auth crypto primitives ..... no deps (adds x/crypto)
T3  auth Verifier + cache ...... depends T1, T2
T4  auth SessionManager+CSRF ... depends T2 (GenerateCSRFToken sibling), store
T5  config Auth section ........ no code deps
T6  enrollment service ......... depends T2, T3(SealSecret via auth), store
T7  checkin + device services .. depends store
T8  auth service ............... depends T2, T4, store
T9  bootstrap service .......... depends T2, store
T10 huma auth middleware ....... depends T3, T4
T11 api scaffold (Build deps) .. depends T6, T7, T8, T9, T10
T12 agent ops (enroll/checkin/self) . depends T11
T13 browser auth+bootstrap ops . depends T11
T14 devices ops + guard test ... depends T11
T15 server/cmd wiring + pruner . depends T11–T14
T16 parent-spec amendment ...... no deps (docs)
```

---

### Task 1: `internal/shared` — HMAC wire contract

**Files:**
- Create: `internal/shared/hmac.go`
- Test: `internal/shared/hmac_test.go`

**Interfaces:**
- Produces: `HeaderDevice/Timestamp/Nonce/Signature` consts; `BodyHashHex`, `CanonicalRequest`, `Sign` (see Shared Contracts).
- Consumes: stdlib only (`crypto/hmac`, `crypto/sha256`, `encoding/hex`, `strings`).

- [ ] **Step 1: Write the failing test** — `internal/shared/hmac_test.go`

```go
package shared

import "testing"

func TestBodyHashHex_EmptyIsSHA256OfEmpty(t *testing.T) {
	// SHA256("") well-known value.
	if got := BodyHashHex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty body hash = %q", got)
	}
}

func TestCanonicalRequest_NewlineJoinedLF(t *testing.T) {
	got := CanonicalRequest("POST", "/agent/v1/checkin", "1720000000", "nonce123", "abcd")
	want := "POST\n/agent/v1/checkin\n1720000000\nnonce123\nabcd"
	if got != want {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, want)
	}
}

func TestSign_KnownVector(t *testing.T) {
	// HMAC-SHA256 of "msg" under key "key", lowercase hex.
	if got := Sign([]byte("key"), "msg"); got != "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628" {
		t.Fatalf("sign = %q", got)
	}
}

func TestSign_Deterministic(t *testing.T) {
	a := Sign([]byte("s"), CanonicalRequest("GET", "/agent/v1/self", "1", "n", BodyHashHex(nil)))
	b := Sign([]byte("s"), CanonicalRequest("GET", "/agent/v1/self", "1", "n", BodyHashHex(nil)))
	if a != b {
		t.Fatal("Sign not deterministic")
	}
}
```

- [ ] **Step 2: Run test to verify it fails** — `go test ./internal/shared/ -run TestSign -v` → FAIL (undefined: `Sign`).

- [ ] **Step 3: Write minimal implementation** — `internal/shared/hmac.go`

```go
// Package shared holds the HMAC request-signing wire contract used by the
// server to verify agent requests and (in a later plan) by the client to sign
// them. Stdlib-only: it must remain importable by the huma-free client binary.
package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	HeaderDevice    = "X-Diyddns-Device"
	HeaderTimestamp = "X-Diyddns-Timestamp"
	HeaderNonce     = "X-Diyddns-Nonce"
	HeaderSignature = "X-Diyddns-Signature"
)

// BodyHashHex returns lowercase-hex SHA256(body). A nil/empty body hashes the
// SHA256 of the empty string.
func BodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalRequest builds the LF-joined signing input:
// METHOD\nPATH\nTIMESTAMP\nNONCE\nBODYHASH
func CanonicalRequest(method, path, timestamp, nonce, bodyHashHex string) string {
	return strings.Join([]string{method, path, timestamp, nonce, bodyHashHex}, "\n")
}

// Sign returns lowercase-hex HMAC-SHA256(secret, canonical).
func Sign(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
```

- [ ] **Step 4: Run tests to verify they pass** — `go test ./internal/shared/ -race -cover -v` → PASS, coverage 100.0%.

- [ ] **Step 5: Commit** — `git add internal/shared && git commit -m "feat(shared): HMAC request-signing wire contract"`

---

### Task 2: `internal/auth` crypto primitives (argon2id passwords + AES-GCM secret sealing)

**Files:**
- Create: `internal/auth/password.go`, `internal/auth/secret.go`
- Test: `internal/auth/password_test.go`, `internal/auth/secret_test.go`

**Interfaces:**
- Produces: `Argon2Params`, `HashPassword`, `VerifyPassword`, `GenerateSecret`, `SealSecret`, `OpenSecret` (see Shared Contracts).
- Consumes: `golang.org/x/crypto/argon2` (NEW dep), stdlib `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/subtle`, `encoding/base64`.

- [ ] **Step 1: Add the dependency**

Run: `go get golang.org/x/crypto/argon2@latest` (pins `golang.org/x/crypto` as a direct dep once imported below).

- [ ] **Step 2: Write the failing tests** — `internal/auth/secret_test.go`

```go
package auth

import (
	"bytes"
	"testing"
)

func testKey() []byte { return bytes.Repeat([]byte{0x2a}, 32) } // 32 bytes = AES-256

func TestSealOpen_RoundTrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil { t.Fatal(err) }
	if len(secret) != 32 { t.Fatalf("secret len = %d", len(secret)) }

	sealed, err := SealSecret(testKey(), secret)
	if err != nil { t.Fatal(err) }

	got, err := OpenSecret(testKey(), sealed)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, secret) { t.Fatal("round-trip mismatch") }
}

func TestSeal_NonDeterministic(t *testing.T) { // random nonce per seal
	s := []byte("0123456789abcdef0123456789abcdef")
	a, _ := SealSecret(testKey(), s)
	b, _ := SealSecret(testKey(), s)
	if a == b { t.Fatal("seal must use a fresh random nonce each time") }
}

func TestOpen_WrongKeyFails(t *testing.T) {
	sealed, _ := SealSecret(testKey(), []byte("0123456789abcdef0123456789abcdef"))
	wrong := make([]byte, 32)
	if _, err := OpenSecret(wrong, sealed); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

func TestOpen_TamperedFails(t *testing.T) {
	sealed, _ := SealSecret(testKey(), []byte("0123456789abcdef0123456789abcdef"))
	// flip a byte in the base64 payload
	b := []byte(sealed)
	b[len(b)-2] ^= 0x01
	if _, err := OpenSecret(testKey(), string(b)); err == nil {
		t.Fatal("expected GCM auth failure on tamper")
	}
}

// The next three cover OpenSecret/newGCM error branches required for 100% coverage.
func TestOpen_MalformedBase64(t *testing.T) {
	if _, err := OpenSecret(testKey(), "!!!not base64!!!"); err == nil {
		t.Fatal("expected base64 decode error")
	}
}

func TestOpen_CiphertextTooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}) // < GCM nonce size
	if _, err := OpenSecret(testKey(), short); err == nil {
		t.Fatal("expected ciphertext-too-short error")
	}
}

func TestSealOpen_WrongKeyLength(t *testing.T) { // exercises newGCM's len!=32 guard on both paths
	if _, err := SealSecret(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("Seal: expected 16-byte key rejection")
	}
	if _, err := OpenSecret(make([]byte, 16), "AAAA"); err == nil {
		t.Fatal("Open: expected 16-byte key rejection")
	}
}
```

(Add `"encoding/base64"` to the `secret_test.go` imports.)

`internal/auth/password_test.go`:

```go
package auth

import "testing"

func testParams() Argon2Params { return Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1} } // fast for tests

func TestHashVerifyPassword_RoundTrip(t *testing.T) {
	enc, err := HashPassword("correct horse battery staple", testParams())
	if err != nil { t.Fatal(err) }
	ok, err := VerifyPassword(enc, "correct horse battery staple")
	if err != nil { t.Fatal(err) }
	if !ok { t.Fatal("valid password rejected") }
}

func TestVerifyPassword_WrongIsFalse(t *testing.T) {
	enc, _ := HashPassword("hunter2hunter2", testParams())
	ok, err := VerifyPassword(enc, "wrong-password")
	if err != nil { t.Fatal(err) }
	if ok { t.Fatal("wrong password accepted") }
}

func TestHashPassword_SaltedDistinct(t *testing.T) {
	a, _ := HashPassword("samepassword", testParams())
	b, _ := HashPassword("samepassword", testParams())
	if a == b { t.Fatal("hashes must differ (random salt)") }
}
```

- [ ] **Step 3: Run tests to verify they fail** — `go test ./internal/auth/ -run 'TestSeal|TestHash' -v` → FAIL (undefined).

- [ ] **Step 4: Implement `internal/auth/secret.go`**

```go
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecret returns 32 cryptographically-random bytes — a device's HMAC secret.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("auth.GenerateSecret: %w", err)
	}
	return b, nil
}

// SealSecret AES-256-GCM-encrypts secret under key (must be 32 bytes) and returns
// base64(nonce || ciphertext). A fresh random 96-bit nonce is used per call.
func SealSecret(key, secret []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth.SealSecret: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, secret, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// OpenSecret reverses SealSecret. Returns an error if the key is wrong, the
// payload is malformed, or the GCM tag fails to authenticate.
func OpenSecret(key []byte, sealed string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenSecret: decode: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("auth.OpenSecret: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenSecret: %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("auth: AEAD key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: new gcm: %w", err)
	}
	return gcm, nil
}
```

- [ ] **Step 5: Implement `internal/auth/password.go`**

```go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters (from server config).
type Argon2Params struct {
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
}

const argon2SaltLen, argon2KeyLen = 16, 32

// HashPassword returns a PHC-encoded argon2id hash embedding a fresh random salt
// and the params, so VerifyPassword is self-describing.
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth.HashPassword: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Parallelism, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether pw matches the PHC-encoded argon2id hash, using
// a constant-time comparison. A malformed encoding is an error, not a false.
func VerifyPassword(encoded, pw string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("auth.VerifyPassword: bad encoding")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: version: %w", err)
	}
	var mem, time uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &par); err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: key: %w", err)
	}
	got := argon2.IDKey([]byte(pw), salt, time, mem, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
```

- [ ] **Step 6: Run tests + verify coverage** — `go test ./internal/auth/ -race -run 'TestSeal|TestOpen|TestHash|TestVerify' -cover -v` → PASS; confirm `SealSecret`/`OpenSecret` at 100%.

- [ ] **Step 7: Commit** — `git add go.mod go.sum internal/auth && git commit -m "feat(auth): argon2id passwords and AES-256-GCM secret sealing"`

---

### Task 3: `internal/auth` HMAC `Verifier` + secret cache

**Files:**
- Create: `internal/auth/hmac.go`
- Test: `internal/auth/hmac_test.go`

**Interfaces:**
- Consumes: `shared.*` (Task 1), `SealSecret`/`OpenSecret` (Task 2), `store.Device`/`store.User`/`store.ErrNotFound`.
- Produces: `DeviceReader`, `UserReader`, `NonceInserter`, `RequestParts`, `Verifier`, `NewVerifier`, `Verify` (see Shared Contracts). Also a package error `ErrUnauthorized` (sentinel returned for every auth failure so the caller maps a single 401 — no leak of which check failed).

- [ ] **Step 1: Write failing tests** — cover the whole rejection matrix + success + cache repopulation. `internal/auth/hmac_test.go`:

```go
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// --- fakes satisfying the consumer interfaces ---
type fakeDevices struct{ d store.Device; err error }
func (f fakeDevices) GetByID(_ context.Context, _ string) (store.Device, error) { return f.d, f.err }
type fakeUsers struct{ u store.User; err error }
func (f fakeUsers) GetByID(_ context.Context, _ string) (store.User, error) { return f.u, f.err }
type fakeNonces struct{ seen map[string]bool }
func (f *fakeNonces) Insert(_ context.Context, sig string, _ int64) error {
	if f.seen[sig] { return store.ErrConflict }
	f.seen[sig] = true
	return nil
}

func newFixture(t *testing.T) (*Verifier, store.Device, []byte, []byte) {
	t.Helper()
	key := make([]byte, 32); for i := range key { key[i] = byte(i) }
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	dev := store.Device{ID: "dev1", UserID: "usr1", SecretHash: sealed}
	usr := store.User{ID: "usr1"}
	v := NewVerifier(fakeDevices{d: dev}, fakeUsers{u: usr}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	return v, dev, key, secret
}

func signedParts(secret []byte, now int64, body []byte) RequestParts {
	ts := "1720000000"
	nonce := "nonce-abc"
	sig := shared.Sign(secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(body)))
	return RequestParts{Device: "dev1", Timestamp: ts, Nonce: nonce, Signature: sig, Method: "POST", Path: "/agent/v1/checkin", Body: body}
}

func TestVerify_Success(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, []byte(`{"ipv4":"1.2.3.4"}`))
	id, err := v.Verify(context.Background(), p, 1720000000)
	if err != nil { t.Fatalf("unexpected err: %v", err) }
	if id != "dev1" { t.Fatalf("device id = %q", id) }
}

func TestVerify_SkewOut(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	_, err := v.Verify(context.Background(), p, 1720000000+121)
	if !errors.Is(err, ErrUnauthorized) { t.Fatalf("want ErrUnauthorized, got %v", err) }
}

func TestVerify_BadSignature(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	p.Signature = "deadbeef"
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); err != nil { t.Fatal(err) }
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay must be rejected, got %v", err)
	}
}

func TestVerify_DisabledDevice(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret(); sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed, Disabled: true}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled device must be rejected, got %v", err)
	}
}

func TestVerify_DisabledUser(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret(); sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed}},
		fakeUsers{u: store.User{ID: "u", Disabled: true}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled user must be rejected, got %v", err)
	}
}

func TestVerify_UnknownDevice(t *testing.T) {
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{err: store.ErrNotFound}, fakeUsers{}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "nope", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown device must be rejected, got %v", err)
	}
}

// The next two cover the remaining Verify/secretFor error branches for 100% coverage.
func TestVerify_NonNumericTimestamp(t *testing.T) {
	v, _, _, _ := newFixture(t)
	p := RequestParts{Device: "dev1", Timestamp: "not-a-number", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-numeric timestamp must be rejected, got %v", err)
	}
}

func TestVerify_CorruptSecretHash(t *testing.T) { // OpenSecret fails in secretFor
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: "not-valid-sealed"}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "dev1", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("corrupt secret_hash must be rejected, got %v", err)
	}
}
```

- [ ] **Step 2: Run to verify fail** — `go test ./internal/auth/ -run TestVerify -v` → FAIL (undefined `Verifier`).

- [ ] **Step 3: Implement `internal/auth/hmac.go`**

```go
package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrUnauthorized is the single sentinel returned for EVERY HMAC failure, so the
// HTTP layer maps one 401 and never leaks which check failed.
var ErrUnauthorized = errors.New("auth: unauthorized")

type DeviceReader interface {
	GetByID(ctx context.Context, id string) (store.Device, error)
}
type UserReader interface {
	GetByID(ctx context.Context, id string) (store.User, error)
}
type NonceInserter interface {
	Insert(ctx context.Context, signature string, expiresAt int64) error
}

// RequestParts is the parsed, framework-agnostic view of an agent request.
type RequestParts struct {
	Device, Timestamp, Nonce, Signature, Method, Path string
	Body                                              []byte
}

// Verifier authenticates agent HMAC requests. It holds a process-local cache of
// decrypted secret bytes (populate-only in Plan 04 — secrets never rotate here;
// device disable is checked live from the DB each request).
type Verifier struct {
	devices  DeviceReader
	users    UserReader
	nonces   NonceInserter
	key      []byte
	skew     time.Duration
	nonceTTL time.Duration

	mu    sync.RWMutex
	cache map[string][]byte // deviceID -> secret bytes
}

func NewVerifier(d DeviceReader, u UserReader, n NonceInserter, key []byte, skew, nonceTTL time.Duration) *Verifier {
	return &Verifier{devices: d, users: u, nonces: n, key: key, skew: skew, nonceTTL: nonceTTL, cache: map[string][]byte{}}
}

// Verify authenticates one request and returns the device_id on success. Order:
// device/user liveness -> skew -> secret -> constant-time compare -> nonce insert
// (verify BEFORE nonce insert so forged requests never pollute replay_nonces).
func (v *Verifier) Verify(ctx context.Context, p RequestParts, now int64) (string, error) {
	dev, err := v.devices.GetByID(ctx, p.Device)
	if err != nil || dev.Disabled {
		return "", ErrUnauthorized
	}
	usr, err := v.users.GetByID(ctx, dev.UserID)
	if err != nil || usr.Disabled {
		return "", ErrUnauthorized
	}

	ts, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil {
		return "", ErrUnauthorized
	}
	if d := now - ts; d > int64(v.skew.Seconds()) || d < -int64(v.skew.Seconds()) {
		return "", ErrUnauthorized
	}

	secret, err := v.secretFor(dev)
	if err != nil {
		return "", ErrUnauthorized
	}

	canonical := shared.CanonicalRequest(p.Method, p.Path, p.Timestamp, p.Nonce, shared.BodyHashHex(p.Body))
	expected := shared.Sign(secret, canonical)
	if !hmac.Equal([]byte(expected), []byte(p.Signature)) {
		return "", ErrUnauthorized
	}

	if err := v.nonces.Insert(ctx, p.Signature, ts+int64(v.nonceTTL.Seconds())); err != nil {
		return "", ErrUnauthorized // ErrConflict => replay; any insert error is fail-closed
	}
	return dev.ID, nil
}

func (v *Verifier) secretFor(dev store.Device) ([]byte, error) {
	v.mu.RLock()
	s, ok := v.cache[dev.ID]
	v.mu.RUnlock()
	if ok {
		return s, nil
	}
	secret, err := OpenSecret(v.key, dev.SecretHash)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.cache[dev.ID] = secret
	v.mu.Unlock()
	return secret, nil
}
```

- [ ] **Step 4: Run tests + coverage** — `go test ./internal/auth/ -race -run TestVerify -cover -v` → PASS; confirm `Verify` (and `secretFor`) at 100%.

- [ ] **Step 5: Commit** — `git add internal/auth/hmac.go internal/auth/hmac_test.go && git commit -m "feat(auth): HMAC verifier with replay defense and secret cache"`

---

### Task 4: `internal/auth` `SessionManager` + CSRF

**Files:**
- Create: `internal/auth/session.go`
- Test: `internal/auth/session_test.go`

**Interfaces:**
- Consumes: `store.Session`/`store.User`, `UserReader` (Task 3), `store.ErrNotFound`.
- Produces: `SessionStore`, `SessionManager`, `NewSessionManager`, `Create`, `Authenticate`, `Destroy`, `GenerateCSRFToken` (see Shared Contracts).

- [ ] **Step 1: Write failing tests** covering: Create mints id+csrf; Authenticate returns user+session and rejects expired; slide extends expiry; Destroy deletes. Use an in-memory `SessionStore` fake and a `fakeUsers` (reuse from Task 3 patterns — declare a local one). `internal/auth/session_test.go`:

```go
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

type memSessions struct{ m map[string]store.Session }
func (s *memSessions) Create(_ context.Context, sess store.Session) (store.Session, error) { s.m[sess.ID] = sess; return sess, nil }
func (s *memSessions) GetByID(_ context.Context, id string) (store.Session, error) {
	v, ok := s.m[id]; if !ok { return store.Session{}, store.ErrNotFound }; return v, nil
}
func (s *memSessions) Touch(_ context.Context, id string, exp int64) error {
	v, ok := s.m[id]; if !ok { return store.ErrNotFound }; v.ExpiresAt = exp; s.m[id] = v; return nil
}
func (s *memSessions) Delete(_ context.Context, id string) error { delete(s.m, id); return nil }

func newSM(u store.User) (*SessionManager, *memSessions) {
	ms := &memSessions{m: map[string]store.Session{}}
	return NewSessionManager(ms, fakeUsers{u: u}, 720*time.Hour, 7*24*time.Hour), ms
}

func TestSession_CreateAuthenticate(t *testing.T) {
	sm, _ := newSM(store.User{ID: "u1"})
	sess, err := sm.Create(context.Background(), "u1", "1.2.3.4", "agent")
	if err != nil { t.Fatal(err) }
	if sess.ID == "" || sess.CSRFToken == "" { t.Fatal("session must have id + csrf") }
	u, got, err := sm.Authenticate(context.Background(), sess.ID)
	if err != nil { t.Fatal(err) }
	if u.ID != "u1" || got.ID != sess.ID { t.Fatal("authenticate returned wrong identity") }
}

func TestSession_Expired(t *testing.T) {
	sm, ms := newSM(store.User{ID: "u1"})
	sess, _ := sm.Create(context.Background(), "u1", "", "")
	s := ms.m[sess.ID]; s.ExpiresAt = 1; ms.m[sess.ID] = s // force expired
	if _, _, err := sm.Authenticate(context.Background(), sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired session must be ErrUnauthorized, got %v", err)
	}
}

func TestSession_Destroy(t *testing.T) {
	sm, _ := newSM(store.User{ID: "u1"})
	sess, _ := sm.Create(context.Background(), "u1", "", "")
	if err := sm.Destroy(context.Background(), sess.ID); err != nil { t.Fatal(err) }
	if _, _, err := sm.Authenticate(context.Background(), sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("destroyed session must not authenticate")
	}
}

func TestGenerateCSRFToken_Distinct(t *testing.T) {
	a, _ := GenerateCSRFToken(); b, _ := GenerateCSRFToken()
	if a == "" || a == b { t.Fatal("csrf tokens must be non-empty and unique") }
}
```

- [ ] **Step 2: Run to verify fail** → FAIL (undefined `NewSessionManager`).

- [ ] **Step 3: Implement `internal/auth/session.go`**

```go
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

type SessionStore interface {
	Create(ctx context.Context, s store.Session) (store.Session, error)
	GetByID(ctx context.Context, id string) (store.Session, error)
	Touch(ctx context.Context, id string, expiresAt int64) error
	Delete(ctx context.Context, id string) error
}

type SessionManager struct {
	sessions SessionStore
	users    UserReader
	ttl      time.Duration
	slide    time.Duration
	now      func() int64 // injectable for tests; defaults to time.Now().Unix
}

func NewSessionManager(s SessionStore, u UserReader, ttl, slide time.Duration) *SessionManager {
	return &SessionManager{sessions: s, users: u, ttl: ttl, slide: slide, now: func() int64 { return time.Now().Unix() }}
}

// RandToken returns an n-byte URL-safe random token. Exported so the service
// package can mint enrollment codes and the bootstrap token from one source.
func RandToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateCSRFToken returns a random URL-safe token.
func GenerateCSRFToken() (string, error) {
	t, err := RandToken(32)
	if err != nil {
		return "", fmt.Errorf("auth.GenerateCSRFToken: %w", err)
	}
	return t, nil
}

// Create mints a new session (opaque id + rotated CSRF token) for userID.
func (m *SessionManager) Create(ctx context.Context, userID, ip, ua string) (store.Session, error) {
	id, err := RandToken(32)
	if err != nil {
		return store.Session{}, fmt.Errorf("auth.Session.Create: id: %w", err)
	}
	csrf, err := GenerateCSRFToken()
	if err != nil {
		return store.Session{}, err
	}
	now := m.now()
	return m.sessions.Create(ctx, store.Session{
		ID: id, UserID: userID, CSRFToken: csrf, IP: ip, UserAgent: ua,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now + int64(m.ttl.Seconds()),
	})
}

// Authenticate validates a session id, slides its expiry, and returns the user.
func (m *SessionManager) Authenticate(ctx context.Context, sessionID string) (store.User, store.Session, error) {
	sess, err := m.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	now := m.now()
	if sess.ExpiresAt <= now {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	usr, err := m.users.GetByID(ctx, sess.UserID)
	if err != nil || usr.Disabled {
		return store.User{}, store.Session{}, ErrUnauthorized
	}
	// Slide: if last seen more than `slide` ago, extend expiry.
	if now-sess.LastSeenAt >= int64(m.slide.Seconds()) {
		newExp := now + int64(m.ttl.Seconds())
		if err := m.sessions.Touch(ctx, sess.ID, newExp); err == nil {
			sess.ExpiresAt = newExp
		}
	}
	return usr, sess, nil
}

// Destroy removes a session (logout). A missing session is not an error.
func (m *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	if err := m.sessions.Delete(ctx, sessionID); err != nil && !errorsIsNotFound(err) {
		return fmt.Errorf("auth.Session.Destroy: %w", err)
	}
	return nil
}
```

Add a tiny helper (same file): `func errorsIsNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }` and import `errors`.

- [ ] **Step 4: Run tests** — `go test ./internal/auth/ -race -cover -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(auth): DB-backed session manager and CSRF tokens"`

---

### Task 5: `internal/config` — `Auth` section + validation

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (extend)

**Interfaces:**
- Produces: `config.Auth` (+ nested `SessionCfg`, `HMACCfg`, `PasswordCfg`, `BootstrapCfg`), added to the existing `config.Server` struct as field `Auth`. Startup validation: `SecretKey` base64→exactly 32 bytes; `NonceTTL >= SkewWindow`.

- [ ] **Step 1: Write failing tests** — defaults present; `nonce_ttl < skew_window` errors; a non-32-byte `secret_key` errors; a valid base64 32-byte key parses. (Mirror the existing precedence-test style in `config_test.go`.) Assert `Load` surfaces these via a returned error.

```go
func TestLoad_AuthDefaults(t *testing.T) {
	cfg := mustLoadWithDB(t) // helper that sets database.path and loads
	if cfg.Auth.Session.TTL != 720*time.Hour { t.Fatalf("session ttl = %v", cfg.Auth.Session.TTL) }
	if cfg.Auth.HMAC.SkewWindow != 120*time.Second { t.Fatalf("skew = %v", cfg.Auth.HMAC.SkewWindow) }
	if cfg.Auth.Password.MinLength != 12 { t.Fatalf("min_length = %d", cfg.Auth.Password.MinLength) }
}

func TestLoad_RejectsNonceTTLBelowSkew(t *testing.T) {
	t.Setenv("DIYDDNS_AUTH_HMAC_NONCE_TTL", "60s")
	t.Setenv("DIYDDNS_AUTH_HMAC_SKEW_WINDOW", "120s")
	if _, err := loadWithDB(t); err == nil { t.Fatal("expected nonce_ttl<skew_window error") }
}

func TestSecretKeyBytes_Requires32(t *testing.T) {
	if _, err := DecodeSecretKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("16-byte key must be rejected")
	}
	if _, err := DecodeSecretKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("32-byte key must parse: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Add to `internal/config/config.go`:

```go
type Auth struct {
	Session   SessionCfg
	HMAC      HMACCfg
	Password  PasswordCfg
	Bootstrap BootstrapCfg
}
// mapstructure tags are REQUIRED for multi-word keys — viper lowercases field
// names but does not split them (see the existing ServerSection.base_url tag).
type SessionCfg struct {
	CookieName     string        `mapstructure:"cookie_name"`
	CookieSecure   bool          `mapstructure:"cookie_secure"`
	CookieSameSite string        `mapstructure:"cookie_samesite"`
	TTL            time.Duration `mapstructure:"ttl"`
	SlideWindow    time.Duration `mapstructure:"slide_window"`
}
type HMACCfg struct {
	SkewWindow time.Duration `mapstructure:"skew_window"`
	NonceTTL   time.Duration `mapstructure:"nonce_ttl"`
	SecretKey  string        `mapstructure:"secret_key"` // base64 of 32 bytes; decoded via DecodeSecretKey at startup (Task 15)
}
type PasswordCfg struct {
	Argon2Time        uint32 `mapstructure:"argon2_time"`
	Argon2MemoryKiB   uint32 `mapstructure:"argon2_memory_kib"`
	Argon2Parallelism uint8  `mapstructure:"argon2_parallelism"`
	MinLength         int    `mapstructure:"min_length"`
}
type BootstrapCfg struct {
	AdminEmail    string `mapstructure:"admin_email"`
	AdminPassword string `mapstructure:"admin_password"`
}
```

Add `Auth Auth` to the `Server` struct. **Env binding is explicit** (`config.Load` has no `AutomaticEnv` — it loops `keyDefaults` calling `SetDefault`+`BindEnv`), so **every new `auth.*` key MUST be added to `keyDefaults` or its env var is silently ignored** — including the security-critical `auth.hmac.secret_key`. Change `keyDefaults` from `map[string]string` to **`map[string]any`** (so numeric/bool/duration defaults are typed correctly) and add:

```go
// added to keyDefaults (map[string]any):
"auth.session.cookie_name":       "diyddns_session",
"auth.session.cookie_secure":     true,
"auth.session.cookie_samesite":   "lax",
"auth.session.ttl":               "720h",
"auth.session.slide_window":      "168h",
"auth.hmac.skew_window":          "120s",
"auth.hmac.nonce_ttl":            "120s",
"auth.hmac.secret_key":           "",
"auth.password.argon2_time":      3,
"auth.password.argon2_memory_kib": 65536,
"auth.password.argon2_parallelism": 2,
"auth.password.min_length":       12,
"auth.bootstrap.admin_email":     "",
"auth.bootstrap.admin_password":  "",
```

(Duration string defaults like `"720h"` decode into `time.Duration` via viper's built-in `StringToTimeDurationHookFunc`; typed int/bool defaults unmarshal directly.) After `keyDefaults`, honor the spec §5C env-var names by adding two explicit aliases so `DIYDDNS_BOOTSTRAP_ADMIN_EMAIL`/`_PASSWORD` also bind (the design §5.3 names, distinct from the auto-derived `DIYDDNS_AUTH_BOOTSTRAP_*`):

```go
_ = v.BindEnv("auth.bootstrap.admin_email", "DIYDDNS_BOOTSTRAP_ADMIN_EMAIL")
_ = v.BindEnv("auth.bootstrap.admin_password", "DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD")
```

After `Unmarshal`, enforce `Auth.HMAC.NonceTTL >= Auth.HMAC.SkewWindow` (else return an error). Add:

```go
// DecodeSecretKey decodes the base64 AEAD master key and requires exactly 32 bytes.
func DecodeSecretKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("config: auth.hmac.secret_key not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("config: auth.hmac.secret_key must decode to 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
```

(Do NOT validate `SecretKey` presence in `Load` — an empty key is allowed at config time; the server enforces fail-closed at startup only when agent auth is needed, per Task 15.)

- [ ] **Step 4: Run tests** — `go test ./internal/config/ -race -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(config): auth section (session/hmac/password/bootstrap) + validation"`

---

### Task 6: `internal/server/service` — `EnrollmentService`

**Files:**
- Create: `internal/server/service/enrollment.go`
- Test: `internal/server/service/enrollment_test.go`

**Interfaces:**
- Consumes: `store.Store` (real `:memory:` in tests via `store.Open`), `auth.GenerateSecret`/`SealSecret`/`VerifyPassword`, the AEAD key bytes.
- Produces: `EnrollmentService`, `NewEnrollmentService(st *store.Store, key []byte, codeTTL time.Duration, audit AuditSink)`, `CreateCode`, `ConsumeCode`, `EnrollCredentials`; types `ClientMeta`, `EnrollResult` (see Shared Contracts). `AuditSink` is a tiny interface `interface{ Log(ctx, store.AuditEntry) }` implemented by an `auditWriter` wrapping `st.AuditLog()` (define once here; reused by Tasks 7–9).

- [ ] **Step 1: Write failing integration tests** against a real `:memory:` store (`store.Open(ctx, ":memory:")`), seeding a user. Cover: `CreateCode` inserts a code; `ConsumeCode` happy path returns `{DeviceID, Secret}` and marks the code used; `ConsumeCode` on an expired/used code returns an error and creates **no** device (assert `Devices.ListByUser` empty — the compensating-delete); `EnrollCredentials` with a good password creates a device, wrong password errors, and the device's `SecretHash` decrypts via `auth.OpenSecret` to the returned secret.

```go
func TestConsumeCode_HappyPath(t *testing.T) {
	st := openTestStore(t); usr := seedUser(t, st, "a@b.co", "user")
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})
	code, _, err := svc.CreateCode(ctx, usr.ID, "laptop"); if err != nil { t.Fatal(err) }
	res, err := svc.ConsumeCode(ctx, code, ClientMeta{Hostname: "lp", OS: "linux"})
	if err != nil { t.Fatal(err) }
	dev, _ := st.Devices().GetByID(ctx, res.DeviceID)
	got, err := auth.OpenSecret(testKey32(), dev.SecretHash)
	if err != nil || !bytes.Equal(got, res.Secret) { t.Fatal("stored sealed secret must decrypt to returned secret") }
}

func TestConsumeCode_ExpiredLeavesNoDevice(t *testing.T) {
	st := openTestStore(t); usr := seedUser(t, st, "a@b.co", "user")
	// insert an already-expired code directly
	st.EnrollmentCodes().Create(ctx, store.EnrollmentCode{Code: "old", UserID: usr.ID, Label: "x", ExpiresAt: 1})
	svc := NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{})
	if _, err := svc.ConsumeCode(ctx, "old", ClientMeta{}); err == nil { t.Fatal("expected error") }
	ds, _ := st.Devices().ListByUser(ctx, usr.ID)
	if len(ds) != 0 { t.Fatalf("compensating-delete failed: %d devices", len(ds)) }
}
```

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement `internal/server/service/enrollment.go`.** Key logic:

```go
func (s *EnrollmentService) ConsumeCode(ctx context.Context, code string, meta ClientMeta) (EnrollResult, error) {
	c, err := s.st.EnrollmentCodes().Get(ctx, code)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("enroll.ConsumeCode: %w", err) // ErrNotFound flows up
	}
	now := store.NowUnix()
	if c.UsedAt != 0 || c.ExpiresAt <= now {
		return EnrollResult{}, fmt.Errorf("enroll.ConsumeCode: %w", store.ErrNotFound)
	}
	secret, err := auth.GenerateSecret()
	if err != nil { return EnrollResult{}, err }
	sealed, err := auth.SealSecret(s.key, secret)
	if err != nil { return EnrollResult{}, err }

	dev, err := s.st.Devices().Create(ctx, store.Device{
		UserID: c.UserID, Label: c.Label, SecretHash: sealed,
		Hostname: meta.Hostname, OS: meta.OS, ClientVersion: meta.ClientVersion,
	})
	if err != nil { return EnrollResult{}, fmt.Errorf("enroll.ConsumeCode: %w", err) }

	// Atomic single-use consume; on failure compensate by deleting the device.
	if _, err := s.st.EnrollmentCodes().Consume(ctx, code, dev.ID, now); err != nil {
		_ = s.st.Devices().Delete(ctx, dev.ID)
		return EnrollResult{}, fmt.Errorf("enroll.ConsumeCode: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: c.UserID, EventType: "device.enroll.code", TargetType: "device", TargetID: dev.ID})
	return EnrollResult{DeviceID: dev.ID, Secret: secret}, nil
}
```

`CreateCode`: `code, _ := auth.RandToken(16)`, `EnrollmentCodes.Create` with `ExpiresAt = now + codeTTL`; no audit here (audit `device.enroll.code` fires on consume). `EnrollCredentials`: `Users.GetByEmail`; if `ErrNotFound` or disabled → return a uniform error; `VerifyPassword`; on success generate/seal/create device (label from `meta.Hostname` or `"device"`), audit `device.enroll.credentials`. Also define `AuditSink` + `auditWriter` here.

- [ ] **Step 4: Run tests** — `go test ./internal/server/service/ -race -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(service): enrollment (code + credentials) with compensating-delete"`

---

### Task 7: `internal/server/service` — `CheckinService` + `DeviceService`

**Files:**
- Create: `internal/server/service/checkin.go`, `internal/server/service/device.go`
- Test: `internal/server/service/checkin_test.go`, `internal/server/service/device_test.go`

**Interfaces:**
- Produces: `CheckinService`, `NewCheckinService(st, audit)`, `Checkin`, `Self`; `DeviceService`, `NewDeviceService(st)`, `List`, `Get`. Types `CheckinReport`, `CheckinResult` (Shared Contracts).

- [ ] **Step 1: Write failing tests** against `:memory:`: a first checkin stores (`Stored==true`) and appends one `ip_history` row; an identical re-checkin returns `Stored==false` and appends **no** row (assert via `st.IPHistory().Page` count); `Self` returns the device; `DeviceService.Get` enforces ownership (a different user's id → `ErrNotFound`); `List` returns only the caller's devices.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** `Checkin` loads the device (`Devices.GetByID`), compares `CurrentIPv4/6` to the report; if unchanged returns `{..., Stored:false}` without writing; if changed calls `Devices.UpdateIP` then `st.IPHistory().Append(ctx, store.IPHistory{DeviceID: id, IPv4: ..., IPv6: ..., ObservedAt: store.NowUnix(), ClientVersion: ...})`. **Do not audit routine checkins** (no such event in the parent §3 list — don't invent one). `Self` = `Devices.GetByID`. `DeviceService.Get` = `GetByID` then check `dev.UserID == userID` else return `store.ErrNotFound`; `List` = `Devices.ListByUser`.

> **Store API (confirmed):** `st.IPHistory()` exposes `Append(ctx, IPHistory)`, `Latest(ctx, deviceID)`, `Page(ctx, deviceID, cursor, limit)` — the change-count assertion in the test uses `Page`.

> **`last_seen_at` semantics (deliberate, per parent spec §3 + §12):** because `Devices.UpdateIP` (the only writer of `last_seen_at`) is called **only on IP change**, `last_seen_at` means "time of last *change* seen" in v1 — exactly what parent spec §3 documents (`-- v1: time of last *change* seen`). True last-contact ("Last seen" vs "Last change") is the deferred **heartbeat** future-work (§12). This is intended, not a bug — do **not** touch `last_seen_at` on an unchanged checkin.

- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(service): checkin (change-only history) and device read"`

---

### Task 8: `internal/server/service` — `AuthService` (login/logout/me/password)

**Files:**
- Create: `internal/server/service/auth.go`
- Test: `internal/server/service/auth_test.go`

**Interfaces:**
- Consumes: `store.Store`, `auth.SessionManager` (Task 4), `auth.VerifyPassword`/`HashPassword` (Task 2), `config.PasswordCfg` (Argon2 params + MinLength), `AuditSink`.
- Produces: `AuthService`, `NewAuthService(st, sessions, pw config.PasswordCfg, audit)`, `Login(ctx, email, pw, ip, ua) (store.Session, error)`, `Logout(ctx, sessionID) error`, `ChangePassword(ctx, userID, oldPw, newPw) error`. (`Me` is served in the API layer from the authenticated context — no service method.)

- [ ] **Step 1: Write failing tests:** valid login returns a session whose `Authenticate` resolves to the user; wrong password → uniform error; **unknown email also runs a hash** (timing-equalized) and returns the same uniform error; a disabled user cannot log in; `ChangePassword` rejects a wrong old password and a `< MinLength` new password, and succeeds otherwise (new hash verifies). Assert `user.login.failed` audited on failure and `user.login.local` on success.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Login:

```go
var errInvalidCreds = errors.New("service: invalid credentials")
// decoyHash is a fixed valid argon2id encoding used to equalize timing on unknown email.
func (s *AuthService) Login(ctx context.Context, email, pw, ip, ua string) (store.Session, error) {
	u, err := s.st.Users().GetByEmail(ctx, email)
	if err != nil {
		_, _ = auth.VerifyPassword(s.decoy, pw) // constant-work path; ignore result
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip}) // identical audit shape for both failure paths (design §4.3)
		return store.Session{}, errInvalidCreds
	}
	// Run the decoy path too when the user has no local password (OIDC-only, empty
	// hash) so timing does not distinguish those accounts once OIDC lands (Plan 05).
	if u.PasswordHash == "" {
		_, _ = auth.VerifyPassword(s.decoy, pw)
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip})
		return store.Session{}, errInvalidCreds
	}
	ok, _ := auth.VerifyPassword(u.PasswordHash, pw)
	if !ok || u.Disabled {
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip}) // NOTE: omit ActorUserID so unknown-vs-known failures are indistinguishable in the log
		return store.Session{}, errInvalidCreds
	}
	sess, err := s.sessions.Create(ctx, u.ID, ip, ua)
	if err != nil { return store.Session{}, err }
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.login.local", IP: ip})
	return sess, nil
}
```

`s.decoy` is computed once in `NewAuthService` via `HashPassword("x", pw-params)`. `Logout` = `sessions.Destroy` + audit `user.logout`. `ChangePassword` = verify old, enforce `len(newPw) >= MinLength`, `HashPassword`, `Users.Update` (load user, set `PasswordHash`, keep other fields), audit `user.password_change`.

- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(service): auth service with timing-equalized login"`

---

### Task 9: `internal/server/service` — `BootstrapService`

**Files:**
- Create: `internal/server/service/bootstrap.go`
- Test: `internal/server/service/bootstrap_test.go`

**Interfaces:**
- Consumes: `store.Store`, `auth.HashPassword`/`VerifyPassword`, `config.BootstrapCfg` + `config.PasswordCfg`, a logger, `AuditSink`.
- Produces: `BootstrapService`, `NewBootstrapService(...)`, `Startup(ctx) error`, `AdminExists(ctx) (bool, error)`, `Consume(ctx, token, email, pw string) (store.User, error)`. Errors: `ErrBootstrapClosed` (any admin exists → maps 410), `ErrBootstrapToken` (bad token → 401).

- [ ] **Step 1: Write failing tests:**
  - `Startup` env-path: with `BootstrapCfg.AdminEmail/Password` set and no users → creates an admin; a second `Startup` is a no-op (still one admin).
  - `Startup` token-path: no env, no users → sets `bootstrap.token_hash` (assert `Bootstrap.Get` has a hash) and returns the token via a captured log/side-channel (return the plaintext token from `Startup` **only** in tests? No — instead expose it through the logger). *Test approach:* have `Startup` call an injected `func(token string)` sink (default logs the `BOOTSTRAP_TOKEN=` line); the test injects a capturing sink.
  - `Consume` happy: with a minted token, correct token+email+pw → creates admin, `Bootstrap.Get` now has empty hash (consumed).
  - `Consume` wrong token → `ErrBootstrapToken`, no admin created.
  - `Consume` when an admin already exists → `ErrBootstrapClosed`.
  - **Atomic gate:** two sequential `Consume` with the same token → first succeeds, second → `ErrBootstrapClosed` (the second sees an admin) OR `ErrBootstrapToken`/closed (consume already cleared). Assert exactly one admin.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** `AdminExists` = `Users.List` and scan for `role=="admin"` (family scale; fine). `Startup`:

```go
func (s *BootstrapService) Startup(ctx context.Context) error {
	users, err := s.st.Users().List(ctx)
	if err != nil { return fmt.Errorf("bootstrap.Startup: %w", err) }
	if len(users) > 0 { return nil }
	if s.cfg.AdminEmail != "" && s.cfg.AdminPassword != "" {
		return s.createAdmin(ctx, s.cfg.AdminEmail, s.cfg.AdminPassword, "env")
	}
	st, err := s.st.Bootstrap().Get(ctx)
	if err == nil && st.TokenHash != "" && st.ConsumedAt == 0 {
		s.log.Info("bootstrap pending; visit /bootstrap to claim admin")
		return nil
	}
	token, err := auth.RandToken(32); if err != nil { return err }
	hash, err := auth.HashPassword(token, s.pwParams()); if err != nil { return err }
	if err := s.st.Bootstrap().SetTokenHash(ctx, hash); err != nil { return fmt.Errorf("bootstrap.Startup: %w", err) }
	s.emitToken(token) // default: logs `BOOTSTRAP_TOKEN=<token> visit /bootstrap to claim admin (single use)`
	return nil
}
```

`Consume` — atomic gate ordering (design §5.3):

```go
func (s *BootstrapService) Consume(ctx context.Context, token, email, pw string) (store.User, error) {
	if err := validateEmail(email); err != nil { return store.User{}, err }
	if len(pw) < s.pwMinLen { return store.User{}, fmt.Errorf("bootstrap: password too short") }
	if ok, _ := s.AdminExists(ctx); ok { return store.User{}, ErrBootstrapClosed }

	bs, err := s.st.Bootstrap().Get(ctx)
	if err != nil || bs.TokenHash == "" { return store.User{}, ErrBootstrapToken }
	if ok, _ := auth.VerifyPassword(bs.TokenHash, token); !ok { return store.User{}, ErrBootstrapToken }

	if err := s.st.Bootstrap().Consume(ctx); err != nil { // atomic single-use gate
		return store.User{}, ErrBootstrapClosed // ErrNotFound => already consumed / raced
	}
	u, err := s.createAdmin(ctx, email, pw, "token")
	if err != nil {
		s.log.Error("BOOTSTRAP CRITICAL: token consumed but admin creation failed; delete bootstrap row or use env path", "err", err)
		return store.User{}, err
	}
	return u, nil
}
```

`createAdmin`: `HashPassword`, `Users.Create{Role:"admin"}`, audit `user.created` (+ `bootstrap.consumed` when path=="token").

- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(service): bootstrap admin with atomic single-use gate"`

---

### Task 10: `internal/server/api` — huma auth middleware (HMAC + session + CSRF)

**Files:**
- Create: `internal/server/api/authmw.go`
- Test: `internal/server/api/authmw_test.go`

**Interfaces:**
- Consumes: `auth.Verifier` (Task 3), `auth.SessionManager` (Task 4), `shared.*`, huma v2.38.0 (`huma.API`, `huma.Context`, `humago.Unwrap`, `huma.WithValue`, `huma.WriteErr`, `huma.Middlewares`).
- Produces: `hmacMiddleware(api huma.API, v *auth.Verifier, maxBody int64) func(huma.Context, func(huma.Context))`; `sessionMiddleware(api, sm)`; `csrfMiddleware(api)`; context-key accessors `DeviceIDFrom(ctx)`, `UserFrom(ctx)`, `SessionFrom(ctx)`; const `maxAgentBody = 64 * 1024`.

- [ ] **Step 1: Write the failing PROBE + behavior tests.** Register a **throwaway** guarded op on a real `humago.New(mux)` API, attach `hmacMiddleware`, drive it via `httptest`: (a) a correctly-signed request reaches the handler and the handler sees the device id via `DeviceIDFrom`; (b) an unsigned request → 401; (c) an oversize body → 413; (d) the handler can still read the JSON body (proves body-restore). This is the P1/P3 in-repo confirmation.

```go
func TestHMACMiddleware_ProbesBodyRestoreAndAuth(t *testing.T) {
	st := openTestStore(t) // seed a device with a known sealed secret + user
	key := testKey32(); secret := seedDeviceWithSecret(t, st, key, "dev1", "usr1")
	v := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, 120*time.Second, 120*time.Second)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("probe", "1"))
	type in struct{ Body struct{ IPv4 string `json:"ipv4"` } }
	type out struct{ Body struct{ Echo, Device string } }
	huma.Register(api, huma.Operation{
		Method: "POST", Path: "/agent/v1/probe",
		Middlewares: huma.Middlewares{hmacMiddleware(api, v, maxAgentBody)},
	}, func(ctx context.Context, i *in) (*out, error) {
		o := &out{}; o.Body.Echo = i.Body.IPv4; o.Body.Device = DeviceIDFrom(ctx); return o, nil
	})

	srv := httptest.NewServer(mux); defer srv.Close()
	body := []byte(`{"ipv4":"1.2.3.4"}`)
	// signed request -> 200, echoes body + device id (body-restore works)
	// unsigned -> 401 ; oversize -> 413   (assert all three)
}
```

- [ ] **Step 2: Run to verify fail** → FAIL (undefined `hmacMiddleware`).

- [ ] **Step 3: Implement `internal/server/api/authmw.go`.**

```go
package api

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

const maxAgentBody = 64 * 1024

type ctxKey int
const (
	deviceIDKey ctxKey = iota
	userKey
	sessionKey
)

func DeviceIDFrom(ctx context.Context) string { s, _ := ctx.Value(deviceIDKey).(string); return s }
func UserFrom(ctx context.Context) store.User { u, _ := ctx.Value(userKey).(store.User); return u }
func SessionFrom(ctx context.Context) store.Session { s, _ := ctx.Value(sessionKey).(store.Session); return s }

// hmacMiddleware verifies the HMAC envelope, bounds the body read (pre-auth DoS
// defense), restores the body for the handler, and forwards the device id.
func hmacMiddleware(api huma.API, v *auth.Verifier, maxBody int64) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		body, err := io.ReadAll(io.LimitReader(ctx.BodyReader(), maxBody+1))
		if err != nil || int64(len(body)) > maxBody {
			_ = huma.WriteErr(api, ctx, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body)) // restore for handler input parsing
		deviceID, verr := v.Verify(ctx.Context(), auth.RequestParts{
			Device:    ctx.Header(shared.HeaderDevice),
			Timestamp: ctx.Header(shared.HeaderTimestamp),
			Nonce:     ctx.Header(shared.HeaderNonce),
			Signature: ctx.Header(shared.HeaderSignature),
			Method:    ctx.Method(),
			Path:      ctx.URL().Path,
			Body:      body,
		}, nowUnix())
		if verr != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(huma.WithValue(ctx, deviceIDKey, deviceID))
	}
}

// sessionMiddleware authenticates the session cookie and forwards user+session.
func sessionMiddleware(api huma.API, sm *auth.SessionManager, cookieName string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		c, err := r.Cookie(cookieName)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}
		u, sess, err := sm.Authenticate(ctx.Context(), c.Value)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(huma.WithValue(huma.WithValue(ctx, userKey, u), sessionKey, sess))
	}
}

// csrfMiddleware enforces X-CSRF-Token on mutating requests (constant-time).
// MUST run AFTER sessionMiddleware (needs the session in context).
func csrfMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sess := SessionFrom(ctx.Context())
		got := ctx.Header("X-CSRF-Token")
		if sess.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "invalid csrf token")
			return
		}
		next(ctx)
	}
}
```

`nowUnix` = a small package var `func() int64 { return time.Now().Unix() }` (injectable for tests). Import `crypto/subtle`, `time`.

> **Middleware order for protected mutating `/api` ops:** `huma.Middlewares{sessionMiddleware(...), csrfMiddleware(api)}` (session first — CSRF reads the session from context). Read-only `/api` ops carry only `sessionMiddleware`.

- [ ] **Step 4: Run probe tests** — `go test ./internal/server/api/ -race -run TestHMACMiddleware -v` → PASS (proves body-restore + auth + 413). If `humago.Unwrap`-based restore fails against v2.38.0, fall back to the net/http-scoped middleware (design §3.2) — but the source review says this compiles.

- [ ] **Step 5: Commit** — `git commit -am "feat(api): huma HMAC, session, and CSRF middleware"`

---

### Task 11: `internal/server/api` — `ServerDeps` + extend `api.Build`

**Files:**
- Modify: `internal/server/api/api.go`
- Test: `internal/server/api/api_test.go` (extend; also apply follow-up #6: nil-store → `:memory:`)

**Interfaces:**
- Produces: `ServerDeps` struct (see Shared Contracts) and the new `Build(mux *http.ServeMux, deps ServerDeps)` signature. Build constructs `agentAPI` + `apiAPI` (unchanged `groupConfig`), registers `capabilities` (unchanged), `RegisterHealth`, and exposes the two `huma.API` handles to the op-registration functions the next tasks add (via package-level `register*` funcs called with the API + deps).

- [ ] **Step 1: Write/adjust failing test.** `Build` now takes `ServerDeps`; update the existing api tests to pass a `ServerDeps{Store: memStore, Info: ...}` (construct real services/verifier from the store + a test key). Assert the existing capabilities + health + OpenAPI behavior still holds. **Do not register the new ops yet** — that's Tasks 12–14; this task only changes the signature + wiring shell.

- [ ] **Step 2: Run → FAIL** (signature mismatch across callers).

- [ ] **Step 3: Implement.** Change `Build` to:

```go
func Build(mux *http.ServeMux, deps ServerDeps) {
	agentAPI := humago.New(mux, groupConfig("DIYDDNS Agent API", "/agent", deps.Info.Version))
	registerCapabilities(agentAPI, deps.Info)
	registerAgentOps(agentAPI, deps) // Task 12 fills this in (empty stub now)

	apiAPI := humago.New(mux, groupConfig("DIYDDNS UI API", "/api", deps.Info.Version))
	registerAuthOps(apiAPI, deps)    // Task 13 (empty stub now)
	registerDeviceOps(apiAPI, deps)  // Task 14 (empty stub now)

	RegisterHealth(mux, deps.Log, deps.Store)
}
```

Add empty `registerAgentOps`, `registerAuthOps`, `registerDeviceOps` stubs in this task (filled by later tasks) so the file compiles. Update `internal/server/server.go`'s `Handler` call site to build a `ServerDeps` — **temporarily** with only `Store/Log/Info` (Task 15 wires the real services). Keep it compiling.

- [ ] **Step 4: Run** — `go test ./internal/server/... -race -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "refactor(api): thread ServerDeps through Build for auth wiring"`

---

### Task 12: `internal/server/api` — agent ops (enroll/code, enroll/credentials, checkin, self)

**Files:**
- Create: `internal/server/api/enroll.go`, `internal/server/api/checkin.go`
- Modify: `internal/server/api/api.go` (`registerAgentOps` body)
- Test: `internal/server/api/agent_test.go`

**Interfaces:**
- Consumes: `deps.Enroll`, `deps.Checkin`, `deps.Verifier`, `hmacMiddleware`, `DeviceIDFrom`.
- Produces: the four agent operations, all registered by `registerAgentOps(api, deps)`.

- [ ] **Step 1: Write failing integration tests** over a full `Build`-assembled server (`httptest`): unauthenticated `enroll/code` with a valid seeded code returns `{device_id, secret}`; `enroll/credentials` with good creds works; a **signed** `checkin` (build the signature with `shared.Sign` + the returned secret) stores and is visible via a signed `self`; an **unsigned** checkin → 401.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Enroll ops (no middleware): huma input structs with `Body`, call `deps.Enroll.ConsumeCode`/`EnrollCredentials`, map `store.ErrNotFound` → `huma.Error401Unauthorized` (uniform; §8), return `{DeviceID, Secret: base64(secret)}`. Checkin/self ops attach `Middlewares: huma.Middlewares{hmacMiddleware(api, deps.Verifier, maxAgentBody)}`, read the device via `DeviceIDFrom(ctx)`, call `deps.Checkin.Checkin`/`Self`. Fill `registerAgentOps` to register all four.

- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(api): agent enroll, checkin, and self operations"`

---

### Task 13: `internal/server/api` — browser auth + bootstrap ops

**Files:**
- Create: `internal/server/api/auth.go`
- Modify: `internal/server/api/api.go` (`registerAuthOps`)
- Test: `internal/server/api/auth_ops_test.go`

**Interfaces:**
- Consumes: `deps.Auth`, `deps.Bootstrap`, `deps.Sessions`, `sessionMiddleware`, `csrfMiddleware`, `UserFrom`, `SessionFrom`, `deps.Cfg.Session` (cookie attrs).
- Produces: `login`, `logout`, `me`, `password`, `bootstrap` ops via `registerAuthOps`.

- [ ] **Step 1: Write failing integration tests:** login sets a `diyddns_session` cookie (assert `HttpOnly`, `SameSite=Lax`); `me` (with cookie) returns `{user, csrf}`; `password` change requires cookie **and** a matching `X-CSRF-Token` (missing token → 403); `logout` clears the session (subsequent `me` → 401); `bootstrap` on a fresh store creates admin and returns 200; a second `bootstrap` → 410.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** `login` (no middleware): call `deps.Auth.Login`; on success set the cookie via `humago.Unwrap` writer + `http.SetCookie` with attrs from `deps.Cfg.Session` (HttpOnly, `SameSite=Lax`, `Path=/`; **Secure** = `r.TLS != nil || cfg.CookieSecure`). **Deferred:** the design §5.2 `X-Forwarded-Proto` + `server.trusted_proxies` CIDR refinement is **not** implemented in Plan 04 (no `trusted_proxies` config key exists yet) — it lands with the Deploy/TLS or Hardening plan when proxy-header trust is built. For the default `tls.mode=plain` shape, `cookie_secure` config controls it. `me`: `sessionMiddleware`; return `UserFrom`+`SessionFrom().CSRFToken`. `password`: `sessionMiddleware`+`csrfMiddleware`; call `ChangePassword`. `logout`: `sessionMiddleware`; `Destroy` + expire cookie. `bootstrap` (no middleware): call `deps.Bootstrap.Consume`; map `ErrBootstrapClosed`→410, `ErrBootstrapToken`→401.

- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(api): browser auth (login/logout/me/password) and bootstrap"`

---

### Task 14: `internal/server/api` — device ops (mint/list/get) + behavioral guard test

**Files:**
- Create: `internal/server/api/devices.go`
- Modify: `internal/server/api/api.go` (`registerDeviceOps`)
- Test: `internal/server/api/devices_test.go`, `internal/server/api/guard_test.go`

**Interfaces:**
- Consumes: `deps.Enroll.CreateCode`, `deps.Devices`, `sessionMiddleware`, `csrfMiddleware`, `UserFrom`.
- Produces: `POST /api/v1/devices` (session+CSRF, mints a code), `GET /api/v1/devices` (session), `GET /api/v1/devices/{id}` (session) via `registerDeviceOps`; plus the fail-open **behavioral guard test**.

- [ ] **Step 1: Write failing tests:** logged-in `POST /api/v1/devices {label}` (with CSRF) returns `{code, expires_at}`; `GET /api/v1/devices` lists the caller's devices; `GET /api/v1/devices/{id}` for another user's device → 404. **Guard test (`guard_test.go`):** table of every protected path+method; hit each with **no cookie/signature** and assert status is 401 or 403 (never 2xx) — catches a future fail-open op.

```go
func TestGuard_ProtectedPathsRejectUnauthenticated(t *testing.T) {
	srv := newFullServer(t) // Build over :memory:
	cases := []struct{ method, path string }{
		{"POST", "/agent/v1/checkin"}, {"GET", "/agent/v1/self"},
		{"POST", "/api/v1/auth/logout"}, {"GET", "/api/v1/auth/me"}, {"POST", "/api/v1/auth/password"},
		{"POST", "/api/v1/devices"}, {"GET", "/api/v1/devices"},
	}
	for _, c := range cases {
		code := doNoAuth(t, srv, c.method, c.path)
		if code != 401 && code != 403 { t.Errorf("%s %s returned %d (fail-open!)", c.method, c.path, code) }
	}
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the three device ops (session; POST also CSRF) and fill `registerDeviceOps`.
- [ ] **Step 4: Run tests + full package** — `go test ./internal/server/api/ -race -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(api): device mint/list/get + fail-open guard test"`

---

### Task 15: `internal/server` + `cmd` wiring — construct deps, bootstrap startup, pruner

**Files:**
- Modify: `internal/server/server.go` (build real `ServerDeps`; start pruner), `cmd/diyddns-server/main.go` (run `BootstrapService.Startup` in `serve`)
- Create: `internal/server/pruner.go`
- Test: `internal/server/server_test.go` (extend; add restart-survival + serve-boot test — follow-up #6)

**Interfaces:**
- Consumes: everything. Produces: a fully wired server. `New(cfg, st, log)` now also decodes `cfg.Auth.HMAC.SecretKey` (via `config.DecodeSecretKey`) and constructs `auth.NewVerifier`, `auth.NewSessionManager`, and all five services, packing them into `ServerDeps` for `api.Build`.

- [ ] **Step 1: Write failing tests:**
  - **Fail-closed:** `New` returns an error when `cfg.Auth.HMAC.SecretKey` is empty/invalid (agent auth impossible).
  - **Restart survival (design §12.5):** open a `:memory:`... *no* — `:memory:` doesn't survive reopen; use a temp-file DB. Enroll a device (seal secret) with key K; construct a **new** `Verifier` with key K over the same store; a signed checkin verifies. Proves AEAD-at-rest repopulation.
  - **Serve boot (follow-up #6):** `New` + `Run` in a goroutine, hit `/healthz`, cancel, clean shutdown.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** In `server.New`: `key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)` (error if empty → fail-closed); build verifier/sessions/services; pass `ServerDeps` to `api.Build`. In `cmd serve`: after `store.Open`, construct `BootstrapService` and call `Startup(ctx)` before `server.Run`. `internal/server/pruner.go`: a goroutine loop on `time.NewTicker(prunerInterval)` where `const prunerInterval = time.Hour` (an explicit Plan 04 const — no config key; the configurable `retention.*` section is a later plan) calling `ReplayNonces.PruneExpired`, `Sessions.PruneExpired`, `EnrollmentCodes.PruneExpired` with `store.NowUnix()`; started in `Run`, stopped on ctx cancel via `select { case <-ctx.Done(): return; case <-ticker.C: ... }`.

- [ ] **Step 4: Run full suite** — `go test ./... -race` → PASS; `golangci-lint run` clean; `go test ./cmd/diyddns-client/ -run TestDeps` (client still huma-free) → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(server): wire auth deps, bootstrap startup, and background pruner"`

---

### Task 16: Amend the parent design spec (D1–D4)

**Files:**
- Modify: `docs/plans/2026-05-01-diyddns-design.md`

- [ ] **Step 1: Patch the spec** to match the shipped, reviewed deviations:
  - **§3** `devices.secret_hash` comment: change "argon2id of HMAC secret" → "AES-256-GCM-sealed HMAC secret (base64 of nonce‖ciphertext), under the server master key `auth.hmac.secret_key`; argon2id would be unverifiable for HMAC."
  - **§5A step 4:** replace the "one-time argon2id verify" cache description with the AEAD-decrypt-and-cache scheme; note verify-before-nonce-insert ordering (D3).
  - **§8:** add `auth.hmac.secret_key` (base64 32-byte AEAD master key) under `auth.hmac`.
  - **§10:** update the "HMAC at rest" bullet from argon2id to AES-256-GCM + master-key note (loss ⇒ re-enroll; rotation is future work).
- [ ] **Step 2: Verify links + internal consistency** — no other section still claims argon2id for the device secret (`grep -n "argon2id" docs/plans/2026-05-01-diyddns-design.md` and confirm remaining hits are passwords/bootstrap-token only).
- [ ] **Step 3: Commit** — `git commit -am "docs(spec): amend HMAC secret storage to AES-256-GCM (Plan 04 D1-D4)"`

---

## Self-Review (completed by plan author)

- **Spec coverage:** every design §4/§5/§6 component maps to a task (see Dependency Order); deviations D1–D4 → Task 16; follow-up #6 → Tasks 11 & 15; #7 → satisfied by `huma.WriteErr` (no partial writes) in Task 10.
- **Type consistency:** shared signatures are pinned in **Shared Contracts** and each task's Interfaces block cites them (`EnrollResult`, `CheckinResult`, `ServerDeps`, `Verify`, `Authenticate` used identically across tasks).
- **Ordering:** `api.Build` signature change is isolated to Task 11 **before** the op tasks (12–14) — the defect the critical-thinking pass caught. The guard test is **behavioral** (Task 14), not introspective, since huma per-op middleware isn't reflectable.
- **Open probes:** P1/P3 confirmed in-repo by Task 10's probe test; P2 (AES-256-GCM) is baked into Task 2.

## Notes for the implementer

- Store helpers used across tasks are **confirmed present**: `store.NowUnix() int64`, `store.NewID() string`, `st.IPHistory().Append/Latest/Page`, and the repo accessors `st.Users()/Devices()/Sessions()/EnrollmentCodes()/ReplayNonces()/Bootstrap()/AuditLog()`. Still read a repo file before calling an unfamiliar method to confirm its exact signature.
- `validateEmail` (Task 9) can be a minimal RFC-lax check (`strings.Contains(s,"@")` + non-empty local/domain) — this is not the security boundary; the password + token are.
