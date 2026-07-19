# DIYDDNS Plan 09 — Services (device management + admin) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the server-side device-management (`PATCH`/`DELETE`/`rotate-secret`/`history`) and admin (users CRUD, all-devices, audit-log, server-info) `/api/v1` surface deferred from Plan 04, reusing existing store repos and the huma per-operation auth middleware.

**Architecture:** Purely additive over existing seams — no schema migration, no new persistence. Two new low-level seams (`Verifier.Invalidate` for secret-cache eviction on rotate; `adminMiddleware` for role gating). The thin `DeviceService` gains owner-scoped mutation methods; a new `AdminService` holds guarded user management + audit reads. New huma ops register on the existing `apiAPI` (`/api` group) via new register functions wired in `api.Build`.

**Tech Stack:** Go 1.25 (no CGO), huma v2.38.0 (per-op middleware via `Operation.Middlewares` + `humago.Unwrap`), modernc.org/sqlite store, argon2id password hashing + AES-256-GCM secret sealing (`internal/auth`), slog.

**Design doc:** `docs/designs/2026-07-18-diyddns-09-services-design.md` (read it first).

## Global Constraints

- **Go 1.25, no CGO.** Pure-Go only; nothing that pulls a C toolchain.
- **All changes are server-side.** The client-isolation guard `cmd/diyddns-client/deps_test.go` MUST stay green — never import server-only packages into the client. Do not touch `cmd/diyddns-client`.
- **No schema migration.** This plan adds zero migrations; it only calls existing store methods.
- **Errors wrapped with `%w`.** Match the existing `fmt.Errorf("pkg.Method: %w", err)` idiom.
- **TDD, `-race`, frequent commits.** Every task: RED test → run-fail → implement → run-pass → commit.
- **Gates per task:** `go build ./...`, `go vet ./...`, `gofmt -l` (empty), `golangci-lint run` (0 issues, whole module), `go test ./... -race`.
- **huma per-op middleware pattern (verified v2.38.0):** middleware is `func(huma.Context, func(huma.Context))`; unwrap with `humago.Unwrap(ctx)`; forward context values with `huma.WithValue`; write errors with `huma.WriteErr(api, ctx, status, msg)`. Chain order: `sessionMiddleware` → (`adminMiddleware`) → (`csrfMiddleware`).
- **Uniform error mapping:** `store.ErrNotFound`/foreign-owner → 404; `store.ErrConflict`/guard violations → 409; admin gate → 403; missing/invalid session → 401; missing/invalid CSRF → 403; body validation → 422 (huma default).
- **Secrets never logged.** The rotated plaintext secret and password hashes never appear in logs or error strings.

---

## File Structure

- `internal/auth/hmac.go` — **modify:** add `Verifier.Invalidate(deviceID string)`.
- `internal/auth/hmac_test.go` — **modify/create:** test eviction + re-populate.
- `internal/server/api/authmw.go` — **modify:** add `adminMiddleware(api huma.API)`.
- `internal/server/api/authmw_test.go` — **modify:** test admin gate 403/pass.
- `internal/server/service/device.go` — **modify:** add `key`, `invalidator`, `audit` deps + `Rename`/`SetEnabled`/`Delete`/`RotateSecret`/`History` methods; change `NewDeviceService` signature.
- `internal/server/service/device_test.go` — **modify:** service-method + guard tests.
- `internal/server/service/admin.go` — **create:** `AdminService` (user CRUD + guards + `ListUsers`/`ListAllDevices`/`ListAudit`).
- `internal/server/service/admin_test.go` — **create:** guard + CRUD tests.
- `internal/server/api/devices.go` — **modify:** add device-management ops (`registerDeviceMgmtOps`) + DTOs.
- `internal/server/api/devices_manage_test.go` — **create:** op-level auth-matrix + behavior tests.
- `internal/server/api/admin.go` — **create:** `registerAdminOps` + DTOs.
- `internal/server/api/admin_test.go` — **create:** op-level auth-matrix + behavior tests.
- `internal/server/api/api.go` — **modify:** add `ServerDeps.Admin` field; call `registerDeviceMgmtOps` + `registerAdminOps` in `Build`.
- `internal/server/server.go` — **modify:** update `NewDeviceService(...)` call; construct + wire `AdminService`.

---

## Task Dependency Graph

- **T1** (`Verifier.Invalidate`) — no deps.
- **T2** (`adminMiddleware`) — no deps.
- **T3** (`DeviceService` extensions) — depends on T1.
- **T4** (device-management ops) — depends on T3.
- **T5** (`AdminService`) — no deps (uses store + auth + config only).
- **T6** (admin ops + wiring) — depends on T2 and T5.

Independent starts: T1, T2, T5. Order for a single worker: T1 → T2 → T3 → T4 → T5 → T6.

---

### Task 1: `Verifier.Invalidate` secret-cache eviction seam

**Files:**
- Modify: `internal/auth/hmac.go`
- Test: `internal/auth/hmac_test.go`

**Interfaces:**
- Consumes: existing `Verifier` (`cache map[string][]byte`, `mu sync.RWMutex`, `secretFor`).
- Produces: `func (v *Verifier) Invalidate(deviceID string)` — deletes the cached decrypted secret for `deviceID` under the write lock, so the next `Verify` re-opens the (rotated) sealed secret from the DB. Satisfies the `SecretCacheInvalidator` interface T3 defines.

- [ ] **Step 1: Write the failing test**

Add to `internal/auth/hmac_test.go`. This exercises the cache directly via `secretFor` behavior: seed the cache by verifying once, rotate the stored `SecretHash`, confirm the *stale* secret still verifies (cache hit), then `Invalidate` and confirm the *new* secret is required. If the existing test file already has a `Verifier` harness (fakes for `DeviceReader`/`UserReader`/`NonceInserter`), reuse it; otherwise mirror the fakes from the existing tests in this file.

```go
func TestVerifier_Invalidate_EvictsCachedSecret(t *testing.T) {
	// Two sealed forms of two different secrets for the same device id.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	secretA := []byte("secret-A-0123456789012345")
	secretB := []byte("secret-B-0123456789012345")
	sealedA, err := SealSecret(key, secretA)
	if err != nil {
		t.Fatal(err)
	}
	sealedB, err := SealSecret(key, secretB)
	if err != nil {
		t.Fatal(err)
	}

	dev := store.Device{ID: "dev1", UserID: "u1", SecretHash: sealedA}
	dr := &fakeDeviceReader{dev: dev}
	ur := &fakeUserReader{user: store.User{ID: "u1"}}
	nonces := &fakeNonceInserter{}
	v := NewVerifier(dr, ur, nonces, key, 120*time.Second, 120*time.Second)

	// Populate the cache with secretA by verifying a request signed with it.
	now := int64(1_000_000)
	mustVerify(t, v, dr.dev, secretA, now, "n1") // helper builds a valid signed RequestParts and asserts success

	// Rotate the stored secret to sealedB; cache still holds secretA.
	dr.dev.SecretHash = sealedB

	// Without Invalidate: a request signed with the NEW secretB must FAIL (cache still serves secretA).
	if _, err := v.Verify(context.Background(), signedParts(dr.dev, secretB, now, "n2"), now); err == nil {
		t.Fatal("expected stale cache to reject the new secret before Invalidate")
	}

	// After Invalidate: the new secretB must now verify.
	v.Invalidate(dr.dev.ID)
	if _, err := v.Verify(context.Background(), signedParts(dr.dev, secretB, now, "n3"), now); err != nil {
		t.Fatalf("expected new secret to verify after Invalidate, got %v", err)
	}
}
```

If the file lacks `mustVerify`/`signedParts`/`fakeDeviceReader`/`fakeUserReader`/`fakeNonceInserter`, add small helpers using `shared.CanonicalRequest`, `shared.BodyHashHex(nil)`, and `shared.Sign(secret, canonical)` (the same functions `Verify` uses at `hmac.go:88-89`) so the signatures are valid. Keep nonces unique per call (`fakeNonceInserter` should accept any signature once).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestVerifier_Invalidate -v`
Expected: FAIL — `v.Invalidate undefined` (compile error).

- [ ] **Step 3: Implement `Invalidate`**

Add to `internal/auth/hmac.go` after `secretFor`:

```go
// Invalidate evicts the cached decrypted secret for deviceID, forcing the next
// Verify to re-open the stored (possibly rotated) sealed secret from the DB.
// Called after a device's secret is rotated so the stale secret stops
// authenticating.
func (v *Verifier) Invalidate(deviceID string) {
	v.mu.Lock()
	delete(v.cache, deviceID)
	v.mu.Unlock()
}
```

Also update the `Verifier` type doc comment at `hmac.go:40-42` — replace "populate-only in Plan 04 — secrets never rotate here" with a note that entries are evicted via `Invalidate` on rotation.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run TestVerifier_Invalidate -race -v`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/auth && golangci-lint run && go test ./internal/auth/ -race`
Expected: build/vet clean, `gofmt -l` prints nothing, lint 0 issues, tests PASS.

```bash
git add internal/auth/hmac.go internal/auth/hmac_test.go
git commit -m "feat(auth): add Verifier.Invalidate to evict rotated device secrets"
```

---

### Task 2: `adminMiddleware` role gate

**Files:**
- Modify: `internal/server/api/authmw.go`
- Test: `internal/server/api/authmw_test.go`

**Interfaces:**
- Consumes: existing `UserFrom(ctx context.Context) store.User`, `huma.WriteErr`.
- Produces: `func adminMiddleware(api huma.API) func(huma.Context, func(huma.Context))` — returns 403 unless `UserFrom(ctx.Context()).Role == "admin"`. MUST run after `sessionMiddleware` (reads the user set by it).

- [ ] **Step 1: Write the failing test**

Add to `internal/server/api/authmw_test.go`. Follow the existing middleware-test style in that file (it already tests `csrfMiddleware` etc. against a huma test API). Register a tiny GET op guarded by `sessionMiddleware` + `adminMiddleware`, then drive it with an admin session (expect 200) and a non-admin session (expect 403). Reuse whatever session-seeding helper the file already has for `sessionMiddleware` tests; if it seeds a user via a fake `SessionManager`/store, set `Role` accordingly.

```go
func TestAdminMiddleware_ForbidsNonAdmin(t *testing.T) {
	// newAuthTestAPI is the existing helper pattern in this file that returns a
	// humatest API plus a way to seed a valid session cookie for a store.User.
	// If its signature differs, adapt — the assertions below are the contract.
	deps, seedSession := newSessionTestDeps(t) // admin + user rows, session cookie factory

	a, _ := humatest.New(t)
	huma.Register(a, huma.Operation{
		Method: http.MethodGet,
		Path:   "/admin/ping",
		Middlewares: huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			adminMiddleware(a),
		},
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body struct{ OK bool } }, error) {
		out := &struct{ Body struct{ OK bool } }{}
		out.Body.OK = true
		return out, nil
	})

	// Admin → 200
	adminCookie := seedSession(t, "admin")
	if resp := a.Get("/admin/ping", "Cookie: "+adminCookie); resp.Code != http.StatusOK {
		t.Fatalf("admin: got %d, want 200", resp.Code)
	}
	// Regular user → 403
	userCookie := seedSession(t, "user")
	if resp := a.Get("/admin/ping", "Cookie: "+userCookie); resp.Code != http.StatusForbidden {
		t.Fatalf("user: got %d, want 403", resp.Code)
	}
}
```

> Note: match the file's actual test harness. If the existing session tests use a real in-memory store (`testdb`) + `auth.NewSessionManager` + a created session, do the same and set the user's `Role` to `"admin"`/`"user"`. The behavioral contract (admin→200, user→403) is what matters.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/api/ -run TestAdminMiddleware -v`
Expected: FAIL — `adminMiddleware undefined`.

- [ ] **Step 3: Implement `adminMiddleware`**

Add to `internal/server/api/authmw.go` after `csrfMiddleware`:

```go
// adminMiddleware rejects the request with 403 unless the session-authenticated
// user has the "admin" role. It MUST run after sessionMiddleware in the chain,
// since it reads the user from context.
func adminMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if UserFrom(ctx.Context()).Role != "admin" {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "admin role required")
			return
		}
		next(ctx)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/api/ -run TestAdminMiddleware -race -v`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/server/api && golangci-lint run && go test ./internal/server/api/ -race`
Expected: all clean/PASS.

```bash
git add internal/server/api/authmw.go internal/server/api/authmw_test.go
git commit -m "feat(api): add adminMiddleware role gate for admin operations"
```

---

### Task 3: `DeviceService` owner-scoped mutation methods

**Files:**
- Modify: `internal/server/service/device.go`
- Modify: `internal/server/server.go` (update `NewDeviceService` call)
- Test: `internal/server/service/device_test.go`

**Interfaces:**
- Consumes: `store.DeviceRepo` (`Rename`, `SetDisabled`, `Delete`, `RotateSecret`, `GetByID`), `store.IPHistoryRepo.Page`, `auth.GenerateSecret`, `auth.SealSecret`, `AuditSink`, and the `SecretCacheInvalidator` satisfied by `*auth.Verifier.Invalidate` (T1).
- Produces (later tasks rely on these exact signatures):
  - `type SecretCacheInvalidator interface { Invalidate(deviceID string) }`
  - `func NewDeviceService(st *store.Store, key []byte, invalidator SecretCacheInvalidator, audit AuditSink) *DeviceService`
  - `func (s *DeviceService) Rename(ctx context.Context, userID, id, newLabel string) (store.Device, error)`
  - `func (s *DeviceService) SetEnabled(ctx context.Context, userID, id string, disabled bool) (store.Device, error)`
  - `func (s *DeviceService) Delete(ctx context.Context, userID, id string) error`
  - `func (s *DeviceService) RotateSecret(ctx context.Context, userID, id string) ([]byte, error)` — returns the fresh plaintext secret (base64-encode at the API layer).
  - `func (s *DeviceService) History(ctx context.Context, userID, id, cursor string, limit int) (store.HistoryPage, error)`
  - All resolve ownership first; foreign owner → `store.ErrNotFound`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/server/service/device_test.go`. The file already has a `DeviceService` test harness (from the existing `List`/`Get` tests) using an in-memory store — reuse its setup helper (a `newDeviceServiceTest(t)` or equivalent that returns a store + seeded user + service). Because the constructor signature changes, update the harness to build the service with the new args (a real `*auth.Verifier` as the invalidator, or a tiny fake). Use a fake invalidator to assert eviction is called:

```go
type fakeInvalidator struct{ called []string }

func (f *fakeInvalidator) Invalidate(id string) { f.called = append(f.called, id) }

func TestDeviceService_Rename_OwnerScoped(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t) // build svc with new ctor
	dev := seedDevice(t, st, userID, "old-label")

	got, err := svc.Rename(context.Background(), userID, dev.ID, "new-label")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "new-label" {
		t.Fatalf("label = %q, want new-label", got.Label)
	}

	// Foreign owner → ErrNotFound.
	if _, err := svc.Rename(context.Background(), "someone-else", dev.ID, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign rename err = %v, want ErrNotFound", err)
	}
}

func TestDeviceService_Rename_ConflictSurfaces(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
	seedDevice(t, st, userID, "taken")
	dev := seedDevice(t, st, userID, "other")
	if _, err := svc.Rename(context.Background(), userID, dev.ID, "taken"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestDeviceService_SetEnabled_TogglesDisabled(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	got, err := svc.SetEnabled(context.Background(), userID, dev.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Fatal("expected Disabled=true")
	}
}

func TestDeviceService_Delete_OwnerScoped(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	if err := svc.Delete(context.Background(), "not-owner", dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign delete err = %v, want ErrNotFound", err)
	}
	if err := svc.Delete(context.Background(), userID, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Devices().GetByID(context.Background(), dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device still present after delete: %v", err)
	}
}

func TestDeviceService_RotateSecret_ReSealsAndEvicts(t *testing.T) {
	st, userID, svc, inv := newDeviceServiceTest(t) // inv is *fakeInvalidator
	dev := seedDevice(t, st, userID, "d")
	before, err := st.Devices().GetByID(context.Background(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := svc.RotateSecret(context.Background(), userID, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("expected a plaintext secret")
	}
	after, err := st.Devices().GetByID(context.Background(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SecretHash == before.SecretHash {
		t.Fatal("expected SecretHash to change after rotate")
	}
	if len(inv.called) != 1 || inv.called[0] != dev.ID {
		t.Fatalf("Invalidate calls = %v, want [%s]", inv.called, dev.ID)
	}
	// Foreign owner cannot rotate.
	if _, err := svc.RotateSecret(context.Background(), "nope", dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign rotate err = %v, want ErrNotFound", err)
	}
}

func TestDeviceService_History_Paginates(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	for i := 0; i < 3; i++ {
		if _, err := st.IPHistory().Append(context.Background(), store.IPHistory{DeviceID: dev.ID, IPv4: "203.0.113.1", ObservedAt: int64(1000 + i)}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.History(context.Background(), userID, dev.ID, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.NextCursor == "" {
		t.Fatalf("page = %d rows, cursor %q; want 2 rows + cursor", len(page.Rows), page.NextCursor)
	}
	// Foreign owner → ErrNotFound (never leaks another user's history).
	if _, err := svc.History(context.Background(), "intruder", dev.ID, "", 2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign history err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/service/ -run TestDeviceService_ -v`
Expected: FAIL — new methods / constructor args undefined.

- [ ] **Step 3: Implement the service changes**

Rewrite `internal/server/service/device.go`:

```go
package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// SecretCacheInvalidator evicts a device's cached HMAC secret so a rotated
// secret takes effect immediately. Satisfied by *auth.Verifier.
type SecretCacheInvalidator interface {
	Invalidate(deviceID string)
}

// DeviceService provides owner-scoped device read and management operations. A
// device owned by a different user is always reported as store.ErrNotFound, so
// callers cannot distinguish "not yours" from "doesn't exist".
type DeviceService struct {
	st          *store.Store
	key         []byte
	invalidator SecretCacheInvalidator
	audit       AuditSink
}

// NewDeviceService constructs a DeviceService. key is the 32-byte AEAD key used
// to seal rotated device secrets (see auth.SealSecret); invalidator evicts the
// HMAC verifier's secret cache on rotation; audit records lifecycle events.
func NewDeviceService(st *store.Store, key []byte, invalidator SecretCacheInvalidator, audit AuditSink) *DeviceService {
	return &DeviceService{st: st, key: key, invalidator: invalidator, audit: audit}
}

// List returns all devices belonging to userID.
func (s *DeviceService) List(ctx context.Context, userID string) ([]store.Device, error) {
	devices, err := s.st.Devices().ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.List: %w", err)
	}
	return devices, nil
}

// Get returns the device identified by id, but only if it belongs to userID.
func (s *DeviceService) Get(ctx context.Context, userID, id string) (store.Device, error) {
	dev, err := s.ownedDevice(ctx, userID, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Get: %w", err)
	}
	return dev, nil
}

// ownedDevice fetches id and confirms it belongs to userID, returning
// store.ErrNotFound if it does not exist or is owned by someone else.
func (s *DeviceService) ownedDevice(ctx context.Context, userID, id string) (store.Device, error) {
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, err
	}
	if dev.UserID != userID {
		return store.Device{}, store.ErrNotFound
	}
	return dev, nil
}

// Rename changes a device's label. Returns store.ErrNotFound for a foreign or
// missing device, store.ErrConflict if the new label is already used.
func (s *DeviceService) Rename(ctx context.Context, userID, id, newLabel string) (store.Device, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	if err := s.st.Devices().Rename(ctx, id, newLabel); err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.renamed", TargetType: "device", TargetID: id,
	})
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	return dev, nil
}

// SetEnabled toggles a device's disabled flag.
func (s *DeviceService) SetEnabled(ctx context.Context, userID, id string, disabled bool) (store.Device, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	if err := s.st.Devices().SetDisabled(ctx, id, disabled); err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	event := "device.enabled"
	if disabled {
		event = "device.disabled"
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: event, TargetType: "device", TargetID: id,
	})
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	return dev, nil
}

// Delete removes a device (its ip_history cascades; a consumed enrollment code
// survives with a nulled device_id, per the schema FKs).
func (s *DeviceService) Delete(ctx context.Context, userID, id string) error {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	if err := s.st.Devices().Delete(ctx, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.deleted", TargetType: "device", TargetID: id,
	})
	return nil
}

// RotateSecret mints a fresh HMAC secret, re-seals it into the device row,
// evicts the verifier's cached secret, and returns the new plaintext secret —
// shown to the caller exactly once and never persisted or logged in the clear.
func (s *DeviceService) RotateSecret(ctx context.Context, userID, id string) ([]byte, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	sealed, err := auth.SealSecret(s.key, secret)
	if err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	if err := s.st.Devices().RotateSecret(ctx, id, sealed); err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	s.invalidator.Invalidate(id)
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.secret.rotated", TargetType: "device", TargetID: id,
	})
	return secret, nil
}

// History returns a cursor-paginated page of a device's IP history.
func (s *DeviceService) History(ctx context.Context, userID, id, cursor string, limit int) (store.HistoryPage, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return store.HistoryPage{}, fmt.Errorf("service.History: %w", err)
	}
	page, err := s.st.IPHistory().Page(ctx, id, cursor, limit)
	if err != nil {
		return store.HistoryPage{}, fmt.Errorf("service.History: %w", err)
	}
	return page, nil
}
```

Update the call site in `internal/server/server.go` (currently `Devices: service.NewDeviceService(st),` at line ~86). `key`, `verifier`, and `audit` are already in scope in `handler`:

```go
		Devices:   service.NewDeviceService(st, key, verifier, audit),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/service/ -run TestDeviceService_ -race -v`
Expected: PASS. Also `go build ./...` (server.go call site compiles).

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/server && golangci-lint run && go test ./... -race`
Expected: all clean/PASS.

```bash
git add internal/server/service/device.go internal/server/service/device_test.go internal/server/server.go
git commit -m "feat(service): add owner-scoped device rename/enable/delete/rotate/history"
```

---

### Task 4: Device-management huma ops

**Files:**
- Modify: `internal/server/api/devices.go`
- Modify: `internal/server/api/api.go` (call `registerDeviceMgmtOps` in `Build`)
- Test: `internal/server/api/devices_manage_test.go`

**Interfaces:**
- Consumes: `DeviceService.Rename`/`SetEnabled`/`Delete`/`RotateSecret`/`History` (T3); `sessionMiddleware`, `csrfMiddleware`; `newDeviceView`, `deviceView`.
- Produces: `func registerDeviceMgmtOps(a huma.API, deps ServerDeps)`; the four ops from design §3 registered on `apiAPI`.

- [ ] **Step 1: Write the failing op tests**

Create `internal/server/api/devices_manage_test.go`. Use the file's existing op-test harness (the same one `devices_test.go` uses to build an API with a real in-memory store, a session cookie, and a CSRF token — reuse it exactly). Cover the auth matrix + behavior. Representative cases:

```go
func TestPatchDevice_RenamesWithCSRF(t *testing.T) {
	h := newDeviceAPITest(t)             // existing helper: API + store + session/csrf factory
	dev := h.seedDevice(t, "old")
	resp := h.patch(t, "/api/v1/devices/"+dev.ID, `{"label":"new"}`, h.withSessionAndCSRF())
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.Code, resp.Body)
	}
	// body reflects the new label
	if !strings.Contains(resp.Body.String(), `"label":"new"`) {
		t.Fatalf("body missing new label: %s", resp.Body.String())
	}
}

func TestPatchDevice_MissingCSRF_Forbidden(t *testing.T) {
	h := newDeviceAPITest(t)
	dev := h.seedDevice(t, "old")
	resp := h.patch(t, "/api/v1/devices/"+dev.ID, `{"label":"new"}`, h.withSessionOnly())
	if resp.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.Code)
	}
}

func TestPatchDevice_NoSession_Unauthorized(t *testing.T) {
	h := newDeviceAPITest(t)
	dev := h.seedDevice(t, "old")
	resp := h.patch(t, "/api/v1/devices/"+dev.ID, `{"label":"new"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.Code)
	}
}

func TestPatchDevice_ForeignDevice_NotFound(t *testing.T) {
	h := newDeviceAPITest(t)
	other := h.seedDeviceForUser(t, "other-user", "d")
	resp := h.patch(t, "/api/v1/devices/"+other.ID, `{"label":"x"}`, h.withSessionAndCSRF())
	if resp.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.Code)
	}
}

func TestDeleteDevice_RemovesDevice(t *testing.T) {
	h := newDeviceAPITest(t)
	dev := h.seedDevice(t, "d")
	resp := h.delete(t, "/api/v1/devices/"+dev.ID, h.withSessionAndCSRF())
	if resp.Code != http.StatusNoContent {
		t.Fatalf("got %d, want 204", resp.Code)
	}
}

func TestRotateSecret_ReturnsSecretOnce(t *testing.T) {
	h := newDeviceAPITest(t)
	dev := h.seedDevice(t, "d")
	resp := h.post(t, "/api/v1/devices/"+dev.ID+"/rotate-secret", ``, h.withSessionAndCSRF())
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.Code, resp.Body)
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(body.Secret); err != nil || body.Secret == "" {
		t.Fatalf("secret not valid base64: %q (%v)", body.Secret, err)
	}
}

func TestDeviceHistory_Paginated(t *testing.T) {
	h := newDeviceAPITest(t)
	dev := h.seedDevice(t, "d")
	h.seedHistory(t, dev.ID, 3)
	resp := h.get(t, "/api/v1/devices/"+dev.ID+"/history?limit=2", h.withSessionOnly())
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.Code)
	}
	var body struct {
		Rows       []map[string]any `json:"rows"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Rows) != 2 || body.NextCursor == "" {
		t.Fatalf("rows=%d cursor=%q, want 2 + cursor", len(body.Rows), body.NextCursor)
	}
}
```

> If `newDeviceAPITest`'s exact helper names differ, adapt to the real harness in `devices_test.go` — but keep the status-code and body contracts above.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/api/ -run 'TestPatchDevice|TestDeleteDevice|TestRotateSecret|TestDeviceHistory' -v`
Expected: FAIL — routes 404 / helpers undefined.

- [ ] **Step 3: Implement the ops + DTOs**

Append to `internal/server/api/devices.go` (add `encoding/base64` to imports). DTOs:

```go
// patchDeviceInput is the body of PATCH /api/v1/devices/{id}. Both fields are
// optional: a nil pointer means "leave unchanged", so disabling (Disabled=false)
// is distinguishable from "not supplied".
type patchDeviceInput struct {
	ID   string `path:"id"`
	Body struct {
		Label    *string `json:"label,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
	}
}

type deleteDeviceInput struct {
	ID string `path:"id"`
}

// deleteDeviceOutput carries no body; huma emits 204 via DefaultStatus.
type deleteDeviceOutput struct{}

type rotateSecretInput struct {
	ID string `path:"id"`
}

// rotateSecretResponse carries the fresh plaintext HMAC secret, base64-encoded
// (matching enroll.go's enrollResponse), shown to the caller exactly once.
type rotateSecretResponse struct {
	Secret string `json:"secret"`
}

type rotateSecretOutput struct {
	Body rotateSecretResponse
}

type historyInput struct {
	ID     string `path:"id"`
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type historyRow struct {
	ObservedAt    int64  `json:"observed_at"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	ClientVersion string `json:"client_version"`
}

type historyResponse struct {
	Rows       []historyRow `json:"rows"`
	NextCursor string       `json:"next_cursor"`
}

type historyOutput struct {
	Body historyResponse
}
```

Registration function:

```go
// registerDeviceMgmtOps registers the owner-scoped device management operations
// onto apiAPI: PATCH (rename / enable-disable), DELETE, POST rotate-secret (all
// mutating → session + CSRF), and GET history (session only). Ownership scoping
// (foreign device → 404) is enforced by service.DeviceService.
func registerDeviceMgmtOps(a huma.API, deps ServerDeps) {
	session := func() huma.Middlewares {
		return huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)}
	}
	sessionCSRF := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
		}
	}

	huma.Register(a, huma.Operation{
		Method:      http.MethodPatch,
		Path:        "/api/v1/devices/{id}",
		Middlewares: sessionCSRF(),
	}, func(ctx context.Context, in *patchDeviceInput) (*getDeviceOutput, error) {
		u := UserFrom(ctx)
		dev := store.Device{}
		var err error
		changed := false
		if in.Body.Label != nil {
			if *in.Body.Label == "" {
				return nil, huma.Error422UnprocessableEntity("label must not be empty")
			}
			dev, err = deps.Devices.Rename(ctx, u.ID, in.ID, *in.Body.Label)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "rename device", u.ID, in.ID, err)
			}
			changed = true
		}
		if in.Body.Disabled != nil {
			dev, err = deps.Devices.SetEnabled(ctx, u.ID, in.ID, *in.Body.Disabled)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "set device enabled", u.ID, in.ID, err)
			}
			changed = true
		}
		if !changed {
			// Nothing to change: return the current device (also enforces ownership).
			dev, err = deps.Devices.Get(ctx, u.ID, in.ID)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "get device", u.ID, in.ID, err)
			}
		}
		return &getDeviceOutput{Body: newDeviceView(dev)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodDelete,
		Path:          "/api/v1/devices/{id}",
		DefaultStatus: http.StatusNoContent,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *deleteDeviceInput) (*deleteDeviceOutput, error) {
		u := UserFrom(ctx)
		if err := deps.Devices.Delete(ctx, u.ID, in.ID); err != nil {
			return nil, deviceMgmtErr(ctx, deps, "delete device", u.ID, in.ID, err)
		}
		return &deleteDeviceOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/devices/{id}/rotate-secret",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *rotateSecretInput) (*rotateSecretOutput, error) {
		u := UserFrom(ctx)
		secret, err := deps.Devices.RotateSecret(ctx, u.ID, in.ID)
		if err != nil {
			return nil, deviceMgmtErr(ctx, deps, "rotate device secret", u.ID, in.ID, err)
		}
		return &rotateSecretOutput{Body: rotateSecretResponse{
			Secret: base64.StdEncoding.EncodeToString(secret),
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/devices/{id}/history",
		Middlewares: session(),
	}, func(ctx context.Context, in *historyInput) (*historyOutput, error) {
		u := UserFrom(ctx)
		page, err := deps.Devices.History(ctx, u.ID, in.ID, in.Cursor, in.Limit)
		if err != nil {
			return nil, deviceMgmtErr(ctx, deps, "get device history", u.ID, in.ID, err)
		}
		rows := make([]historyRow, len(page.Rows))
		for i, h := range page.Rows {
			rows[i] = historyRow{ObservedAt: h.ObservedAt, IPv4: h.IPv4, IPv6: h.IPv6, ClientVersion: h.ClientVersion}
		}
		return &historyOutput{Body: historyResponse{Rows: rows, NextCursor: page.NextCursor}}, nil
	})
}

// deviceMgmtErr maps a service error to the right huma response: ownership /
// missing → 404, label conflict → 409, everything else → logged 500.
func deviceMgmtErr(ctx context.Context, deps ServerDeps, action, userID, deviceID string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("device not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("a device with that label already exists")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed",
			slog.String("user_id", userID), slog.String("device_id", deviceID), slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
```

Wire it in `internal/server/api/api.go` `Build`, right after `registerDeviceOps(apiAPI, deps)`:

```go
	registerDeviceMgmtOps(apiAPI, deps)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -run 'TestPatchDevice|TestDeleteDevice|TestRotateSecret|TestDeviceHistory' -race -v`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/server/api && golangci-lint run && go test ./... -race`
Expected: all clean/PASS.

```bash
git add internal/server/api/devices.go internal/server/api/api.go internal/server/api/devices_manage_test.go
git commit -m "feat(api): add device PATCH/DELETE/rotate-secret/history endpoints"
```

---

### Task 5: `AdminService` — guarded user management + reads

**Files:**
- Create: `internal/server/service/admin.go`
- Modify: `internal/server/api/api.go` (add `ServerDeps.Admin` field)
- Modify: `internal/server/server.go` (construct + wire `AdminService`)
- Test: `internal/server/service/admin_test.go`

**Interfaces:**
- Consumes: `store` (`Users`, `Sessions`, `Devices`, `AuditLog`), `auth.HashPassword`/`Argon2Params`, `config.PasswordCfg`, `AuditSink`.
- Produces (T6 relies on these):
  - `func NewAdminService(st *store.Store, pw config.PasswordCfg, audit AuditSink) *AdminService`
  - `type CreateUserParams struct { Email, Password, Role string }`
  - `type UpdateUserParams struct { Role *string; Disabled *bool; Password *string }`
  - `func (s *AdminService) ListUsers(ctx) ([]store.User, error)`
  - `func (s *AdminService) CreateUser(ctx, actorID string, p CreateUserParams) (store.User, error)`
  - `func (s *AdminService) UpdateUser(ctx, actorID, targetID string, p UpdateUserParams) (store.User, error)`
  - `func (s *AdminService) DeleteUser(ctx, actorID, targetID string) error`
  - `func (s *AdminService) ListAllDevices(ctx) ([]store.Device, error)`
  - `func (s *AdminService) ListAudit(ctx, f store.AuditFilter, cursor string, limit int) (store.AuditPage, error)`
  - Sentinel errors: `ErrLastAdmin`, `ErrSelfLockout`, `ErrOIDCNoPassword`, `ErrInvalidRole` (each maps to 409/422 at the API layer).

- [ ] **Step 1: Write the failing tests**

Create `internal/server/service/admin_test.go`. Use the same in-memory store harness the other service tests use (e.g. `testStore(t)` / `store.OpenMemory` — mirror `enrollment_test.go`'s setup). Representative cases:

```go
func newAdminSvc(t *testing.T) (*store.Store, *AdminService) {
	st := testStore(t) // same helper the other service tests use
	pw := config.PasswordCfg{Argon2Time: 1, Argon2MemoryKiB: 8 * 1024, Argon2Parallelism: 1}
	return st, NewAdminService(st, pw, NewAuditWriter(st))
}

func seedUser(t *testing.T, st *store.Store, email, role string, disabled bool) store.User {
	t.Helper()
	u, err := st.Users().Create(context.Background(), store.User{Email: email, Role: role, PasswordHash: "$argon2id$v=19$m=8192,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$" + "0000000000000000000000000000000000000000000", Disabled: disabled})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAdminService_CreateUser_HashesPassword(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	u, err := svc.CreateUser(context.Background(), admin.ID, CreateUserParams{Email: "new@x", Password: "correcthorse12", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "" || u.PasswordHash == "correcthorse12" {
		t.Fatal("password not hashed")
	}
	ok, _ := auth.VerifyPassword(u.PasswordHash, "correcthorse12")
	if !ok {
		t.Fatal("hash does not verify")
	}
}

func TestAdminService_CreateUser_RejectsBadRole(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	if _, err := svc.CreateUser(context.Background(), admin.ID, CreateUserParams{Email: "n@x", Password: "correcthorse12", Role: "superuser"}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("err = %v, want ErrInvalidRole", err)
	}
}

func TestAdminService_UpdateUser_LastAdminDemote_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	other := seedUser(t, st, "b@x", "user", false)
	role := "user"
	if _, err := svc.UpdateUser(context.Background(), other.ID, admin.ID, UpdateUserParams{Role: &role}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminService_UpdateUser_SelfDisable_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	seedUser(t, st, "b@x", "admin", false) // a second admin so last-admin guard is not what fires
	dis := true
	if _, err := svc.UpdateUser(context.Background(), admin.ID, admin.ID, UpdateUserParams{Disabled: &dis}); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self-disable err = %v, want ErrSelfLockout", err)
	}
}

func TestAdminService_UpdateUser_DisableRevokesSessions(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	target := seedUser(t, st, "b@x", "user", false)
	if _, err := st.Sessions().Create(context.Background(), store.Session{UserID: target.ID, CSRFToken: "c", ExpiresAt: store.NowUnix() + 3600}); err != nil {
		t.Fatal(err)
	}
	dis := true
	if _, err := svc.UpdateUser(context.Background(), admin.ID, target.ID, UpdateUserParams{Disabled: &dis}); err != nil {
		t.Fatal(err)
	}
	// The target's sessions are gone.
	n, err := st.Sessions().DeleteByUser(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 remaining sessions, DeleteByUser removed %d more", n)
	}
}

func TestAdminService_UpdateUser_PasswordOnOIDCOnly_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	// OIDC-only user: no password hash.
	oidcUser, err := st.Users().Create(context.Background(), store.User{Email: "o@x", Role: "user", OIDCProvider: "https://idp", OIDCSubject: "sub1"})
	if err != nil {
		t.Fatal(err)
	}
	pwNew := "correcthorse12"
	if _, err := svc.UpdateUser(context.Background(), admin.ID, oidcUser.ID, UpdateUserParams{Password: &pwNew}); !errors.Is(err, ErrOIDCNoPassword) {
		t.Fatalf("err = %v, want ErrOIDCNoPassword", err)
	}
}

func TestAdminService_DeleteUser_LastAdmin_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	other := seedUser(t, st, "b@x", "user", false)
	if err := svc.DeleteUser(context.Background(), other.ID, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminService_DeleteUser_Self_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin", false)
	seedUser(t, st, "b@x", "admin", false)
	if err := svc.DeleteUser(context.Background(), admin.ID, admin.ID); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self-delete err = %v, want ErrSelfLockout", err)
	}
}
```

> Adapt `testStore`/`seedUser` to the real helpers. The `seedUser` password-hash literal just needs to be non-empty for the "has a local password" branch; use `auth.HashPassword` if you prefer a real hash.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/service/ -run TestAdminService_ -v`
Expected: FAIL — `AdminService` undefined.

- [ ] **Step 3: Implement `AdminService`**

Create `internal/server/service/admin.go`:

```go
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// Guard sentinels — mapped to HTTP 409/422 by the API layer.
var (
	// ErrLastAdmin is returned when an operation would leave zero enabled admins.
	ErrLastAdmin = errors.New("service: cannot remove the last admin")
	// ErrSelfLockout is returned when an admin tries to disable or delete themselves.
	ErrSelfLockout = errors.New("service: cannot disable or delete your own account")
	// ErrOIDCNoPassword is returned when setting a local password on an OIDC-only account.
	ErrOIDCNoPassword = errors.New("service: user is OIDC-managed; no local password")
	// ErrInvalidRole is returned for a role outside {admin, user}.
	ErrInvalidRole = errors.New("service: invalid role")
)

// CreateUserParams is the input to CreateUser. Role must be "admin" or "user".
type CreateUserParams struct {
	Email    string
	Password string
	Role     string
}

// UpdateUserParams is the partial-update input to UpdateUser. A nil field is
// left unchanged.
type UpdateUserParams struct {
	Role     *string
	Disabled *bool
	Password *string
}

// AdminService implements admin-only user management (with lockout guards),
// plus cross-user device and audit reads.
type AdminService struct {
	st           *store.Store
	argon2Params auth.Argon2Params
	audit        AuditSink
}

// NewAdminService constructs an AdminService. pw supplies the argon2id params
// used when creating users or resetting passwords.
func NewAdminService(st *store.Store, pw config.PasswordCfg, audit AuditSink) *AdminService {
	return &AdminService{
		st:           st,
		argon2Params: auth.Argon2Params{Time: pw.Argon2Time, MemoryKiB: pw.Argon2MemoryKiB, Parallelism: pw.Argon2Parallelism},
		audit:        audit,
	}
}

func validRole(r string) bool { return r == "admin" || r == "user" }

// enabledAdminCount returns how many enabled admins exist, and whether target
// is currently one of them.
func (s *AdminService) enabledAdminCount(ctx context.Context, targetID string) (count int, targetIsEnabledAdmin bool, err error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return 0, false, err
	}
	for _, u := range users {
		if u.Role == "admin" && !u.Disabled {
			count++
			if u.ID == targetID {
				targetIsEnabledAdmin = true
			}
		}
	}
	return count, targetIsEnabledAdmin, nil
}

// ListUsers returns all users ordered by email.
func (s *AdminService) ListUsers(ctx context.Context) ([]store.User, error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListUsers: %w", err)
	}
	return users, nil
}

// CreateUser creates a local user with a hashed password.
func (s *AdminService) CreateUser(ctx context.Context, actorID string, p CreateUserParams) (store.User, error) {
	if !validRole(p.Role) {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", ErrInvalidRole)
	}
	hash, err := auth.HashPassword(p.Password, s.argon2Params)
	if err != nil {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", err)
	}
	u, err := s.st.Users().Create(ctx, store.User{Email: p.Email, PasswordHash: hash, Role: p.Role})
	if err != nil {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", err) // ErrConflict flows up
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.created", TargetType: "user", TargetID: u.ID})
	return u, nil
}

// UpdateUser applies a partial update (role / disabled / password) with lockout
// guards. Disabling a user also revokes their active sessions.
func (s *AdminService) UpdateUser(ctx context.Context, actorID, targetID string, p UpdateUserParams) (store.User, error) {
	u, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err) // ErrNotFound flows up
	}

	// Guard: demoting the last enabled admin.
	if p.Role != nil {
		if !validRole(*p.Role) {
			return store.User{}, fmt.Errorf("service.UpdateUser: %w", ErrInvalidRole)
		}
		if *p.Role != "admin" {
			if err := s.guardLastAdmin(ctx, targetID); err != nil {
				return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
			}
		}
	}
	// Guard: disabling self, or disabling the last enabled admin.
	if p.Disabled != nil && *p.Disabled {
		if targetID == actorID {
			return store.User{}, fmt.Errorf("service.UpdateUser: %w", ErrSelfLockout)
		}
		if err := s.guardLastAdmin(ctx, targetID); err != nil {
			return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
		}
	}
	// Guard: password reset only on accounts that already have a local password.
	if p.Password != nil && u.PasswordHash == "" {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", ErrOIDCNoPassword)
	}

	// Apply role and/or password via Update (writes all mutable columns).
	if p.Role != nil || p.Password != nil {
		if p.Role != nil {
			u.Role = *p.Role
		}
		if p.Password != nil {
			hash, err := auth.HashPassword(*p.Password, s.argon2Params)
			if err != nil {
				return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
			}
			u.PasswordHash = hash
		}
		if err := s.st.Users().Update(ctx, u); err != nil {
			return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
		}
		if p.Role != nil {
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.role_change", TargetType: "user", TargetID: targetID})
		}
		if p.Password != nil {
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.password_change", TargetType: "user", TargetID: targetID})
		}
	}

	// Apply disabled via SetDisabled; on disable, revoke sessions.
	if p.Disabled != nil {
		if err := s.st.Users().SetDisabled(ctx, targetID, *p.Disabled); err != nil {
			return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
		}
		event := "user.enabled"
		if *p.Disabled {
			event = "user.disabled"
			if n, _ := s.st.Sessions().DeleteByUser(ctx, targetID); n > 0 {
				s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "session.revoked", TargetType: "user", TargetID: targetID})
			}
		}
		s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: event, TargetType: "user", TargetID: targetID})
	}

	updated, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}
	return updated, nil
}

// DeleteUser deletes a user (cascading sessions + devices + codes via FK), with
// last-admin and self-lockout guards.
func (s *AdminService) DeleteUser(ctx context.Context, actorID, targetID string) error {
	if targetID == actorID {
		return fmt.Errorf("service.DeleteUser: %w", ErrSelfLockout)
	}
	if err := s.guardLastAdmin(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err)
	}
	if err := s.st.Users().Delete(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err) // ErrNotFound flows up
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.deleted", TargetType: "user", TargetID: targetID})
	return nil
}

// guardLastAdmin returns ErrLastAdmin if targetID is currently the only enabled
// admin (so removing/demoting/disabling it would lock everyone out).
func (s *AdminService) guardLastAdmin(ctx context.Context, targetID string) error {
	count, targetIsEnabledAdmin, err := s.enabledAdminCount(ctx, targetID)
	if err != nil {
		return err
	}
	if targetIsEnabledAdmin && count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// ListAllDevices returns every device across all users (admin view).
func (s *AdminService) ListAllDevices(ctx context.Context) ([]store.Device, error) {
	devices, err := s.st.Devices().ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListAllDevices: %w", err)
	}
	return devices, nil
}

// ListAudit returns a cursor-paginated page of audit-log entries.
func (s *AdminService) ListAudit(ctx context.Context, f store.AuditFilter, cursor string, limit int) (store.AuditPage, error) {
	page, err := s.st.AuditLog().ListPaginated(ctx, f, cursor, limit)
	if err != nil {
		return store.AuditPage{}, fmt.Errorf("service.ListAudit: %w", err)
	}
	return page, nil
}
```

Add the `Admin` field to `ServerDeps` in `internal/server/api/api.go`:

```go
	Devices   *service.DeviceService
	Admin     *service.AdminService
```

Wire it in `internal/server/server.go` inside `api.Build(mux, api.ServerDeps{...})`:

```go
		Devices:   service.NewDeviceService(st, key, verifier, audit),
		Admin:     service.NewAdminService(st, cfg.Auth.Password, audit),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/service/ -run TestAdminService_ -race -v`
Expected: PASS. Also `go build ./...`.

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/server && golangci-lint run && go test ./... -race`
Expected: all clean/PASS.

```bash
git add internal/server/service/admin.go internal/server/service/admin_test.go internal/server/api/api.go internal/server/server.go
git commit -m "feat(service): add AdminService with user-management lockout guards"
```

---

### Task 6: Admin huma ops + wiring

**Files:**
- Create: `internal/server/api/admin.go`
- Modify: `internal/server/api/api.go` (call `registerAdminOps` in `Build`)
- Test: `internal/server/api/admin_test.go`

**Interfaces:**
- Consumes: `AdminService` (T5) via `deps.Admin`; `adminMiddleware` (T2); `sessionMiddleware`/`csrfMiddleware`; `deps.Cfg` (`config.Auth`), `deps.Info` (`version.Info`); `newDeviceView`.
- Produces: `func registerAdminOps(a huma.API, deps ServerDeps)` — the seven admin ops from design §3.

- [ ] **Step 1: Write the failing op tests**

Create `internal/server/api/admin_test.go`. Reuse the API test harness (real store, session cookie + CSRF factory) — but seed both an **admin** and a **regular user** so you can assert the 403 gate. Representative cases:

```go
func TestAdminListUsers_RequiresAdmin(t *testing.T) {
	h := newAdminAPITest(t) // API + store; admin + user session factories

	// Non-admin → 403
	if resp := h.get(t, "/api/v1/admin/users", h.userSession()); resp.Code != http.StatusForbidden {
		t.Fatalf("user: got %d, want 403", resp.Code)
	}
	// Admin → 200
	if resp := h.get(t, "/api/v1/admin/users", h.adminSession()); resp.Code != http.StatusOK {
		t.Fatalf("admin: got %d, want 200", resp.Code)
	}
	// No session → 401
	if resp := h.get(t, "/api/v1/admin/users", nil); resp.Code != http.StatusUnauthorized {
		t.Fatalf("anon: got %d, want 401", resp.Code)
	}
}

func TestAdminCreateUser_RequiresCSRF(t *testing.T) {
	h := newAdminAPITest(t)
	// Admin session but no CSRF → 403
	if resp := h.post(t, "/api/v1/admin/users", `{"email":"n@x","password":"correcthorse12","role":"user"}`, h.adminSessionNoCSRF()); resp.Code != http.StatusForbidden {
		t.Fatalf("no csrf: got %d, want 403", resp.Code)
	}
	// Admin + CSRF → 200
	if resp := h.post(t, "/api/v1/admin/users", `{"email":"n2@x","password":"correcthorse12","role":"user"}`, h.adminSessionCSRF()); resp.Code != http.StatusOK {
		t.Fatalf("with csrf: got %d, want 200: %s", resp.Code, resp.Body)
	}
}

func TestAdminUpdateUser_LastAdmin_Conflict(t *testing.T) {
	h := newAdminAPITest(t)
	// Demoting the only admin → 409 (guard surfaced).
	resp := h.patch(t, "/api/v1/admin/users/"+h.adminID(), `{"role":"user"}`, h.adminSessionCSRF())
	if resp.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409", resp.Code)
	}
}

func TestAdminServer_OmitsClientSecret(t *testing.T) {
	h := newAdminAPITest(t)
	resp := h.get(t, "/api/v1/admin/server", h.adminSession())
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.Code)
	}
	if strings.Contains(resp.Body.String(), "client_secret") {
		t.Fatalf("server info leaked client_secret: %s", resp.Body.String())
	}
}

func TestAdminAudit_Paginated(t *testing.T) {
	h := newAdminAPITest(t)
	h.seedAudit(t, 3) // append 3 audit rows
	resp := h.get(t, "/api/v1/admin/audit?limit=2", h.adminSession())
	if resp.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.Code)
	}
	var body struct {
		Rows       []map[string]any `json:"rows"`
		NextCursor string           `json:"next_cursor"`
	}
	_ = json.Unmarshal(resp.Body.Bytes(), &body)
	if len(body.Rows) != 2 || body.NextCursor == "" {
		t.Fatalf("rows=%d cursor=%q, want 2 + cursor", len(body.Rows), body.NextCursor)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/api/ -run TestAdmin -v`
Expected: FAIL — routes 404 / helpers undefined.

- [ ] **Step 3: Implement the admin ops + DTOs**

Create `internal/server/api/admin.go`:

```go
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// ---- user DTOs ----

type adminUserView struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	OIDCOnly  bool   `json:"oidc_only"` // true = no local password (OIDC-managed)
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func newAdminUserView(u store.User) adminUserView {
	return adminUserView{
		ID: u.ID, Email: u.Email, Role: u.Role, Disabled: u.Disabled,
		OIDCOnly: u.PasswordHash == "", CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

type listUsersOutput struct{ Body []adminUserView }

type createUserInput struct {
	Body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
}
type createUserOutput struct{ Body adminUserView }

type updateUserInput struct {
	ID   string `path:"id"`
	Body struct {
		Role     *string `json:"role,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
		Password *string `json:"password,omitempty"`
	}
}
type updateUserOutput struct{ Body adminUserView }

type deleteUserInput struct {
	ID string `path:"id"`
}
type deleteUserOutput struct{}

// ---- admin devices DTO (adds user_id to the non-secret device view) ----

type adminDeviceView struct {
	deviceView
	UserID string `json:"user_id"`
}
type listAllDevicesOutput struct{ Body []adminDeviceView }

// ---- audit DTOs ----

type auditInput struct {
	ActorUserID string `query:"actor_user_id"`
	EventType   string `query:"event_type"`
	Since       int64  `query:"since"`
	Until       int64  `query:"until"`
	Cursor      string `query:"cursor"`
	Limit       int    `query:"limit"`
}
type auditRow struct {
	ID          int64  `json:"id"`
	ActorUserID string `json:"actor_user_id"`
	EventType   string `json:"event_type"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	IP          string `json:"ip"`
	CreatedAt   int64  `json:"created_at"`
}
type auditResponse struct {
	Rows       []auditRow `json:"rows"`
	NextCursor string     `json:"next_cursor"`
}
type auditOutput struct{ Body auditResponse }

// ---- server-info DTO ----

type serverInfoOIDC struct {
	Enabled         bool     `json:"enabled"`
	Required        bool     `json:"required"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	Scopes          []string `json:"scopes"`
	AutoLinkByEmail bool     `json:"auto_link_by_email"`
	AllowOIDCSignup bool     `json:"allow_oidc_signup"`
}
type serverInfoResponse struct {
	Version         string         `json:"version"`
	Commit          string         `json:"commit"`
	Date            string         `json:"date"`
	SkewWindowSecs  int64          `json:"skew_window_secs"`
	SessionCookie   string         `json:"session_cookie"`
	SessionSecure   bool           `json:"session_secure"`
	SessionSameSite string         `json:"session_samesite"`
	OIDC            serverInfoOIDC `json:"oidc"`
}
type serverInfoOutput struct{ Body serverInfoResponse }

// registerAdminOps registers the admin-role operations onto apiAPI. Every op is
// session + admin gated; mutations additionally require CSRF.
func registerAdminOps(a huma.API, deps ServerDeps) {
	adminRead := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			adminMiddleware(a),
		}
	}
	adminWrite := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			adminMiddleware(a),
			csrfMiddleware(a),
		}
	}

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/users", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*listUsersOutput, error) {
		users, err := deps.Admin.ListUsers(ctx)
		if err != nil {
			return nil, adminErr(ctx, deps, "list users", err)
		}
		views := make([]adminUserView, len(users))
		for i, u := range users {
			views[i] = newAdminUserView(u)
		}
		return &listUsersOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/users", DefaultStatus: http.StatusOK, Middlewares: adminWrite(),
	}, func(ctx context.Context, in *createUserInput) (*createUserOutput, error) {
		actor := UserFrom(ctx)
		u, err := deps.Admin.CreateUser(ctx, actor.ID, service.CreateUserParams{
			Email: in.Body.Email, Password: in.Body.Password, Role: in.Body.Role,
		})
		if err != nil {
			return nil, adminErr(ctx, deps, "create user", err)
		}
		return &createUserOutput{Body: newAdminUserView(u)}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPatch, Path: "/api/v1/admin/users/{id}", Middlewares: adminWrite(),
	}, func(ctx context.Context, in *updateUserInput) (*updateUserOutput, error) {
		actor := UserFrom(ctx)
		u, err := deps.Admin.UpdateUser(ctx, actor.ID, in.ID, service.UpdateUserParams{
			Role: in.Body.Role, Disabled: in.Body.Disabled, Password: in.Body.Password,
		})
		if err != nil {
			return nil, adminErr(ctx, deps, "update user", err)
		}
		return &updateUserOutput{Body: newAdminUserView(u)}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/admin/users/{id}", DefaultStatus: http.StatusNoContent, Middlewares: adminWrite(),
	}, func(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
		actor := UserFrom(ctx)
		if err := deps.Admin.DeleteUser(ctx, actor.ID, in.ID); err != nil {
			return nil, adminErr(ctx, deps, "delete user", err)
		}
		return &deleteUserOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/devices", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*listAllDevicesOutput, error) {
		devices, err := deps.Admin.ListAllDevices(ctx)
		if err != nil {
			return nil, adminErr(ctx, deps, "list all devices", err)
		}
		views := make([]adminDeviceView, len(devices))
		for i, d := range devices {
			views[i] = adminDeviceView{deviceView: newDeviceView(d), UserID: d.UserID}
		}
		return &listAllDevicesOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/audit", Middlewares: adminRead(),
	}, func(ctx context.Context, in *auditInput) (*auditOutput, error) {
		page, err := deps.Admin.ListAudit(ctx, store.AuditFilter{
			ActorUserID: in.ActorUserID, EventType: in.EventType, Since: in.Since, Until: in.Until,
		}, in.Cursor, in.Limit)
		if err != nil {
			return nil, adminErr(ctx, deps, "list audit", err)
		}
		rows := make([]auditRow, len(page.Rows))
		for i, e := range page.Rows {
			rows[i] = auditRow{
				ID: e.ID, ActorUserID: e.ActorUserID, EventType: e.EventType,
				TargetType: e.TargetType, TargetID: e.TargetID, IP: e.IP, CreatedAt: e.CreatedAt,
			}
		}
		return &auditOutput{Body: auditResponse{Rows: rows, NextCursor: page.NextCursor}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/server", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*serverInfoOutput, error) {
		oidc := deps.Cfg.OIDC
		sess := deps.Cfg.Session
		return &serverInfoOutput{Body: serverInfoResponse{
			Version:         deps.Info.Version,
			Commit:          deps.Info.Commit,
			Date:            deps.Info.Date,
			SkewWindowSecs:  int64(deps.Cfg.HMAC.SkewWindow.Seconds()),
			SessionCookie:   sess.CookieName,
			SessionSecure:   sess.CookieSecure,
			SessionSameSite: sess.CookieSameSite,
			OIDC: serverInfoOIDC{
				Enabled: oidc.Enabled, Required: oidc.Required, Issuer: oidc.Issuer,
				ClientID: oidc.ClientID, Scopes: oidc.Scopes,
				AutoLinkByEmail: oidc.AutoLinkByEmail, AllowOIDCSignup: oidc.AllowOIDCSignup,
			},
		}}, nil
	})
}

// adminErr maps an AdminService error to the right huma response.
func adminErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("user not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("a user with that email already exists")
	case errors.Is(err, service.ErrLastAdmin):
		return huma.Error409Conflict("cannot remove the last admin")
	case errors.Is(err, service.ErrSelfLockout):
		return huma.Error409Conflict("cannot disable or delete your own account")
	case errors.Is(err, service.ErrOIDCNoPassword):
		return huma.Error409Conflict("user is OIDC-managed; no local password")
	case errors.Is(err, service.ErrInvalidRole):
		return huma.Error422UnprocessableEntity("role must be 'admin' or 'user'")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
```

> Note: `adminDeviceView` embeds `deviceView`. huma/JSON flattens embedded structs, so the wire object carries all `deviceView` fields plus `user_id`. Verify the emitted JSON in the test (`TestAdminListDevices`) includes both `id` and `user_id`.

Wire it in `internal/server/api/api.go` `Build`, right after `registerDeviceMgmtOps(apiAPI, deps)`:

```go
	registerAdminOps(apiAPI, deps)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/api/ -run TestAdmin -race -v`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

Run: `go build ./... && go vet ./... && gofmt -l internal/server && golangci-lint run && go test ./... -race`
Expected: all clean/PASS.

```bash
git add internal/server/api/admin.go internal/server/api/api.go internal/server/api/admin_test.go
git commit -m "feat(api): add admin users/devices/audit/server endpoints"
```

---

## Final Verification (after all tasks)

Run the whole-module gate and confirm the new surface:

- [ ] `go build ./... && go vet ./... && gofmt -l . && golangci-lint run && go test ./... -race` — all clean/PASS.
- [ ] **Client isolation intact:** `go test ./cmd/diyddns-client/ -run TestClientDeps -race` passes and `git diff --stat origin/main -- cmd/diyddns-client go.mod go.sum` shows **no** changes (this plan adds no deps and does not touch the client).
- [ ] **OpenAPI surface:** start the server (or use the api test harness) and confirm the 11 new operations appear under `/api/openapi.json` and render at `/api/docs`. A quick check: `GET /api/openapi.json` body contains `"/api/v1/devices/{id}/rotate-secret"` and `"/api/v1/admin/users"`.
- [ ] Independent whole-branch review on the full diff from branch point (per the execution workflow), then `superpowers:finishing-a-development-branch`.

---

## Self-Review notes (author)

- **Spec coverage:** every design §3 endpoint maps to a task (device-mgmt → T4 over T3; admin → T6 over T5); the two new seams → T1/T2. `admin/server` payload matches the corrected design §5 (no retention/TLS). Deferred items (§9) are intentionally absent.
- **Type consistency:** `NewDeviceService(st, key, invalidator, audit)` is defined in T3 and called in T3's server.go edit; `SecretCacheInvalidator` (T3) is satisfied by `Verifier.Invalidate` (T1). `AdminService` params/sentinels defined in T5 are consumed by T6's `adminErr`/handlers. `ServerDeps.Admin` added in T5, read in T6.
- **No placeholders:** all steps carry real code and exact commands. Test-harness helper names (`newDeviceAPITest`, `newAdminAPITest`, `testStore`) must be matched to the actual helpers in the existing `*_test.go` files during implementation — flagged inline where they appear.
