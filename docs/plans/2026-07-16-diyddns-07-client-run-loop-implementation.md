# Plan 07 — `diyddns-client run` public-IP reporting loop — Implementation Plan

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

**Goal:** Add a `diyddns-client run` command that discovers the host's public IP from a quorum of independent lookup providers and HMAC-signs check-ins to `POST /agent/v1/checkin`, completing the enroll→report MVP.

**Architecture:** Three new client packages — `ipdiscovery` (2-of-N majority quorum per address family, family-locked dialers), `checkin` (HMAC-signed POST reusing `internal/shared`), `poller` (RunOnce + scheduled Run with backoff/jitter) — wired by a new `run` cobra command. Plus a bounded server-side fix for #12: `Devices().Touch` so `CheckinService` advances `last_seen_at` on the no-change branch (last contact, not just last change).

**Tech Stack:** Go 1.25 (no CGO), stdlib `net/http`/`net/netip`/`crypto/rand`, `internal/shared` HMAC primitives, cobra/viper (already present), `modernc.org/sqlite` (server side), stdlib `testing` (table-driven, `-race`).

**Design:** `docs/designs/2026-07-16-diyddns-07-client-run-loop-design.md` (user-approved; SGE APPROVE-WITH-NITS, findings I1/I2/M1–M7 folded).

## Global Constraints

- **Go 1.25, no CGO.** Errors wrapped with `%w`.
- **Client dependency guard:** the client binary must NOT import `huma`, `golang.org/x/oauth2`, `coreos/go-oidc`, or `go-jose`. `cmd/diyddns-client/deps_test.go` must stay green **unchanged**. New client packages import only stdlib + `internal/shared`, `internal/client/credentials`, `internal/config`, `internal/version`. Do **not** import `internal/auth` from the client (it pulls `store`/sqlite + argon2).
- **Never log or print** the device secret or the raw HMAC key. Log discovered IPs and the `stored` result only.
- **HMAC wire (do not reinvent):** reuse `internal/shared` — `HeaderDevice/HeaderTimestamp/HeaderNonce/HeaderSignature`, `CanonicalRequest`, `BodyHashHex`, `Sign`. Signed path is `/agent/v1/checkin` exactly.
- **I1 — hash the exact bytes you send:** `json.Marshal` → `bytes.NewReader`. Never `json.Encoder.Encode` (appends `\n` → body-hash diverges → every check-in 401s).
- **ZERO new module dependencies.** Everything is stdlib or already in `go.mod`.
- **Tests:** stdlib `testing`, table-driven, run with `-race`. Per-task lint: run the whole-module `golangci-lint run` (not just `go vet`) — gosec findings surface at module scope (Plan 06 T1 lesson).
- **No `--server` flag on `run`:** the server URL is authoritative from `credentials.json` (`ServerURL`), written at enrollment.

## Test Harness Reference (real, in-tree helpers — use exactly)

| Package | Helper / idiom |
|---------|----------------|
| `internal/store` (`*_test.go`, package `store`) | `newTestStore(t) (*Store, context.Context)` (in `testdb_test.go`). Create fixtures via `s.Users().Create(ctx, User{Email, Role})` then `s.Devices().Create(ctx, Device{UserID, Label, ...})`; read via `s.Devices().GetByID(ctx, id)`. `ErrNotFound` sentinel; `NowUnix()`; `nullIfZero`/`nullIfEmpty` helpers; the `RowsAffected → ErrNotFound` idiom (see `UpdateIP`/`Rename`). |
| `internal/server/service` (package `service`) | Construct `NewCheckinService(st, audit)`. Existing tests build a store via the store test helper pattern and exercise `Checkin(ctx, deviceID, CheckinReport{...})`. |
| `internal/config` (package `config`) | `LoadClient(v *viper.Viper, configPath string) (ClientConfig, error)`; no `AutomaticEnv` — every key is in `clientKeyDefaults` with `BindEnv`. Tests set env via `t.Setenv("DIYDDNS_...", ...)` and pass a fresh `viper.New()`. |
| client packages (`ipdiscovery`, `checkin`, `poller`) | White-box tests (`package X`) so unexported seams (`now`, fake providers, `randFloat`) are settable. `httptest.NewServer` for HTTP; `internal/shared` to reconstruct/verify signatures. |
| `cmd/diyddns-client` (package `main`) | Cobra command built by `newRunCmd()`; drive via `cmd.SetArgs(...)`, `cmd.ExecuteContext(ctx)`; `deps_test.go` stays unchanged. |

---

## Task dependency order

```
T1 store.Touch ───► T2 service #12
T3 config Run section ─────────────────┐
T4 ipdiscovery core ─► T5 httpProvider ─┤
T6 checkin client ──────────────────────┼─► T7 poller ─► T8 cmd run.go
```
Independent starts: **T1, T3, T4, T6.** Order for TodoWrite seeding: T1, T2, T3, T4, T5, T6, T7, T8.

---

### Task 1: `Devices().Touch` store method (#12 groundwork)

**Files:**
- Modify: `internal/store/devices.go` (add `Touch` after `UpdateIP`)
- Test: `internal/store/devices_test.go` (add `TestDeviceRepo_Touch`)

**Interfaces:**
- Consumes: `store.ErrNotFound`, `store.NowUnix`, `DeviceRepo.db` (existing).
- Produces: `func (r *DeviceRepo) Touch(ctx context.Context, id string, lastSeenAt int64) error` — sets `last_seen_at`+`updated_at`; `ErrNotFound` if no row matched.

- [ ] **Step 1: Write the failing test**

```go
// internal/store/devices_test.go
func TestDeviceRepo_Touch(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.Users().Create(ctx, User{Email: "touch@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "box"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := s.Devices().Touch(ctx, dev.ID, 1_700_000_000); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Devices().GetByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastSeenAt != 1_700_000_000 {
		t.Errorf("LastSeenAt = %d, want 1700000000", got.LastSeenAt)
	}
	if got.UpdatedAt == 0 {
		t.Errorf("UpdatedAt not set")
	}

	if err := s.Devices().Touch(ctx, "nonexistent", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("Touch(missing) err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestDeviceRepo_Touch -v`
Expected: FAIL — `s.Devices().Touch undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/store/devices.go — add after UpdateIP (around line 240)

// Touch advances last_seen_at (and updated_at) for a device without changing
// its IP addresses — the liveness signal for a routine, unchanged check-in.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) Touch(ctx context.Context, id string, lastSeenAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?`,
		nullIfZero(lastSeenAt), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("devices.Touch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.Touch: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.Touch: %w", ErrNotFound)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/ -run TestDeviceRepo_Touch -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/devices.go internal/store/devices_test.go
git commit -m "feat(store): add Devices().Touch to advance last_seen_at without an IP change"
```

---

### Task 2: `CheckinService` advances `last_seen_at` on no-change (#12 fix)

**Files:**
- Modify: `internal/server/service/checkin.go` (no-change branch, ~lines 70–77)
- Modify: `internal/server/service/checkin_test.go` — **the existing `TestCheckin_IdenticalReport_DoesNotStoreOrWrite` currently asserts (lines ~105–110) that `LastSeenAt`/`UpdatedAt` do NOT change on an unchanged check-in. The #12 fix deliberately reverses that.** Update the test to the new semantics (Touch advances `last_seen_at`; ip_history still does NOT grow).

**Interfaces:**
- Consumes: `store.DeviceRepo.Touch` (Task 1), `store.NowUnix`, existing `CheckinService`; test helpers `openTestStore(t) *store.Store`, `seedUser(t, st, email, role)`, `seedDevice(t, st, userID, label)`, `discardAudit{}`, `t.Context()`.
- Produces: no signature change — `Checkin` now calls `Touch` before the `Stored:false` early return.

> **Why this task modifies an existing test rather than adding a new one:** the current assertion encodes the OLD (`last_seen_at` = last change) semantics that #12 replaces. Adding a parallel test would leave the old one failing. `NowUnix()` is second-granularity, so we can't reliably observe "advanced" between two same-second check-ins — instead **rewind** `last_seen_at` to a known-old value before the unchanged check-in, then assert it moved forward.

- [ ] **Step 1: Update the existing test to the new (failing) expectation**

Replace `TestCheckin_IdenticalReport_DoesNotStoreOrWrite` in `internal/server/service/checkin_test.go` with:

```go
func TestCheckin_IdenticalReport_TouchesLastSeenButNoHistory(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, discardAudit{})

	report := CheckinReport{IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0"}
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}
	// Rewind last_seen_at to a known-old value so the liveness advance is
	// observable despite NowUnix() second-granularity.
	if err := st.Devices().Touch(t.Context(), dev.ID, 1000); err != nil {
		t.Fatalf("rewind Touch: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, report) // unchanged IP
	if err != nil {
		t.Fatalf("second Checkin: %v", err)
	}
	if res.Stored {
		t.Fatal("Checkin: Stored = true, want false for an unchanged report")
	}
	if res.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 1.2.3.4", res.CurrentIPv4)
	}

	// ip_history still does NOT grow on an unchanged check-in.
	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1 (no new row on unchanged checkin)", len(page.Rows))
	}

	// last_seen_at DID advance past the rewound value (liveness; #12).
	after, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if after.LastSeenAt <= 1000 {
		t.Fatalf("device LastSeenAt did not advance on unchanged check-in: got %d, want > 1000", after.LastSeenAt)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/service/ -run TestCheckin_IdenticalReport -v`
Expected: FAIL — `LastSeenAt did not advance` (current code writes nothing on no-change).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/server/service/checkin.go — replace the no-change early return
	if effV4 == dev.CurrentIPv4 && effV6 == dev.CurrentIPv6 {
		// IP unchanged: still a contact. Advance last_seen_at (liveness) so a
		// stable-IP device is distinguishable from a dead one (#12). "Last
		// change" remains derivable from the latest ip_history row.
		if err := s.st.Devices().Touch(ctx, dev.ID, store.NowUnix()); err != nil {
			return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
		}
		return CheckinResult{
			DeviceID:    dev.ID,
			CurrentIPv4: dev.CurrentIPv4,
			CurrentIPv6: dev.CurrentIPv6,
			Stored:      false,
		}, nil
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/service/ -run TestCheckin -race -v`
Expected: PASS (the updated identical-report test + all other checkin tests green). Also skim for any OTHER test in the repo asserting no-write-on-unchanged (e.g. an api-level checkin test) and update it to the new semantics if present.

- [ ] **Step 5: Commit**

```bash
git add internal/server/service/checkin.go internal/server/service/checkin_test.go
git commit -m "fix(service): advance last_seen_at on unchanged check-in so it means last contact (#12)"
```

---

### Task 3: `ClientRunSection` config (additive)

**Files:**
- Modify: `internal/config/client.go` (add `Run` section + keys)
- Test: `internal/config/client_test.go` (add Run-section binding cases)

**Interfaces:**
- Consumes: existing `LoadClient`, `clientKeyDefaults`.
- Produces:
  - `type ClientRunSection struct { Interval time.Duration; Quorum int; AddressFamilies, ProvidersV4, ProvidersV6 []string }`
  - `ClientConfig.Run ClientRunSection`.
  - Defaults: interval `5m`, quorum `2`, families `["ipv4","ipv6"]`, providers empty (empty ⇒ callers use built-in defaults).

- [ ] **Step 1: Write the failing test**

```go
// internal/config/client_test.go
func TestLoadClient_RunDefaults(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.Interval != 5*time.Minute {
		t.Errorf("Interval = %v, want 5m", cfg.Run.Interval)
	}
	if cfg.Run.Quorum != 2 {
		t.Errorf("Quorum = %d, want 2", cfg.Run.Quorum)
	}
	if got := cfg.Run.AddressFamilies; len(got) != 2 || got[0] != "ipv4" || got[1] != "ipv6" {
		t.Errorf("AddressFamilies = %v, want [ipv4 ipv6]", got)
	}
	if len(cfg.Run.ProvidersV4) != 0 {
		t.Errorf("ProvidersV4 = %v, want empty", cfg.Run.ProvidersV4)
	}
}

func TestLoadClient_RunEnvOverrides(t *testing.T) {
	t.Setenv("DIYDDNS_RUN_INTERVAL", "90s")
	t.Setenv("DIYDDNS_RUN_QUORUM", "3")
	t.Setenv("DIYDDNS_RUN_PROVIDERS_V4", "https://a.example,https://b.example,https://c.example")
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.Interval != 90*time.Second {
		t.Errorf("Interval = %v, want 90s", cfg.Run.Interval)
	}
	if cfg.Run.Quorum != 3 {
		t.Errorf("Quorum = %d, want 3", cfg.Run.Quorum)
	}
	want := []string{"https://a.example", "https://b.example", "https://c.example"}
	if !slices.Equal(cfg.Run.ProvidersV4, want) {
		t.Errorf("ProvidersV4 = %v, want %v (env comma-string → slice)", cfg.Run.ProvidersV4, want)
	}
}
```

Imports for the test: `"slices"`, `"time"`, `"github.com/spf13/viper"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoadClient_Run -v`
Expected: FAIL — `cfg.Run` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/config/client.go

// add to imports: "time"

type ClientConfig struct {
	Server  ClientServerSection
	Logging LoggingSection
	Run     ClientRunSection
}

// ClientRunSection configures the `run` reporting loop. Empty provider lists
// mean "use the built-in defaults" (see internal/client/ipdiscovery).
type ClientRunSection struct {
	Interval        time.Duration `mapstructure:"interval"`
	Quorum          int           `mapstructure:"quorum"`
	AddressFamilies []string      `mapstructure:"address_families"`
	ProvidersV4     []string      `mapstructure:"providers_v4"`
	ProvidersV6     []string      `mapstructure:"providers_v6"`
}

// add to clientKeyDefaults:
	"run.interval":         5 * time.Minute,
	"run.quorum":           2,
	"run.address_families": []string{"ipv4", "ipv6"},
	"run.providers_v4":     []string{},
	"run.providers_v6":     []string{},
```

> The existing `LoadClient` loop already `SetDefault` + `BindEnv`s every key in `clientKeyDefaults`; viper's default `Unmarshal` `DecodeHook` composes `StringToTimeDurationHookFunc` (env `"90s"` → `time.Duration`) and `StringToSliceHookFunc(",")` (env `"a,b,c"` → `[]string`). No `AutomaticEnv` needed and none added.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestLoadClient -race -v`
Expected: PASS (new + existing config tests).

- [ ] **Step 5: Commit**

```bash
git add internal/config/client.go internal/config/client_test.go
git commit -m "feat(config): add ClientRunSection (interval/quorum/families/providers) to LoadClient"
```

---

### Task 4: `ipdiscovery` core — Provider, quorum tally, Discoverer

**Files:**
- Create: `internal/client/ipdiscovery/discover.go`
- Test: `internal/client/ipdiscovery/discover_test.go`
- Delete: `internal/client/ipdiscovery/.gitkeep`

**Interfaces:**
- Consumes: stdlib only (`context`, `net/netip`, `sync`, `time`, `errors`, `fmt`).
- Produces:
  - `type Family int` with `FamilyV4, FamilyV6` and `String()` → `"ipv4"`/`"ipv6"`.
  - `type Provider interface { Lookup(ctx context.Context) (netip.Addr, error) }`
  - `type Result struct { Addr netip.Addr; OK bool }`
  - `type Discoverer struct{…}`
  - `func NewDiscoverer(v4, v6 []Provider, quorum int, perReq time.Duration) (*Discoverer, error)` — a nil/empty provider list means that family is disabled (skipped, `Result{OK:false}`, no validation). For a **non-empty** family, requires `1 ≤ quorum ≤ len(providers)` (M3).
  - `func (d *Discoverer) Discover(ctx context.Context) (v4, v6 Result)`

- [ ] **Step 1: Write the failing test**

```go
// internal/client/ipdiscovery/discover_test.go
package ipdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeProvider struct {
	addr netip.Addr
	err  error
}

func (f fakeProvider) Lookup(context.Context) (netip.Addr, error) { return f.addr, f.err }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDiscoverer_Quorum(t *testing.T) {
	a := mustAddr("203.0.113.7")
	b := mustAddr("203.0.113.8")
	tests := []struct {
		name      string
		providers []Provider
		quorum    int
		wantOK    bool
		wantAddr  netip.Addr
	}{
		{"two agree of three", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: b}}, 2, true, a},
		{"all three agree", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: a}}, 2, true, a},
		{"no agreement", []Provider{fakeProvider{addr: a}, fakeProvider{addr: b}, fakeProvider{err: errors.New("x")}}, 2, false, netip.Addr{}},
		{"one up below quorum", []Provider{fakeProvider{addr: a}, fakeProvider{err: errors.New("x")}, fakeProvider{err: errors.New("y")}}, 2, false, netip.Addr{}},
		{"top-count tie → no winner", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: b}, fakeProvider{addr: b}}, 2, false, netip.Addr{}},
		{"exact threshold boundary", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}}, 2, true, a},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDiscoverer(tt.providers, nil, tt.quorum, time.Second)
			if err != nil {
				t.Fatalf("NewDiscoverer: %v", err)
			}
			v4, _ := d.Discover(context.Background())
			if v4.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v", v4.OK, tt.wantOK)
			}
			if tt.wantOK && v4.Addr != tt.wantAddr {
				t.Errorf("Addr = %v, want %v", v4.Addr, tt.wantAddr)
			}
		})
	}
}

func TestNewDiscoverer_Validation(t *testing.T) {
	p := []Provider{fakeProvider{addr: mustAddr("203.0.113.7")}}
	if _, err := NewDiscoverer(p, nil, 2, time.Second); err == nil {
		t.Error("want error when quorum (2) > len(providers) (1)")
	}
	if _, err := NewDiscoverer(p, nil, 0, time.Second); err == nil {
		t.Error("want error when quorum < 1")
	}
	// Disabled family (nil providers) must not trip validation.
	if _, err := NewDiscoverer(nil, p, 1, time.Second); err != nil {
		t.Errorf("nil v4 family should be allowed (disabled): %v", err)
	}
}

func TestDiscoverer_DisabledFamilySkipped(t *testing.T) {
	d, err := NewDiscoverer(nil, nil, 2, time.Second)
	if err != nil {
		t.Fatalf("NewDiscoverer: %v", err)
	}
	v4, v6 := d.Discover(context.Background())
	if v4.OK || v6.OK {
		t.Errorf("disabled families should both be !OK, got v4=%v v6=%v", v4.OK, v6.OK)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/ipdiscovery/ -run TestDiscoverer -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/ipdiscovery/discover.go

// Package ipdiscovery discovers the host's public IP address for each address
// family from a quorum of independent lookup providers. A family's result is
// trusted only when at least `quorum` providers agree on the same address, so
// a single wrong, stale, or hijacked provider cannot set the reported IP.
package ipdiscovery

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Family is an IP address family.
type Family int

const (
	FamilyV4 Family = iota
	FamilyV6
)

func (f Family) String() string {
	if f == FamilyV6 {
		return "ipv6"
	}
	return "ipv4"
}

// Provider looks up the host's public IP for one address family.
type Provider interface {
	Lookup(ctx context.Context) (netip.Addr, error)
}

// Result is the per-family discovery outcome. OK is false when the family is
// disabled or no address reached quorum.
type Result struct {
	Addr netip.Addr
	OK   bool
}

// Discoverer runs each family's providers concurrently and applies a majority
// quorum. A family with no providers is disabled.
type Discoverer struct {
	v4, v6 []Provider
	quorum int
	perReq time.Duration
}

// NewDiscoverer validates quorum against each ENABLED (non-empty) family and
// returns a ready Discoverer. A nil/empty family list disables that family.
func NewDiscoverer(v4, v6 []Provider, quorum int, perReq time.Duration) (*Discoverer, error) {
	if quorum < 1 {
		return nil, fmt.Errorf("ipdiscovery: quorum must be >= 1, got %d", quorum)
	}
	if len(v4) > 0 && quorum > len(v4) {
		return nil, fmt.Errorf("ipdiscovery: ipv4 quorum %d exceeds provider count %d", quorum, len(v4))
	}
	if len(v6) > 0 && quorum > len(v6) {
		return nil, fmt.Errorf("ipdiscovery: ipv6 quorum %d exceeds provider count %d", quorum, len(v6))
	}
	if perReq <= 0 {
		perReq = 5 * time.Second
	}
	return &Discoverer{v4: v4, v6: v6, quorum: quorum, perReq: perReq}, nil
}

// Discover runs both families concurrently and returns their quorum results.
func (d *Discoverer) Discover(ctx context.Context) (v4, v6 Result) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); v4 = d.discoverFamily(ctx, d.v4) }()
	go func() { defer wg.Done(); v6 = d.discoverFamily(ctx, d.v6) }()
	wg.Wait()
	return v4, v6
}

// discoverFamily queries one family's providers concurrently (each bounded by
// perReq) and applies the majority quorum with a strict-tie-break: if two or
// more addresses share the top count, there is no winner (fail-safe).
func (d *Discoverer) discoverFamily(ctx context.Context, providers []Provider) Result {
	if len(providers) == 0 {
		return Result{}
	}
	addrs := make(chan netip.Addr, len(providers))
	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, d.perReq)
			defer cancel()
			addr, err := p.Lookup(pctx)
			if err == nil && addr.IsValid() {
				addrs <- addr
			}
		}(p)
	}
	wg.Wait()
	close(addrs)

	counts := make(map[netip.Addr]int)
	for a := range addrs {
		counts[a]++
	}
	var winner netip.Addr
	top, tie := 0, false
	for a, n := range counts {
		switch {
		case n > top:
			top, winner, tie = n, a, false
		case n == top:
			tie = true
		}
	}
	if top >= d.quorum && !tie {
		return Result{Addr: winner, OK: true}
	}
	return Result{}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/ipdiscovery/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git rm internal/client/ipdiscovery/.gitkeep
git add internal/client/ipdiscovery/discover.go internal/client/ipdiscovery/discover_test.go
git commit -m "feat(ipdiscovery): majority-quorum public-IP Discoverer with strict tie-break"
```

---

### Task 5: `ipdiscovery` HTTP provider — family-locked dialer + defaults

**Files:**
- Create: `internal/client/ipdiscovery/httpprovider.go`
- Test: `internal/client/ipdiscovery/httpprovider_test.go`

**Interfaces:**
- Consumes: `Provider`, `Family` (Task 4); stdlib `net`, `net/http`, `net/netip`, `io`, `strings`.
- Produces:
  - `func NewHTTPProvider(url string, family Family, hc *http.Client) Provider`
  - `func FamilyHTTPClient(family Family) *http.Client` (family-locked `tcp4`/`tcp6` dialer)
  - `func DefaultProvidersV4() []Provider`, `func DefaultProvidersV6() []Provider`
  - `func ProvidersFromURLs(urls []string, family Family) []Provider`

- [ ] **Step 1: Write the failing test**

```go
// internal/client/ipdiscovery/httpprovider_test.go
package ipdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPProvider_ParseAndFamilyValidate(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		family Family
		wantOK bool
	}{
		{"plain v4", "203.0.113.7", FamilyV4, true},
		{"v4 with trailing newline", "203.0.113.7\n", FamilyV4, true},
		{"wrong family: v6 body for v4 provider", "2001:db8::1", FamilyV4, false},
		{"garbage", "not-an-ip", FamilyV4, false},
		{"plain v6", "2001:db8::1", FamilyV6, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			// Use the default client (not family-locked) so httptest's 127.0.0.1
			// is reachable; family validation is on the PARSED address, not the dial.
			p := NewHTTPProvider(srv.URL, tt.family, srv.Client())
			addr, err := p.Lookup(context.Background())
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Lookup err = %v, want nil", err)
				}
				if !addr.IsValid() {
					t.Errorf("addr invalid")
				}
			} else if err == nil {
				t.Errorf("Lookup err = nil, want error for %q", tt.body)
			}
		})
	}
}

func TestDefaultProviders_Shape(t *testing.T) {
	if got := len(DefaultProvidersV4()); got != 3 {
		t.Errorf("DefaultProvidersV4 count = %d, want 3", got)
	}
	if got := len(DefaultProvidersV6()); got != 3 {
		t.Errorf("DefaultProvidersV6 count = %d, want 3", got)
	}
	if got := len(ProvidersFromURLs([]string{"https://a", "https://b"}, FamilyV4)); got != 2 {
		t.Errorf("ProvidersFromURLs count = %d, want 2", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/ipdiscovery/ -run 'TestHTTPProvider|TestDefaultProviders' -v`
Expected: FAIL — symbols undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/ipdiscovery/httpprovider.go
package ipdiscovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxProviderBody bounds how much a provider response we read — a public-IP
// endpoint returns a short string; anything larger is treated as junk.
const maxProviderBody = 1 << 12

// httpProvider GETs a URL and parses the plain-text body as this family's IP.
type httpProvider struct {
	url    string
	family Family
	http   *http.Client
}

// NewHTTPProvider builds a Provider that GETs url with hc and validates the
// parsed address belongs to family.
func NewHTTPProvider(url string, family Family, hc *http.Client) Provider {
	return &httpProvider{url: url, family: family, http: hc}
}

func (p *httpProvider) Lookup(ctx context.Context) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, http.NoBody)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: request %s: %w", p.url, err)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: get %s: %w", p.url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProviderBody)); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: %s status %d", p.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: read %s: %w", p.url, err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: parse %s: %w", p.url, err)
	}
	if !familyMatches(addr, p.family) {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: %s returned %s, not %s", p.url, addr, p.family)
	}
	return addr, nil
}

// familyMatches reports whether addr is genuinely of the given family
// (rejecting v4-in-v6 for the v6 family).
func familyMatches(addr netip.Addr, family Family) bool {
	if family == FamilyV6 {
		return addr.Is6() && !addr.Is4In6()
	}
	return addr.Is4()
}

// FamilyHTTPClient returns an http.Client whose dialer is locked to tcp4 or
// tcp6, guaranteeing a query measures the intended family even against a
// dual-stack endpoint.
func FamilyHTTPClient(family Family) *http.Client {
	network := "tcp4"
	if family == FamilyV6 {
		network = "tcp6"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}
}

// Default providers: three independent operators per family so the 2-of-N
// quorum spans distinct operators.
var (
	defaultURLsV4 = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://4.ident.me"}
	defaultURLsV6 = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://6.ident.me"}
)

// DefaultProvidersV4 returns the built-in IPv4 providers sharing one
// family-locked client (connection reuse).
func DefaultProvidersV4() []Provider { return ProvidersFromURLs(defaultURLsV4, FamilyV4) }

// DefaultProvidersV6 returns the built-in IPv6 providers.
func DefaultProvidersV6() []Provider { return ProvidersFromURLs(defaultURLsV6, FamilyV6) }

// ProvidersFromURLs builds family-locked providers for the given URLs, sharing
// a single client per call.
func ProvidersFromURLs(urls []string, family Family) []Provider {
	hc := FamilyHTTPClient(family)
	ps := make([]Provider, 0, len(urls))
	for _, u := range urls {
		ps = append(ps, NewHTTPProvider(u, family, hc))
	}
	return ps
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/ipdiscovery/ -race -v`
Expected: PASS (all Task 4 + Task 5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/client/ipdiscovery/httpprovider.go internal/client/ipdiscovery/httpprovider_test.go
git commit -m "feat(ipdiscovery): family-locked HTTP provider + default provider sets"
```

---

### Task 6: `checkin` — HMAC-signed check-in client

**Files:**
- Create: `internal/client/checkin/checkin.go`
- Test: `internal/client/checkin/checkin_test.go`

**Interfaces:**
- Consumes: `internal/shared` (headers + `CanonicalRequest`/`BodyHashHex`/`Sign`); stdlib.
- Produces:
  - `type Report struct { IPv4, IPv6, Hostname, OS, ClientVersion string }`
  - `type Result struct { DeviceID, CurrentIPv4, CurrentIPv6 string; Stored bool }`
  - `type Options struct { CACertPath string; Timeout time.Duration }`
  - `var ErrUnauthorized, ErrServer error`
  - `func NewClient(baseURL, deviceID, secretB64 string, opts Options) (*Client, error)`
  - `func (c *Client) Checkin(ctx context.Context, r Report) (Result, error)`

- [ ] **Step 1: Write the failing test**

```go
// internal/client/checkin/checkin_test.go
package checkin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// serverCheckinBody mirrors the SERVER's wire tags (internal/server/api/checkin.go)
// so the test guards the D7-duplicated contract against tag drift (SGE I2).
type serverCheckinBody struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

func TestClient_Checkin_SignsAndParsesFieldParity(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	secretB64 := base64.StdEncoding.EncodeToString(key)
	const deviceID = "dev-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// (a) Verify the client's signature exactly as the server would.
		canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
			r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
		if got, want := r.Header.Get(shared.HeaderSignature), shared.Sign(key, canonical); got != want {
			t.Errorf("signature mismatch: got %s want %s", got, want)
		}
		if r.Header.Get(shared.HeaderDevice) != deviceID {
			t.Errorf("device header = %q", r.Header.Get(shared.HeaderDevice))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		// (b) Tag-parity: body decodes into the SERVER's struct with expected fields.
		var sb serverCheckinBody
		if err := json.Unmarshal(body, &sb); err != nil {
			t.Fatalf("server-side decode: %v", err)
		}
		if sb.IPv4 != "203.0.113.7" || sb.IPv6 != "" {
			t.Errorf("decoded body = %+v, want IPv4 only", sb)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": deviceID, "current_ipv4": "203.0.113.7", "current_ipv6": "", "stored": true,
		})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, deviceID, secretB64, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) } // white-box seam
	res, err := c.Checkin(context.Background(), Report{IPv4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored || res.CurrentIPv4 != "203.0.113.7" {
		t.Errorf("Result = %+v", res)
	}
}

func TestNewClient_BadSecret(t *testing.T) {
	if _, err := NewClient("https://x", "d", "!!!not-base64!!!", Options{}); err == nil {
		t.Error("want error for non-base64 secret")
	}
}

func TestClient_Checkin_StatusMapping(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, tt := range []struct {
		code    int
		wantErr error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusInternalServerError, ErrServer},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.code)
		}))
		c, _ := NewClient(srv.URL, "d", key, Options{})
		_, err := c.Checkin(context.Background(), Report{IPv4: "203.0.113.7"})
		if !errorsIs(err, tt.wantErr) {
			t.Errorf("status %d → err %v, want %v", tt.code, err, tt.wantErr)
		}
		srv.Close()
	}
}
```

> Add `import "errors"` and a tiny `func errorsIs(err, target error) bool { return errors.Is(err, target) }`, or inline `errors.Is`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/checkin/ -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/checkin/checkin.go

// Package checkin is an HMAC-signed HTTP client for POST /agent/v1/checkin. It
// signs each request with the device's HMAC secret (obtained at enrollment)
// using the shared request-signing wire contract. It never logs the secret.
package checkin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// ErrUnauthorized is returned when the server rejects the signature/device
// (401) — e.g. a rotated or invalid secret. ErrServer is any other non-2xx.
var (
	ErrUnauthorized = errors.New("checkin: unauthorized")
	ErrServer       = errors.New("checkin: server error")
)

// Report is the IP/metadata a device reports. Empty families are omitted so
// the server preserves the stored value (merge-on-empty).
type Report struct{ IPv4, IPv6, Hostname, OS, ClientVersion string }

// Result mirrors the server's check-in response.
type Result struct {
	DeviceID    string
	CurrentIPv4 string
	CurrentIPv6 string
	Stored      bool
}

// Options configures the client. CACertPath trusts a self-signed homelab CA.
type Options struct {
	CACertPath string
	Timeout    time.Duration
}

// checkinRequest / checkinResponse are the client-local wire structs (design
// D7). Their json tags MUST match internal/server/api/checkin.go exactly; the
// test decodes the posted body with the server's tag set to guard against drift.
type checkinRequest struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

type checkinResponse struct {
	DeviceID    string `json:"device_id"`
	CurrentIPv4 string `json:"current_ipv4"`
	CurrentIPv6 string `json:"current_ipv6"`
	Stored      bool   `json:"stored"`
}

// Client signs and sends check-ins for one device.
type Client struct {
	baseURL  string
	deviceID string
	key      []byte
	now      func() time.Time
	http     *http.Client
}

// NewClient validates baseURL, decodes the wire-base64 secret to the raw HMAC
// key, and (optionally) trusts a CA bundle.
func NewClient(baseURL, deviceID, secretB64 string, opts Options) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("checkin: server URL must be http(s): %q", baseURL)
	}
	key, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("checkin: secret is not valid base64")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath) // operator-provided CA bundle path (enroll/client.go reads the same way, no #nosec needed — gosec does not flag this pattern here)
		if err != nil {
			return nil, fmt.Errorf("checkin: read ca cert %s: %w", opts.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("checkin: no certificates in %s", opts.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL:  baseURL,
		deviceID: deviceID,
		key:      key,
		now:      time.Now,
		http:     &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// Checkin signs and POSTs one check-in.
func (c *Client) Checkin(ctx context.Context, r Report) (Result, error) {
	// I1: hash exactly the bytes we send — Marshal then read those bytes.
	body, err := json.Marshal(checkinRequest{
		IPv4: r.IPv4, IPv6: r.IPv6, Hostname: r.Hostname, OS: r.OS, ClientVersion: r.ClientVersion,
	})
	if err != nil {
		return Result{}, fmt.Errorf("checkin: marshal: %w", err)
	}
	const path = "/agent/v1/checkin"
	ts := strconv.FormatInt(c.now().Unix(), 10)
	nonce, err := randNonce()
	if err != nil {
		return Result{}, err
	}
	canonical := shared.CanonicalRequest(http.MethodPost, path, ts, nonce, shared.BodyHashHex(body))
	sig := shared.Sign(c.key, canonical)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("checkin: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(shared.HeaderDevice, c.deviceID)
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("checkin: post: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var b checkinResponse
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return Result{}, fmt.Errorf("checkin: decode: %w", err)
		}
		return Result{DeviceID: b.DeviceID, CurrentIPv4: b.CurrentIPv4, CurrentIPv6: b.CurrentIPv6, Stored: b.Stored}, nil
	case http.StatusUnauthorized:
		return Result{}, ErrUnauthorized
	default:
		return Result{}, fmt.Errorf("%w: status %d", ErrServer, resp.StatusCode)
	}
}

// randNonce returns a fresh 16-byte hex nonce (server replay-nonce table
// requires a unique value per request within the skew window).
func randNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("checkin: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
```

> **Lint watch-item (dupl):** `NewClient`'s bootstrap (URL parse + `http.DefaultTransport.Clone()` + CA trust + timeout) closely resembles `enroll/client.go:74-97`. The module-scope `dupl` linter (`.golangci.yml`) *probably* won't fire (checkin interleaves the base64 key-decode and uses distinct `"checkin:"` error strings, keeping the contiguous run under the 150-token threshold). If the per-task `golangci-lint run` *does* flag it, either extract a small shared HTTP-bootstrap helper both packages call, or add a scoped `//nolint:dupl // <reason>` (repo `nolintlint` requires the linter name + explanation). Do **not** pre-extract — wait to see if it fires (YAGNI).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/checkin/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/client/checkin/
git commit -m "feat(checkin): HMAC-signed POST /agent/v1/checkin client"
```

---

### Task 7: `poller` — RunOnce + scheduled Run

**Files:**
- Create: `internal/client/poller/poller.go`
- Test: `internal/client/poller/poller_test.go`
- Delete: `internal/client/poller/.gitkeep`

**Interfaces:**
- Consumes: `ipdiscovery.Result` (Task 4), `checkin.Report`/`checkin.Result` (Task 6).
- Produces:
  - `type Clock interface { Now() time.Time; Sleep(ctx context.Context, d time.Duration) error }`; `func NewSystemClock() Clock`
  - `type Discoverer interface { Discover(ctx context.Context) (v4, v6 ipdiscovery.Result) }`
  - `type Checkiner interface { Checkin(ctx context.Context, r checkin.Report) (checkin.Result, error) }`
  - `type Options struct { Interval time.Duration; Clock Clock; RandFloat func() float64; Logger *slog.Logger; Hostname, OS, ClientVersion string }`
  - `func New(d Discoverer, c Checkiner, opts Options) *Poller`
  - `var ErrNoQuorum error`
  - `func (p *Poller) RunOnce(ctx context.Context) error`
  - `func (p *Poller) Run(ctx context.Context) error`

- [ ] **Step 1: Write the failing test**

```go
// internal/client/poller/poller_test.go
package poller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
)

type fakeDisc struct{ v4, v6 ipdiscovery.Result }

func (f fakeDisc) Discover(context.Context) (ipdiscovery.Result, ipdiscovery.Result) { return f.v4, f.v6 }

type fakeChk struct {
	last checkin.Report
	res  checkin.Result
	err  error
	n    int
}

func (f *fakeChk) Checkin(_ context.Context, r checkin.Report) (checkin.Result, error) {
	f.last = r
	f.n++
	return f.res, f.err
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunOnce_ReportsQuorumFamiliesOnly(t *testing.T) {
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: true}}
	p := New(d, c, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if c.last.IPv4 != "203.0.113.7" || c.last.IPv6 != "" {
		t.Errorf("report = %+v, want IPv4 only (v6 omitted)", c.last)
	}
}

func TestRunOnce_NoQuorum(t *testing.T) {
	p := New(fakeDisc{}, &fakeChk{}, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); !errors.Is(err, ErrNoQuorum) {
		t.Errorf("err = %v, want ErrNoQuorum", err)
	}
}

func TestRunOnce_AlwaysChecksInWhenQuorum(t *testing.T) {
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: false}} // unchanged
	p := New(d, c, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if c.n != 1 {
		t.Errorf("checkin calls = %d, want 1 even when unchanged", c.n)
	}
}

// fakeClock records sleep durations and cancels after N sleeps.
type fakeClock struct {
	now     time.Time
	sleeps  []time.Duration
	cancel  context.CancelFunc
	stopAt  int
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	if len(c.sleeps) >= c.stopAt {
		c.cancel()
		return context.Canceled
	}
	return nil
}

func TestRun_BackoffThenReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{cancel: cancel, stopAt: 3}
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{err: errors.New("boom")} // every cycle fails → backoff
	p := New(d, c, Options{Interval: 5 * time.Minute, Clock: clk, RandFloat: func() float64 { return 0.5 }, Logger: testLogger()})
	_ = p.Run(ctx)
	// First two failures back off: min(30s,interval)=30s, then 60s.
	if len(clk.sleeps) < 2 || clk.sleeps[0] != 30*time.Second || clk.sleeps[1] != 60*time.Second {
		t.Errorf("backoff sequence = %v, want [30s 60s ...]", clk.sleeps)
	}
}

func TestRun_SuccessJitterWithinBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{cancel: cancel, stopAt: 1}
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: true}}
	p := New(d, c, Options{Interval: 100 * time.Second, Clock: clk, RandFloat: func() float64 { return 1.0 }, Logger: testLogger()})
	_ = p.Run(ctx)
	// rand=1.0 → interval*(1 + 0.1*(2*1-1)) = 110s (upper bound).
	if clk.sleeps[0] != 110*time.Second {
		t.Errorf("jittered sleep = %v, want 110s", clk.sleeps[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/poller/ -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/client/poller/poller.go

// Package poller runs the diyddns-client reporting loop: each cycle discovers
// the host's public IP(s) and posts a signed check-in. It always checks in
// (every contact is a liveness signal); scheduling uses a fixed interval with
// exponential backoff on failure and small jitter on success.
package poller

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
)

// ErrNoQuorum means no address family reached quorum this cycle.
var ErrNoQuorum = errors.New("poller: no address family reached quorum")

// Discoverer runs public-IP discovery for both families.
type Discoverer interface {
	Discover(ctx context.Context) (v4, v6 ipdiscovery.Result)
}

// Checkiner posts a signed check-in.
type Checkiner interface {
	Checkin(ctx context.Context, r checkin.Report) (checkin.Result, error)
}

// Clock abstracts time for deterministic scheduling tests.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type systemClock struct{}

// NewSystemClock returns a real-time Clock.
func NewSystemClock() Clock { return systemClock{} }

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

// Options configures a Poller. Interval defaults to 5m; Clock to real time;
// RandFloat to a real [0,1) source; Logger to slog.Default().
type Options struct {
	Interval      time.Duration
	Clock         Clock
	RandFloat     func() float64
	Logger        *slog.Logger
	Hostname      string
	OS            string
	ClientVersion string
}

// Poller owns one device's reporting loop.
type Poller struct {
	disc      Discoverer
	chk       Checkiner
	interval  time.Duration
	clock     Clock
	randFloat func() float64
	log       *slog.Logger
	hostname  string
	os        string
	clientVer string
}

// New builds a Poller, applying defaults for unset Options.
func New(d Discoverer, c Checkiner, opts Options) *Poller {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	if opts.Clock == nil {
		opts.Clock = NewSystemClock()
	}
	if opts.RandFloat == nil {
		opts.RandFloat = defaultRandFloat
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Poller{
		disc: d, chk: c, interval: opts.Interval, clock: opts.Clock,
		randFloat: opts.RandFloat, log: opts.Logger,
		hostname: opts.Hostname, os: opts.OS, clientVer: opts.ClientVersion,
	}
}

// RunOnce performs one discover→check-in cycle. It reports every family that
// reached quorum (omitting the rest) and always posts if at least one did.
func (p *Poller) RunOnce(ctx context.Context) error {
	v4, v6 := p.disc.Discover(ctx)
	if !v4.OK && !v6.OK {
		return ErrNoQuorum
	}
	rep := checkin.Report{Hostname: p.hostname, OS: p.os, ClientVersion: p.clientVer}
	if v4.OK {
		rep.IPv4 = v4.Addr.String()
	}
	if v6.OK {
		rep.IPv6 = v6.Addr.String()
	}
	res, err := p.chk.Checkin(ctx, rep)
	if err != nil {
		return err
	}
	p.log.LogAttrs(ctx, slog.LevelInfo, "check-in",
		slog.Bool("stored", res.Stored),
		slog.String("ipv4", res.CurrentIPv4),
		slog.String("ipv6", res.CurrentIPv6))
	return nil
}

// Run loops until ctx is cancelled: cycle now, then sleep the jittered interval
// on success or an exponential backoff (capped at interval) on failure.
func (p *Poller) Run(ctx context.Context) error {
	var backoff time.Duration
	for {
		err := p.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var d time.Duration
		if err != nil {
			p.log.LogAttrs(ctx, slog.LevelWarn, "cycle failed", slog.Any("error", err))
			backoff = nextBackoff(backoff, p.interval)
			d = backoff
		} else {
			backoff = 0
			d = p.jittered()
		}
		if err := p.clock.Sleep(ctx, d); err != nil {
			return nil // ctx cancelled → clean stop
		}
	}
}

// nextBackoff returns min(30s,interval) on the first failure, then doubles up
// to interval (M4: first step is clamped so a short interval never backs off
// longer than its own cap).
func nextBackoff(cur, interval time.Duration) time.Duration {
	if cur == 0 {
		return min(30*time.Second, interval)
	}
	return min(cur*2, interval)
}

// jittered returns interval scaled by (1 ± 0.10).
func (p *Poller) jittered() time.Duration {
	factor := 1 + 0.10*(2*p.randFloat()-1)
	return time.Duration(float64(p.interval) * factor)
}

func defaultRandFloat() float64 {
	// crypto/rand-seeded is unnecessary for jitter; math/rand/v2 is fine and
	// needs no seeding. Kept behind a seam so tests are deterministic.
	return randV2Float64()
}
```

> Add a tiny file-local helper for `randV2Float64` using `math/rand/v2`:
> ```go
> import "math/rand/v2"
> func randV2Float64() float64 { return rand.Float64() }
> ```
> (Or inline `rand.Float64()` from `math/rand/v2` directly in `defaultRandFloat`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/poller/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git rm internal/client/poller/.gitkeep
git add internal/client/poller/
git commit -m "feat(poller): reporting loop with always-checkin, backoff, and jitter"
```

---

### Task 8: `run` cobra command (wiring)

**Files:**
- Create: `cmd/diyddns-client/run.go`
- Modify: `cmd/diyddns-client/root.go` (register `newRunCmd()`)
- Test: `cmd/diyddns-client/run_test.go`

**Interfaces:**
- Consumes: `config.LoadClient`/`ClientConfig`, `credentials.Load`/`DefaultPath`, `ipdiscovery.*`, `checkin.NewClient`, `poller.New`/`Run`/`RunOnce`, `version.Current`.
- Produces: `func newRunCmd() *cobra.Command`; registered on root.

- [ ] **Step 1: Write the failing test**

```go
// cmd/diyddns-client/run_test.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/shared"
)

// A full round-trip: --once against a fake server that verifies the HMAC and
// returns a check-in response. The fake providers are supplied via config
// pointing at httptest endpoints, so no real network is used.
func TestRunCmd_Once_EndToEnd(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	// Fake IP provider (returns a v4 address as plain text).
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7"))
	}))
	defer ipSrv.Close()

	// Fake diyddns server: verify signature, return checkin response.
	var gotDevice string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDevice = r.Header.Get(shared.HeaderDevice)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": gotDevice, "current_ipv4": "203.0.113.7", "current_ipv6": "", "stored": true,
		})
	}))
	defer apiSrv.Close()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	writeJSON(t, credPath, map[string]string{
		"server_url": apiSrv.URL, "device_id": "dev-xyz",
		"secret": base64.StdEncoding.EncodeToString(key),
	})
	cfgPath := filepath.Join(dir, "config.yaml")
	// quorum 1 so a single provider suffices; only ipv4 enabled, pointing at the
	// fake. Quote the URL — an unquoted http://host:port breaks YAML flow parsing.
	cfgYAML := fmt.Sprintf("run:\n  quorum: 1\n  address_families: [ipv4]\n  providers_v4: [%q]\n", ipSrv.URL)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRunCmd()
	cmd.SetArgs([]string{"--once", "--credentials-file", credPath, "--config", cfgPath})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("run --once: %v", err)
	}
	if gotDevice != "dev-xyz" {
		t.Errorf("server saw device %q, want dev-xyz", gotDevice)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
```

> Note: quorum 1 means a single provider "agrees with itself." With one provider and `quorum: 1`, the tally has one address at count 1, no tie → winner. Verify `NewDiscoverer` allows `quorum == len(providers)`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/diyddns-client/ -run TestRunCmd_Once -v`
Expected: FAIL — `newRunCmd` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// cmd/diyddns-client/run.go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/client/poller"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"
)

func newRunCmd() *cobra.Command {
	var (
		once       bool
		interval   time.Duration
		caCert     string
		credFile   string
		configFile string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Discover this host's public IP and report it to the diyddns server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viper.New()
			if err := v.BindPFlag("run.interval", cmd.Flags().Lookup("interval")); err != nil {
				return err
			}
			if err := v.BindPFlag("server.ca_bundle", cmd.Flags().Lookup("ca-cert")); err != nil {
				return err
			}
			cfg, err := config.LoadClient(v, configFile)
			if err != nil {
				return err
			}

			credPath := credFile
			if credPath == "" {
				dp, err := credentials.DefaultPath()
				if err != nil {
					return err
				}
				credPath = dp
			}
			creds, err := credentials.Load(credPath)
			if err != nil {
				if errors.Is(err, credentials.ErrNotFound) {
					return fmt.Errorf("no credentials at %s — run `diyddns-client enroll` first", credPath)
				}
				return err
			}

			disc, err := buildDiscoverer(cfg.Run)
			if err != nil {
				return err
			}
			chk, err := checkin.NewClient(creds.ServerURL, creds.DeviceID, creds.Secret,
				checkin.Options{CACertPath: cfg.Server.CABundle})
			if err != nil {
				return err
			}
			host, _ := os.Hostname()
			p := poller.New(disc, chk, poller.Options{
				Interval:      cfg.Run.Interval,
				Logger:        newClientLogger(cfg.Logging), // existing client logger helper; see note
				Hostname:      host,
				OS:            runtime.GOOS,
				ClientVersion: version.Current().Version,
			})
			if once {
				return p.RunOnce(cmd.Context())
			}
			return p.Run(cmd.Context())
		},
	}
	cmd.Flags().BoolVar(&once, "once", false, "run a single discover+check-in and exit")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "reporting interval (daemon mode)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "PEM CA bundle to trust (self-signed servers)")
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to client config.yaml")
	return cmd
}

// buildDiscoverer wires providers per enabled family (config override, else
// built-in defaults) and constructs the quorum Discoverer.
func buildDiscoverer(rc config.ClientRunSection) (*ipdiscovery.Discoverer, error) {
	var v4, v6 []ipdiscovery.Provider
	for _, fam := range rc.AddressFamilies {
		switch fam {
		case "ipv4":
			if len(rc.ProvidersV4) > 0 {
				v4 = ipdiscovery.ProvidersFromURLs(rc.ProvidersV4, ipdiscovery.FamilyV4)
			} else {
				v4 = ipdiscovery.DefaultProvidersV4()
			}
		case "ipv6":
			if len(rc.ProvidersV6) > 0 {
				v6 = ipdiscovery.ProvidersFromURLs(rc.ProvidersV6, ipdiscovery.FamilyV6)
			} else {
				v6 = ipdiscovery.DefaultProvidersV6()
			}
		default:
			return nil, fmt.Errorf("run: unknown address family %q", fam)
		}
	}
	if v4 == nil && v6 == nil {
		return nil, fmt.Errorf("run: no address families enabled")
	}
	return ipdiscovery.NewDiscoverer(v4, v6, rc.Quorum, 5*time.Second)
}
```

> **`newClientLogger` note:** if the client already has a logger constructor (check `cmd/diyddns-client` / `internal/config` for how enroll builds its slog logger from `LoggingSection`), reuse it. If none exists yet, add a minimal helper in `run.go`:
> ```go
> func newClientLogger(l config.LoggingSection) *slog.Logger {
> 	lvl := slog.LevelInfo
> 	_ = lvl.UnmarshalText([]byte(l.Level))
> 	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
> 	if l.Format == "json" {
> 		h2 := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
> 		return slog.New(h2)
> 	}
> 	return slog.New(h)
> }
> ```
> (imports `log/slog`). Keep it consistent with the server's `NewLogger` idiom if one is shared.

- [ ] **Step 4: Register the command**

```go
// cmd/diyddns-client/root.go
	root.AddCommand(newVersionCmd(), newEnrollCmd(), newRunCmd())
```

- [ ] **Step 5: Run tests + deps guard**

Run: `go test ./cmd/diyddns-client/ -race -v`
Expected: PASS — including the unchanged `deps_test.go` (no huma/oauth2/go-oidc/go-jose reachable from the client).

- [ ] **Step 6: Commit**

```bash
git add cmd/diyddns-client/run.go cmd/diyddns-client/root.go cmd/diyddns-client/run_test.go
git commit -m "feat(client): add `run` command wiring discovery + signed check-in loop"
```

---

## Final verification (after all tasks)

- [ ] `go build ./...` — clean.
- [ ] `go vet ./...` — clean.
- [ ] `gofmt -l .` — no output.
- [ ] `golangci-lint run` — 0 issues (whole-module; catches gosec at module scope). Repo `nolintlint` requires `// #nosec <ID> -- <reason>` format.
- [ ] `go test ./... -race` — all pass.
- [ ] Client deps guard: `go list -deps ./cmd/diyddns-client | grep -E 'huma|oauth2|go-oidc|go-jose'` → empty; `deps_test.go` unchanged and green.
- [ ] Manual smoke (optional, real network): with a real `credentials.json`, `diyddns-client run --once` reports a live IP and the server records it.

## Self-review — spec coverage map

| Design element | Task |
|----------------|------|
| D1 run mode both (daemon + --once) | T8 (`--once` branch / `Run`) |
| D2 majority quorum 2-of-N | T4 |
| D3 auto families, report what reaches quorum | T4 (`Discover`), T7 (omit-on-miss), T8 (family gating) |
| D4 always check in | T7 (`RunOnce` posts even when `Stored:false`), test `TestRunOnce_AlwaysChecksInWhenQuorum` |
| D5 #12 last_seen_at = last contact | T1 (`Touch`), T2 (service) |
| D6 interval + backoff + jitter, Clock/rand seams | T7 |
| D7 client-local wire structs + I2 tag-parity | T6 |
| D8 checkin own package | T6 |
| D9 client crypto/rand nonce, no internal/auth | T6 (`randNonce`) |
| I1 hash exact bytes | T6 (`json.Marshal`→`bytes.NewReader`) |
| M1 Content-Type | T6 |
| M2 tie-break | T4 |
| M3 quorum ≤ providers | T4 (`NewDiscoverer`) |
| M4 backoff clamp | T7 (`nextBackoff`) |
| M5 config env-slice test | T3 |
| Config surface | T3, T8 (`buildDiscoverer`) |
| Deps guard unchanged | T8 (verification) |

## Review provenance

- Author self-review (spec-coverage map above; placeholder + type-consistency scan). Caught and fixed: T2 must **modify** the existing `TestCheckin_IdenticalReport_DoesNotStoreOrWrite` (it asserts the old no-write semantics the #12 fix reverses), not add a parallel test; and NowUnix() second-granularity requires a rewind to observe the liveness advance.
- **`sr-go-engineer` (Fable) plan review — APPROVE-WITH-NITS.** Ground-truthed every task against the in-tree APIs; confirmed all tasks compile and all stated tests pass as written; the #12 blast radius is contained to the single test T2 rewrites (`api/agent_test.go` asserts only first-report/changed `Stored`, so nothing else breaks); the HMAC wire is byte-exact vs the server verifier; and **empirically verified** on viper v1.21.0 that `DIYDDNS_RUN_PROVIDERS_V4=a,b,c` → `[]string` (T3). Folded: dropped the unneeded `#nosec G304` in T6 (enroll reads the same way without it), corrected the T7 `Options.Logger` default doc, and added a T6 `dupl` lint watch-item note.

## Execution handoff

Recommended: `superpowers:subagent-driven-development` — fresh `sr-go-engineer` per task (TDD), per-task review, then an independent whole-branch review before finishing. Seed TodoWrite one item per task in the dependency order above (T1→T8), then execute in a worktree off `origin/main` `bcf670f`.
