package mtls

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/shared"
)

// newKey is the pending secret ("N") the fake knows as "new". oldKey, the env's
// own secret, is "old".
var newKey = bytes.Repeat([]byte{0x42}, 32)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// rotEnv is an env with a TLS main port (so the B5 gate lets rotation through),
// no mTLS state, a server that advertises rotation and a fake that checks
// signatures against "old". Tests that exercise the cert track undo the caps.
func rotEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, true)
	e.fs.setCaps(false, "")
	e.fs.capsRotation = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	return e
}

// managerSeedingPending builds a Manager that starts holding pending secret n:
// the credentials file carries it, and the fake learns it as "new".
func (e *env) managerSeedingPending(n []byte) *Manager {
	e.t.Helper()
	cfg := e.config()
	cfg.Creds.PendingSecret = b64(n)
	if err := credentials.Save(cfg.CredentialsPath, cfg.Creds, true); err != nil {
		e.t.Fatalf("seed credentials: %v", err)
	}
	e.fs.keys["new"] = n
	m, err := NewManager(cfg)
	if err != nil {
		e.t.Fatalf("NewManager: %v", err)
	}
	return m
}

// creds is the credentials file as it is on disk now; a file never written is
// the zero value.
func (e *env) creds() credentials.Credentials {
	e.t.Helper()
	c, err := credentials.Load(e.config().CredentialsPath)
	if err != nil && !errors.Is(err, credentials.ErrNotFound) {
		e.t.Fatalf("load credentials: %v", err)
	}
	return c
}

// lockCredentialsDir makes the credentials directory read-only, so no save can
// succeed. It skips where permissions are not enforced.
func (e *env) lockCredentialsDir() {
	e.t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		e.t.Skip("directory permissions are not enforced for this user")
	}
	if err := os.Chmod(e.dir, 0o500); err != nil {
		e.t.Fatalf("chmod: %v", err)
	}
	// Restore access so t.TempDir can remove the directory.
	e.t.Cleanup(func() { _ = os.Chmod(e.dir, 0o700) })
}

// keysSeen is the matched key name of every request to route, in order.
func (f *fakeServer) keysSeen(route string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.seen {
		if s.route == route {
			out = append(out, s.key)
		}
	}
	return out
}

// secrets is a copy of the step-3 secrets received so far.
func (f *fakeServer) secrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.stepThree)
}

func wantStrings(t *testing.T, got []string, what string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

// wantFreshPending asserts the credentials file holds a 32-byte pending secret
// that is not except, and returns its wire form.
func wantFreshPending(t *testing.T, c credentials.Credentials, except []byte) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(c.PendingSecret)
	if err != nil || len(raw) != 32 {
		t.Fatalf("PendingSecret = %q, want 32 bytes of base64", c.PendingSecret)
	}
	if bytes.Equal(raw, except) {
		t.Error("PendingSecret was reused, want a fresh secret")
	}
	return c.PendingSecret
}

func TestRotation_Rule6_Coded409DropsPending(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"old": true}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.managerSeedingPending(newKey)
	e.fs.script(portMain, routeRotateSecret, scripted{status: http.StatusConflict, code: shared.CodeNoSecretRotationPending, times: 1})

	mustCycle(t, m)

	if got := e.creds().PendingSecret; got != "" {
		t.Errorf("PendingSecret = %q, want it dropped", got)
	}
	if m.keys.Pending != nil {
		t.Error("in-memory Pending kept, want nil")
	}
	wantCount(t, e.logs.count(slog.LevelInfo, "the server has no rotation pending"), 1, "drop INFOs")
}

func TestRotation_Rule7_ServerErrorKeepsBoth(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"old": true}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.managerSeedingPending(newKey)
	e.fs.script(portMain, routeRotateSecret, scripted{status: http.StatusInternalServerError, times: 1})

	mustCycle(t, m)

	if got := e.creds().PendingSecret; got != b64(newKey) {
		t.Errorf("PendingSecret = %q, want it kept as %q", got, b64(newKey))
	}
	if m.keys.Pending == nil {
		t.Error("in-memory Pending dropped, want it kept")
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "sending the new secret failed"), 1, "send-failure WARNs")
}

func TestRotation_CapabilityOnlyWhenAdvertised(t *testing.T) {
	e := rotEnv(t)
	e.fs.capsRotation = false
	mustCycle(t, e.manager())
	got := e.fs.newCheckins(portMain)
	if len(got) != 1 {
		t.Fatalf("check-ins = %d, want 1", len(got))
	}
	if v, ok := got[0].body["capabilities"]; ok {
		t.Errorf("capabilities = %v, want the field absent", v)
	}

	e.fs.capsRotation = true
	mustCycle(t, e.manager()) // a fresh Manager: the first one cached its capabilities
	got = e.fs.newCheckins(portMain)
	if len(got) != 1 {
		t.Fatalf("check-ins = %d, want 1", len(got))
	}
	if want := []any{"rotation"}; !reflect.DeepEqual(got[0].body["capabilities"], want) {
		t.Errorf("capabilities = %v, want %v", got[0].body["capabilities"], want)
	}
}

func TestRotation_Rule1_GeneratesSavesAndSends(t *testing.T) {
	e := rotEnv(t)
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()

	mustCycle(t, m)

	pending := wantFreshPending(t, e.creds(), nil)
	wantStrings(t, e.fs.secrets(), "step-3 secrets", pending)
	wantStrings(t, e.fs.keysSeen(routeRotateSecret), "step-3 signing keys", "old")
	wantCount(t, e.logs.count(slog.LevelInfo, "new secret sent"), 1, "sent INFOs")
}

func TestRotation_Rule1_SaveFailureStops(t *testing.T) {
	e := rotEnv(t)
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()
	e.lockCredentialsDir()

	mustCycle(t, m)

	wantCount(t, len(e.fs.secrets()), 0, "step-3 requests")
	wantCount(t, e.logs.count(slog.LevelError, "cannot save credentials"), 1, "save-failure ERRORs")
	if m.keys.Pending != nil {
		t.Error("in-memory Pending kept after the save failed, want nil")
	}
}

func TestRotation_NeverRegenerates(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"old": true}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.managerSeedingPending(newKey)

	mustCycle(t, m)

	wantStrings(t, e.fs.secrets(), "step-3 secrets", b64(newKey))
	if got := e.creds().PendingSecret; got != b64(newKey) {
		t.Errorf("PendingSecret = %q, want the original %q", got, b64(newKey))
	}
}

func TestRotation_Rule4_PendingAcceptedPromotes(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"new": true}
	e.fs.rotation = map[string]any{"secret": false}
	m := e.managerSeedingPending(newKey)

	mustCycle(t, m)

	c := e.creds()
	if c.Secret != b64(newKey) || c.PendingSecret != "" {
		t.Errorf("credentials Secret = %q, PendingSecret = %q, want %q and empty", c.Secret, c.PendingSecret, b64(newKey))
	}
	wantCount(t, len(e.fs.secrets()), 0, "step-3 requests")
	wantStrings(t, e.fs.keysSeen(routeCheckin), "check-in keys", "new")
}

func TestRotation_Rule5_401RetriesNoStrike(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"old": true}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.managerSeedingPending(newKey)

	mustCycle(t, m) // mustCycle fails on any error, so no unauthorized strike reaches the caller

	wantStrings(t, e.fs.keysSeen(routeCheckin), "check-in keys", "new", "old")
	wantStrings(t, e.fs.secrets(), "step-3 secrets", b64(newKey))
}

func TestRotation_SF6_ZombieDropped(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"old": true}
	m := e.managerSeedingPending(newKey)

	mustCycle(t, m)

	if got := e.creds().PendingSecret; got != "" {
		t.Errorf("PendingSecret = %q, want it dropped", got)
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "no longer expects"), 1, "zombie WARNs")
	wantCount(t, len(e.fs.secrets()), 0, "step-3 requests")
}

func TestRotation_SF5_MidCycleAcrossFamilies(t *testing.T) {
	e := dualStackEnv(t)
	e.discovery = config.IPDiscoveryNever
	e.insecure = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	e.fs.accept = map[string]bool{"new": true}
	m := e.managerSeedingPending(newKey)
	promoted := 0
	orig := m.keys.Promoted
	m.keys.Promoted = func() error { promoted++; return orig() }

	mustCycle(t, m)

	wantStrings(t, e.fs.keysSeen(routeCheckin), "check-in keys (one per family)", "new", "new")
	wantCount(t, promoted, 1, "Promoted calls")
	if c := e.creds(); c.Secret != b64(newKey) || c.PendingSecret != "" {
		t.Errorf("credentials Secret = %q, PendingSecret = %q, want %q and empty", c.Secret, c.PendingSecret, b64(newKey))
	}
}

func TestRotation_PromoteThenFreshPendingSameCycle(t *testing.T) {
	e := rotEnv(t)
	e.fs.accept = map[string]bool{"new": true}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.managerSeedingPending(newKey)

	mustCycle(t, m)

	c := e.creds()
	if c.Secret != b64(newKey) {
		t.Errorf("Secret = %q, want the promoted %q", c.Secret, b64(newKey))
	}
	fresh := wantFreshPending(t, c, newKey)
	wantStrings(t, e.fs.keysSeen(routeRotateSecret), "step-3 signing keys", "new")
	wantStrings(t, e.fs.secrets(), "step-3 secrets", fresh)
}

func TestRotation_CorruptPendingDroppedWithWarn(t *testing.T) {
	e := rotEnv(t)
	cfg := e.config()
	cfg.Creds.PendingSecret = "!!bad!!"

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m.keys.Pending != nil {
		t.Error("corrupt pending kept in memory, want nil")
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "pending_secret in credentials is unreadable"), 1, "corrupt-pending WARNs")
	raw, err := os.ReadFile(cfg.CredentialsPath)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if strings.Contains(string(raw), "pending_secret") {
		t.Errorf("credentials file still has pending_secret: %s", raw)
	}
}

func TestRotation_CorruptCurrentIsFatal(t *testing.T) {
	e := rotEnv(t)
	cfg := e.config()
	cfg.Creds.Secret = "!!bad!!"
	cfg.Creds.PendingSecret = "!!bad!!"

	if _, err := NewManager(cfg); err == nil {
		t.Fatal("NewManager succeeded, want an error for a bad current secret")
	}
}

func TestRotation_SaveFailureErrorThrottled(t *testing.T) {
	e := rotEnv(t)
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()
	e.lockCredentialsDir()

	mustCycle(t, m)
	mustCycle(t, m)

	wantCount(t, e.logs.count(slog.LevelError, "cannot save credentials"), 1, "save-failure ERRORs over two cycles")
}

func TestRotation_ORMergeAcrossFamilies(t *testing.T) {
	e := dualStackEnv(t)
	e.discovery = config.IPDiscoveryNever
	e.insecure = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	e.fs.capsRotation = true
	observed := sourceAnswer(always(srcObserved))
	e.fs.setCheckin(func(r seenReq) (int, map[string]any) {
		status, body := observed(r)
		body["rotation"] = map[string]any{"secret": r.fam == ipdiscovery.FamilyV4}
		return status, body
	})
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, len(e.fs.secrets()), 1, "step-3 requests")
}

func TestRotation_CertRenewsNowWhenCommitted(t *testing.T) {
	t.Run("committed", func(t *testing.T) {
		e := newEnv(t, true)
		seed := e.seed(true)
		e.fs.rotation = map[string]any{"cert": true}
		m := e.manager()

		mustCycle(t, m)

		wantCount(t, e.fs.count(portAgent, routeCert), 1, "agent cert requests")
		if got := e.mustState().CertPEM; got == seed.CertPEM {
			t.Error("CertPEM unchanged, want the renewed certificate")
		}
	})
	t.Run("probation", func(t *testing.T) {
		e := newEnv(t, true)
		e.seed(false)
		e.fs.script(portAgent, routeSelf, scripted{status: http.StatusInternalServerError, times: 1})
		e.fs.rotation = map[string]any{"cert": true}
		m := e.manager()

		mustCycle(t, m)

		wantCount(t, e.fs.count(portAgent, routeCert), 0, "agent cert requests")
		if e.mustState().Committed {
			t.Error("state committed although the probe failed")
		}
	})
}

func TestRotation_RefusesOverHTTP(t *testing.T) {
	e := newEnv(t, false)
	e.insecure = false
	e.fs.setCaps(false, "")
	e.fs.capsRotation = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()
	const msg = "refusing to rotate the device secret over insecure http://"

	mustCycle(t, m)
	mustCycle(t, m)

	if got := e.creds().PendingSecret; got != "" {
		t.Errorf("PendingSecret = %q, want none: no key may be generated over http://", got)
	}
	wantCount(t, len(e.fs.secrets()), 0, "step-3 requests")
	wantCount(t, e.logs.count(slog.LevelError, msg), 1, "refusal ERRORs over two cycles")

	e.clk.Advance(warnEvery)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelError, msg), 2, "refusal ERRORs after warnEvery")
}

func TestRotation_InsecureProvisionAllowsHTTP(t *testing.T) {
	e := newEnv(t, false)
	e.insecure = true
	e.fs.setCaps(false, "")
	e.fs.capsRotation = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()

	mustCycle(t, m)

	wantFreshPending(t, e.creds(), nil)
	wantCount(t, len(e.fs.secrets()), 1, "step-3 requests")
	wantCount(t, e.logs.count(slog.LevelWarn, "rotating the device secret over insecure http://"), 1, "insecure-rotation WARNs")
}

func TestNewManager_RequiresCredentialsPath(t *testing.T) {
	e := newEnv(t, false)
	cfg := e.config()
	cfg.CredentialsPath = ""

	_, err := NewManager(cfg)

	if err == nil || err.Error() != "mtls: CredentialsPath is required" {
		t.Fatalf("err = %v, want %q", err, "mtls: CredentialsPath is required")
	}
}

// The B5 gate keys on the hop step 3 takes, not on the configured main URL: a
// device committed to mTLS rotates over the agent port even though its main
// URL is http:// and run.insecure_provision is not set.
func TestRotation_CommittedDeviceRotatesOverAgentPortDespiteHTTPMain(t *testing.T) {
	e := newEnv(t, false)
	e.insecure = false
	e.seed(true)
	e.fs.capsRotation = true
	e.fs.keys = map[string][]byte{"old": oldKey}
	e.fs.rotation = map[string]any{"secret": true}
	m := e.manager()

	mustCycle(t, m)

	wantFreshPending(t, e.creds(), nil)
	wantCount(t, e.fs.count(portAgent, routeRotateSecret), 1, "agent-port step-3 requests")
	wantCount(t, e.fs.count(portMain, routeRotateSecret), 0, "main-port step-3 requests")
	wantCount(t, e.logs.count(slog.LevelError, "refusing to rotate the device secret"), 0, "refusal ERRORs")
	wantCount(t, e.logs.count(slog.LevelWarn, "rotating the device secret over insecure http://"), 0, "insecure-rotation WARNs")
}

// A pending secret of the wrong length is as unreadable as a corrupt one: it is
// dropped with the same WARN, and the current secret still signs.
func TestRotation_WrongLengthPendingDroppedWithWarn(t *testing.T) {
	e := rotEnv(t)
	cfg := e.config()
	cfg.Creds.PendingSecret = b64([]byte("short"))

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m.keys.Pending != nil {
		t.Error("wrong-length pending kept in memory, want nil")
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "pending_secret in credentials is unreadable"), 1, "unreadable-pending WARNs")
}
