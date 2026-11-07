//go:build linux || darwin

package agenttls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

var adminNow = time.Date(2026, 11, 7, 12, 30, 45, 0, time.UTC)

// adminFixture is a started CA with the backup key moved "offline", two
// devices holding certificates, and stand-in agent.crt / agent.key files.
type adminFixture struct {
	st      *store.Store
	dir     string
	offline string // path of the offline copy of the original ca-backup.key
	before  store.AgentCA
	devices []string
}

func newAdminFixture(t *testing.T, moveBackupOffline bool) adminFixture {
	t.Helper()
	st, dir := newTestStore(t), t.TempDir()
	mustLoad(t, st, dir)

	offline := filepath.Join(t.TempDir(), "backup.key")
	if err := os.WriteFile(offline, mustRead(t, filepath.Join(dir, CABackupKeyFile)), 0o600); err != nil {
		t.Fatalf("write offline backup key: %v", err)
	}
	if moveBackupOffline {
		if err := os.Remove(filepath.Join(dir, CABackupKeyFile)); err != nil {
			t.Fatalf("remove ca-backup.key: %v", err)
		}
	}
	mustWrite(t, filepath.Join(dir, AgentCertFile))
	mustWrite(t, filepath.Join(dir, AgentKeyFile))

	before, err := st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	u, err := st.Users().Create(t.Context(), store.User{Email: "a@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var ids []string
	for _, label := range []string{"one", "two"} {
		d, err := st.Devices().Create(t.Context(), store.Device{UserID: u.ID, Label: label, SecretHash: "x"})
		if err != nil {
			t.Fatalf("create device %s: %v", label, err)
		}
		if err := st.Devices().SetCert(t.Context(), d.ID, "abcd", adminNow.Unix()); err != nil {
			t.Fatalf("SetCert: %v", err)
		}
		ids = append(ids, d.ID)
	}
	return adminFixture{st: st, dir: dir, offline: offline, before: before, devices: ids}
}

func (f adminFixture) assertDeviceCertsCleared(t *testing.T) {
	t.Helper()
	for _, id := range f.devices {
		d, err := f.st.Devices().GetByID(t.Context(), id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if d.CertSerial != "" || d.CertNotAfter != 0 {
			t.Errorf("device %s cert = (%q, %d), want cleared", id, d.CertSerial, d.CertNotAfter)
		}
	}
}

func (f adminFixture) assertDeviceCertsKept(t *testing.T) {
	t.Helper()
	for _, id := range f.devices {
		d, err := f.st.Devices().GetByID(t.Context(), id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if d.CertSerial == "" {
			t.Errorf("device %s cert was cleared, want kept", id)
		}
	}
}

func (f adminFixture) audit(t *testing.T, eventType string) []store.AuditEntry {
	t.Helper()
	page, err := f.st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: eventType}, "", 50)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	return page.Rows
}

func (f adminFixture) assertAudit(t *testing.T, eventType string, n int) {
	t.Helper()
	rows := f.audit(t, eventType)
	if len(rows) != n {
		t.Fatalf("%d %q audit rows, want %d", len(rows), eventType, n)
	}
	for _, r := range rows {
		if r.TargetType != "agent_ca" || r.TargetID != "1" || r.ActorUserID != "" {
			t.Errorf("audit row = (%q, %q, actor %q), want (agent_ca, 1, no actor)", r.TargetType, r.TargetID, r.ActorUserID)
		}
	}
}

// snapshot is every file in dir except the lock, name to content.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	m := map[string]string{}
	for _, e := range entries {
		if e.Name() == LockFile {
			continue
		}
		m[e.Name()] = string(mustRead(t, filepath.Join(dir, e.Name())))
	}
	return m
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func certPub(t *testing.T, der []byte) *ecdsa.PublicKey {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pub, err := ecPublicKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// assertKeyFile checks dir/name is a 0600 key file whose public half is pub.
func assertKeyFile(t *testing.T, dir, name string, pub *ecdsa.PublicKey) {
	t.Helper()
	p := filepath.Join(dir, name)
	assertMode0600(t, p)
	key, err := readKey(p)
	if err != nil {
		t.Fatalf("readKey %s: %v", name, err)
	}
	if !key.PublicKey.Equal(pub) {
		t.Errorf("%s does not match the expected certificate", name)
	}
}

func assertGone(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: stat err = %v, want not-exist", n, err)
		}
	}
}

func assertNoPending(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pending") {
			t.Errorf("leftover pending file %s", e.Name())
		}
	}
}

func TestPromoteBackup_SwapsAndClears(t *testing.T) {
	f := newAdminFixture(t, true)

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("PromoteBackup: %v", err)
	}

	if res.AlreadyPromoted {
		t.Error("AlreadyPromoted = true on the first run")
	}
	if want := filepath.Join(f.dir, CABackupKeyFile); res.NewBackupKeyPath != want {
		t.Errorf("NewBackupKeyPath = %q, want %q", res.NewBackupKeyPath, want)
	}
	after, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(after.ActiveDER, f.before.BackupDER) {
		t.Error("Active is not the old Backup")
	}
	if bytes.Equal(after.BackupDER, f.before.BackupDER) || bytes.Equal(after.BackupDER, f.before.ActiveDER) {
		t.Error("new Backup equals an old CA, want a fresh one")
	}
	f.assertDeviceCertsCleared(t)
	assertKeyFile(t, f.dir, CAKeyFile, certPub(t, after.ActiveDER))
	assertKeyFile(t, f.dir, CABackupKeyFile, certPub(t, after.BackupDER))
	assertGone(t, f.dir, AgentCertFile, AgentKeyFile)
	assertNoPending(t, f.dir)
	f.assertAudit(t, "agent_ca.backup_promoted", 1)

	ca, _ := mustLoad(t, f.st, f.dir)
	if !bytes.Equal(ca.Active.Raw, after.ActiveDER) {
		t.Error("LoadOrInit after promotion returned a different Active")
	}
}

func TestPromoteBackup_WrongKey(t *testing.T) {
	f := newAdminFixture(t, true)
	_, wrongKey, err := newCACert(adminNow)
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}
	if err := writePending(f.dir, "wrong.key", wrongKey); err != nil {
		t.Fatalf("writePending: %v", err)
	}
	wrong := filepath.Join(f.dir, pendingName("wrong.key"))
	files := snapshot(t, f.dir)

	_, err = PromoteBackup(t.Context(), f.st, f.dir, wrong, adminNow)

	if !errors.Is(err, ErrBackupKeyMismatch) {
		t.Fatalf("err = %v, want ErrBackupKeyMismatch", err)
	}
	after, getErr := f.st.AgentCA().Get(t.Context())
	if getErr != nil {
		t.Fatalf("Get: %v", getErr)
	}
	if !bytes.Equal(after.ActiveDER, f.before.ActiveDER) || !bytes.Equal(after.BackupDER, f.before.BackupDER) {
		t.Error("the recorded CA changed")
	}
	if !equalSnapshots(files, snapshot(t, f.dir)) {
		t.Error("files in the dir changed")
	}
	f.assertDeviceCertsKept(t)
	f.assertAudit(t, "agent_ca.backup_promoted", 0)
}

func TestPromoteBackup_RerunIsIdempotent(t *testing.T) {
	f := newAdminFixture(t, true)
	if _, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow); err != nil {
		t.Fatalf("first PromoteBackup: %v", err)
	}
	afterFirst, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	files := snapshot(t, f.dir)

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("second PromoteBackup: %v", err)
	}

	if !res.AlreadyPromoted {
		t.Error("AlreadyPromoted = false on the rerun")
	}
	afterSecond, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(afterSecond.ActiveDER, afterFirst.ActiveDER) || !bytes.Equal(afterSecond.BackupDER, afterFirst.BackupDER) {
		t.Error("the rerun changed the recorded CA")
	}
	if !equalSnapshots(files, snapshot(t, f.dir)) {
		t.Error("the rerun changed files in the dir")
	}
	f.assertAudit(t, "agent_ca.backup_promoted", 1)
}

func TestPromoteBackup_CompletesAfterCrash(t *testing.T) {
	f := newAdminFixture(t, true)
	errCrash := errors.New("simulated crash")
	afterPromoteTxHook = func() error { return errCrash }
	t.Cleanup(func() { afterPromoteTxHook = nil })

	if _, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow); !errors.Is(err, errCrash) {
		t.Fatalf("first PromoteBackup err = %v, want the simulated crash", err)
	}
	afterPromoteTxHook = nil
	after, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(after.ActiveDER, f.before.BackupDER) {
		t.Fatal("the transaction did not commit before the crash")
	}

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("rerun PromoteBackup: %v", err)
	}

	if !res.AlreadyPromoted {
		t.Error("AlreadyPromoted = false on the completing rerun")
	}
	assertKeyFile(t, f.dir, CAKeyFile, certPub(t, after.ActiveDER))
	assertKeyFile(t, f.dir, CABackupKeyFile, certPub(t, after.BackupDER))
	if want := filepath.Join(f.dir, CABackupKeyFile); res.NewBackupKeyPath != want {
		t.Errorf("NewBackupKeyPath = %q, want %q (the new backup key landed in the dir and must go offline)", res.NewBackupKeyPath, want)
	}
	assertGone(t, f.dir, AgentCertFile, AgentKeyFile)
	assertNoPending(t, f.dir)
	f.assertAudit(t, "agent_ca.backup_promoted", 1) // the crashed run never reached its audit write
	mustLoad(t, f.st, f.dir)
}

// promoteThenDamage promotes once, then runs damage on the dir, simulating a
// volume lost or replaced after the transaction committed.
func promoteThenDamage(t *testing.T, damage func(f adminFixture)) adminFixture {
	t.Helper()
	f := newAdminFixture(t, true)
	if _, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow); err != nil {
		t.Fatalf("PromoteBackup: %v", err)
	}
	damage(f)
	return f
}

func (f adminFixture) assertActiveKeyRestored(t *testing.T, res PromoteResult) {
	t.Helper()
	if !res.AlreadyPromoted || !res.ActiveKeyRestored {
		t.Errorf("result = %+v, want AlreadyPromoted and ActiveKeyRestored", res)
	}
	after, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertKeyFile(t, f.dir, CAKeyFile, certPub(t, after.ActiveDER))
	assertNoPending(t, f.dir)
	mustLoad(t, f.st, f.dir) // startup rule 1
}

func TestPromoteBackup_RerunRestoresMissingActiveKey(t *testing.T) {
	f := promoteThenDamage(t, func(f adminFixture) {
		if err := os.Remove(filepath.Join(f.dir, CAKeyFile)); err != nil {
			t.Fatalf("remove ca.key: %v", err)
		}
	})

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("rerun PromoteBackup: %v", err)
	}

	f.assertActiveKeyRestored(t, res)
	if res.NoLocalBackupKey {
		t.Error("NoLocalBackupKey = true although ca-backup.key is present")
	}
}

func TestPromoteBackup_RerunRestoresMismatchedActiveKey(t *testing.T) {
	f := promoteThenDamage(t, func(f adminFixture) {
		_, other, err := newCACert(adminNow)
		if err != nil {
			t.Fatalf("newCACert: %v", err)
		}
		if err := writePending(f.dir, CAKeyFile, other); err != nil {
			t.Fatalf("writePending: %v", err)
		}
		if err := os.Rename(filepath.Join(f.dir, pendingName(CAKeyFile)), filepath.Join(f.dir, CAKeyFile)); err != nil {
			t.Fatalf("install unrelated ca.key: %v", err)
		}
	})

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("rerun PromoteBackup: %v", err)
	}

	f.assertActiveKeyRestored(t, res)
}

func TestPromoteBackup_RerunRestoreWithoutBackupKeyFlagsIt(t *testing.T) {
	f := promoteThenDamage(t, func(f adminFixture) {
		for _, n := range []string{CAKeyFile, CABackupKeyFile} {
			if err := os.Remove(filepath.Join(f.dir, n)); err != nil {
				t.Fatalf("remove %s: %v", n, err)
			}
		}
	})

	res, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)
	if err != nil {
		t.Fatalf("rerun PromoteBackup: %v", err)
	}

	f.assertActiveKeyRestored(t, res)
	if !res.NoLocalBackupKey {
		t.Error("NoLocalBackupKey = false although no ca-backup.key is present")
	}
	assertGone(t, f.dir, CABackupKeyFile) // a new backup is never generated here
}

func TestPromoteBackup_WorksWithEmptyDir(t *testing.T) {
	f := newAdminFixture(t, true)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(f.dir, e.Name())); err != nil {
			t.Fatalf("remove %s: %v", e.Name(), err)
		}
	}

	if _, err := PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow); err != nil {
		t.Fatalf("PromoteBackup on an empty dir: %v", err)
	}

	after, err := f.st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertKeyFile(t, f.dir, CAKeyFile, certPub(t, after.ActiveDER))
	assertKeyFile(t, f.dir, CABackupKeyFile, certPub(t, after.BackupDER))
	mustLoad(t, f.st, f.dir)
}

func TestPromoteBackup_RefusesWhenLocked(t *testing.T) {
	f := newAdminFixture(t, true)
	lock, err := AcquireLock(f.dir)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()

	_, err = PromoteBackup(t.Context(), f.st, f.dir, f.offline, adminNow)

	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	f.assertDeviceCertsKept(t)
}

func TestReset_RefusesWhenLocked(t *testing.T) {
	f := newAdminFixture(t, false)
	lock, err := AcquireLock(f.dir)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()

	_, err = Reset(t.Context(), f.st, f.dir, adminNow)

	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	if _, getErr := f.st.AgentCA().Get(t.Context()); getErr != nil {
		t.Errorf("the CA was reset despite the lock: %v", getErr)
	}
}

func TestReset_ClearsAndRenames(t *testing.T) {
	f := newAdminFixture(t, false)
	names := []string{CAKeyFile, CABackupKeyFile, AgentCertFile, AgentKeyFile}
	content := map[string][]byte{}
	for _, n := range names {
		content[n] = mustRead(t, filepath.Join(f.dir, n))
	}
	suffix := ".reset-" + adminNow.UTC().Format("20060102T150405Z")

	got, err := Reset(t.Context(), f.st, f.dir, adminNow)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if _, err := f.st.AgentCA().Get(t.Context()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Reset err = %v, want ErrNotFound", err)
	}
	f.assertDeviceCertsCleared(t)
	var want []string
	for _, n := range names {
		renamed := filepath.Join(f.dir, n+suffix)
		want = append(want, renamed)
		if !bytes.Equal(mustRead(t, renamed), content[n]) {
			t.Errorf("%s content changed by the rename", renamed)
		}
		assertMode0600(t, renamed)
	}
	assertGone(t, f.dir, names...)
	if len(got) != len(want) {
		t.Fatalf("Reset returned %v, want %v", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("Reset returned %v, missing %s", got, w)
		}
	}
	f.assertAudit(t, "agent_ca.reset", 1)

	ca, _ := mustLoad(t, f.st, f.dir)
	if bytes.Equal(ca.Active.Raw, f.before.ActiveDER) {
		t.Error("LoadOrInit after Reset kept the old Active, want a fresh pair")
	}
}

func TestReset_RerunIsIdempotent(t *testing.T) {
	f := newAdminFixture(t, false)
	if _, err := Reset(t.Context(), f.st, f.dir, adminNow); err != nil {
		t.Fatalf("first Reset: %v", err)
	}
	files := snapshot(t, f.dir)

	got, err := Reset(t.Context(), f.st, f.dir, adminNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("second Reset: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("second Reset renamed %v, want nothing", got)
	}
	if !equalSnapshots(files, snapshot(t, f.dir)) {
		t.Error("the rerun changed files in the dir")
	}
	f.assertAudit(t, "agent_ca.reset", 2) // each invocation is an operator action
}
