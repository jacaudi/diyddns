package agenttls

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/logtest"
	"github.com/jacaudi/diyddns/internal/store"
)

// newTestStore opens a fresh on-disk store in a temp dir.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return st
}

// load runs LoadOrInit and returns the CA, the error, and the log it wrote.
func load(t *testing.T, st *store.Store, dir string) (*CA, string, error) {
	t.Helper()
	var buf bytes.Buffer
	ca, err := LoadOrInit(t.Context(), st, dir, time.Now(), slog.New(slog.NewJSONHandler(&buf, nil)))
	return ca, buf.String(), err
}

// mustLoad is load that fails the test on error.
func mustLoad(t *testing.T, st *store.Store, dir string) (*CA, string) {
	t.Helper()
	ca, log, err := load(t, st, dir)
	if err != nil {
		t.Fatalf("LoadOrInit: %v", err)
	}
	return ca, log
}

// offlineWarns returns the WARN records in log whose message mentions "offline".
func offlineWarns(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range logtest.Records(t, log) {
		msg, _ := rec["msg"].(string)
		if rec["level"] == "WARN" && strings.Contains(msg, "offline") {
			out = append(out, rec)
		}
	}
	return out
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("%s mode = %o, want 600", path, got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadOrInit_Rule3GeneratesBoth(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()

	ca, log := mustLoad(t, st, dir)

	for _, name := range []string{CAKeyFile, CABackupKeyFile} {
		assertMode0600(t, filepath.Join(dir, name))
	}
	rec, err := st.AgentCA().Get(t.Context())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(rec.ActiveDER, ca.Active.Raw) || !bytes.Equal(rec.BackupDER, ca.Backup.Raw) {
		t.Error("recorded DERs do not match the returned CA")
	}
	if ca.ActiveKey == nil || !ca.ActiveKey.PublicKey.Equal(ca.Active.PublicKey) {
		t.Error("ActiveKey does not match Active")
	}
	if ca.Active.Equal(ca.Backup) {
		t.Error("Active and Backup are the same certificate")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pending") {
			t.Errorf("leftover pending file %s", e.Name())
		}
	}

	warns := offlineWarns(t, log)
	if len(warns) != 1 {
		t.Fatalf("got %d offline WARN records, want exactly 1:\n%s", len(warns), log)
	}
	if msg, _ := warns[0]["msg"].(string); !strings.Contains(msg, "ca-backup.key") {
		t.Errorf("WARN msg = %q, want it to name ca-backup.key", msg)
	}
	if got, want := warns[0]["path"], filepath.Join(dir, CABackupKeyFile); got != want {
		t.Errorf("WARN path = %v, want %v", got, want)
	}
}

func TestLoadOrInit_Rule1UsesRecorded(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	first, _ := mustLoad(t, st, dir)

	type snap struct {
		data  []byte
		mtime time.Time
	}
	take := func() map[string]snap {
		m := map[string]snap{}
		for _, name := range []string{CAKeyFile, CABackupKeyFile} {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("stat %s: %v", name, err)
			}
			m[name] = snap{mustRead(t, filepath.Join(dir, name)), fi.ModTime()}
		}
		return m
	}
	before := take()

	second, _ := mustLoad(t, st, dir)

	if !bytes.Equal(first.Active.Raw, second.Active.Raw) {
		t.Error("second start returned a different Active CA")
	}
	if !bytes.Equal(first.Backup.Raw, second.Backup.Raw) {
		t.Error("second start returned a different Backup CA")
	}
	after := take()
	for name, b := range before {
		a := after[name]
		if !bytes.Equal(a.data, b.data) || !a.mtime.Equal(b.mtime) {
			t.Errorf("%s changed on the second start", name)
		}
	}
}

func TestLoadOrInit_BackupPresentWarnsEveryStart(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	mustLoad(t, st, dir)

	_, log := mustLoad(t, st, dir)
	warns := offlineWarns(t, log)
	if len(warns) != 1 {
		t.Fatalf("second start: got %d offline WARN records, want 1:\n%s", len(warns), log)
	}
	if got, want := warns[0]["path"], filepath.Join(dir, CABackupKeyFile); got != want {
		t.Errorf("WARN path = %v, want %v", got, want)
	}

	if err := os.Remove(filepath.Join(dir, CABackupKeyFile)); err != nil {
		t.Fatalf("remove backup key: %v", err)
	}
	_, log = mustLoad(t, st, dir)
	if warns := offlineWarns(t, log); len(warns) != 0 {
		t.Errorf("third start (backup key removed): got %d offline WARN records, want 0:\n%s", len(warns), log)
	}
}

func TestLoadOrInit_Rule2MissingKeyRefuses(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	mustLoad(t, st, dir)
	if err := os.Remove(filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatalf("remove ca.key: %v", err)
	}

	_, _, err := load(t, st, dir)

	if !errors.Is(err, ErrCAMissing) {
		t.Fatalf("err = %v, want ErrCAMissing", err)
	}
	for _, want := range []string{dir, "ca promote-backup", "ca reset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestLoadOrInit_Rule2MismatchedKeyRefuses(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	mustLoad(t, st, dir)

	// Swap in a different valid P-256 key, as if the volume belonged to another install.
	_, otherKey, err := newCACert(time.Now())
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}
	if err := writePending(dir, CAKeyFile, otherKey); err != nil {
		t.Fatalf("writePending: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "."+CAKeyFile+".pending"), filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if _, _, err := load(t, st, dir); !errors.Is(err, ErrCAMissing) {
		t.Fatalf("err = %v, want ErrCAMissing", err)
	}
}

func TestLoadOrInit_Rule4UnrecordedFilesRefuse(t *testing.T) {
	for _, name := range []string{AgentCertFile, CAKeyFile, CABackupKeyFile, AgentKeyFile} {
		t.Run(name, func(t *testing.T) {
			st, dir := newTestStore(t), t.TempDir()
			mustWrite(t, filepath.Join(dir, name))

			_, _, err := load(t, st, dir)

			if !errors.Is(err, ErrUnrecordedFiles) {
				t.Fatalf("err = %v, want ErrUnrecordedFiles", err)
			}
			for _, want := range []string{name, "restored from before mTLS", "must not overwrite a working CA"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if _, err := st.AgentCA().Get(t.Context()); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("a CA was recorded despite the refusal: err = %v", err)
			}
		})
	}
}

func TestLoadOrInit_IgnoresResetLeftovers(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	mustWrite(t, filepath.Join(dir, "ca.key.reset-20261106T120000Z"))
	mustWrite(t, filepath.Join(dir, "agent.crt.reset-20261106T120000Z"))

	ca, _ := mustLoad(t, st, dir)

	if ca.Active == nil {
		t.Fatal("no CA generated")
	}
}

func TestLoadOrInit_RollsForwardPendingAfterCrash(t *testing.T) {
	st, dir := newTestStore(t), t.TempDir()
	crash := func() error { return errors.New("simulated crash after insert") }

	if _, err := initFresh(t.Context(), st, dir, time.Now(), slog.New(slog.DiscardHandler), crash); err == nil {
		t.Fatal("initFresh succeeded despite the crash hook")
	}
	if _, err := os.Stat(filepath.Join(dir, CAKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ca.key exists after the simulated crash (err = %v); the hook must fire before the renames", err)
	}

	ca, _ := mustLoad(t, st, dir)

	key, err := readKey(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatalf("readKey after recovery: %v", err)
	}
	if !key.PublicKey.Equal(ca.Active.PublicKey) {
		t.Error("recovered ca.key does not match Active")
	}
	if _, err := readKey(filepath.Join(dir, CABackupKeyFile)); err != nil {
		t.Errorf("recovered ca-backup.key: %v", err)
	}
	for _, name := range []string{CAKeyFile, CABackupKeyFile} {
		assertMode0600(t, filepath.Join(dir, name))
	}
}

func TestRollForward_IgnoresMismatchedPending(t *testing.T) {
	dir := t.TempDir()
	c, k, err := newCACert(time.Now())
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}
	if err := writePending(dir, "k", k); err != nil {
		t.Fatalf("writePending: %v", err)
	}
	_, other, err := newCACert(time.Now())
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}

	moved, err := rollForward(dir, "k", &other.PublicKey)
	if err != nil || moved {
		t.Fatalf("rollForward(mismatch) = %v, %v; want false, nil", moved, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "k")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("mismatched pending was renamed (stat err = %v)", err)
	}

	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T, want *ecdsa.PublicKey", c.PublicKey)
	}
	if moved, err = rollForward(dir, "k", pub); err != nil || !moved {
		t.Fatalf("rollForward(match) = %v, %v; want true, nil", moved, err)
	}
	assertMode0600(t, filepath.Join(dir, "k"))
}

func TestFileNames(t *testing.T) {
	got := []string{CAKeyFile, CABackupKeyFile, AgentCertFile, AgentKeyFile, LockFile}
	want := []string{"ca.key", "ca-backup.key", "agent.crt", "agent.key", ".lock"}
	if !slices.Equal(got, want) {
		t.Errorf("file names = %v, want %v", got, want)
	}
}
