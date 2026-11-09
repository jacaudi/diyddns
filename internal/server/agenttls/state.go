package agenttls

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

var (
	// ErrCAMissing means the database records a CA whose key is not on the
	// volume (startup rule 2).
	ErrCAMissing = errors.New("agenttls: agent CA key unavailable")
	// ErrUnrecordedFiles means CA or agent files exist in the directory but the
	// database records no CA (startup rule 4).
	ErrUnrecordedFiles = errors.New("agenttls: CA files present but no CA recorded in the database")
)

// LoadOrInit applies the startup rules for the agent CA in dir:
//
//  1. a CA is recorded and ca.key matches it: use it;
//  2. a CA is recorded and ca.key is missing or does not match: refuse
//     (ErrCAMissing);
//  3. nothing is recorded and dir holds no ca*.key or agent.* files: generate
//     the active and backup CAs;
//  4. nothing is recorded but such files exist: refuse (ErrUnrecordedFiles),
//     since a database restored from before mTLS must not overwrite a working CA.
//
// Whenever ca-backup.key is still in dir it warns that the file belongs
// offline. The caller owns the dir lock and must hold it across this call.
func LoadOrInit(ctx context.Context, st *store.Store, dir string, now time.Time, log *slog.Logger) (*CA, error) {
	rec, err := st.AgentCA().Get(ctx)
	switch {
	case err == nil:
		return loadRecorded(dir, rec, log)
	case errors.Is(err, store.ErrNotFound):
		return initFresh(ctx, st, dir, now, log, nil)
	default:
		return nil, fmt.Errorf("agenttls: read recorded agent CA: %w", err)
	}
}

// loadRecorded is startup rule 1 (and rule 2 when the key is wrong).
func loadRecorded(dir string, rec store.AgentCA, log *slog.Logger) (*CA, error) {
	active, err := x509.ParseCertificate(rec.ActiveDER)
	if err != nil {
		return nil, fmt.Errorf("agenttls: parse recorded active CA: %w", err)
	}
	backup, err := x509.ParseCertificate(rec.BackupDER)
	if err != nil {
		return nil, fmt.Errorf("agenttls: parse recorded backup CA: %w", err)
	}
	activePub, err := ecPublicKey(active)
	if err != nil {
		return nil, err
	}
	backupPub, err := ecPublicKey(backup)
	if err != nil {
		return nil, err
	}

	if _, err := rollForward(dir, CAKeyFile, activePub); err != nil {
		return nil, err
	}
	if _, err := rollForward(dir, CABackupKeyFile, backupPub); err != nil {
		return nil, err
	}

	keyPath := filepath.Join(dir, CAKeyFile)
	key, err := readKey(keyPath)
	if err != nil {
		return nil, errCAMissing(dir, keyPath, err)
	}
	if !key.PublicKey.Equal(activePub) {
		return nil, errCAMissing(dir, keyPath, nil)
	}

	warnBackupPresent(dir, "move the backup CA key offline", log)
	return &CA{Active: active, ActiveKey: key, Backup: backup}, nil
}

// errCAMissing builds the rule 2 refusal; cause, when set, says why the key
// could not be used (it never carries key material).
func errCAMissing(dir, keyPath string, cause error) error {
	err := fmt.Errorf("%w: agent CA is recorded in the database but %s is missing or does not match: "+
		"the CA volume (agent.tls.dir = %s) is missing or wrong; restore it, "+
		`or run "diyddns-server ca promote-backup --backup-key <path>" `+
		`or, as a last resort, "diyddns-server ca reset --confirm"`,
		ErrCAMissing, keyPath, dir)
	if cause != nil {
		return fmt.Errorf("%w: %w", err, cause)
	}
	return err
}

// initFresh is startup rules 4 and 3: refuse on stray files, otherwise
// generate both CAs. All crypto runs before the single Insert, so no
// transaction is open while keys are generated. afterInsert, nil in
// production, runs after the CA row is committed and before the key files are
// renamed into place, so a test can simulate a crash there.
func initFresh(ctx context.Context, st *store.Store, dir string, now time.Time, log *slog.Logger, afterInsert func() error) (*CA, error) {
	stray, err := unrecordedFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(stray) > 0 {
		return nil, fmt.Errorf("%w: found %s in %s but the database records no agent CA "+
			"(a database restored from before mTLS must not overwrite a working CA); "+
			"restore the current database, or move these files aside to start with a new CA",
			ErrUnrecordedFiles, strings.Join(stray, ", "), dir)
	}

	active, activeKey, err := newCACert(now)
	if err != nil {
		return nil, err
	}
	backup, backupKey, err := newCACert(now)
	if err != nil {
		return nil, err
	}
	if err := writePending(dir, CAKeyFile, activeKey); err != nil {
		return nil, err
	}
	if err := writePending(dir, CABackupKeyFile, backupKey); err != nil {
		return nil, err
	}
	if err := st.AgentCA().Insert(ctx, store.AgentCA{ActiveDER: active.Raw, BackupDER: backup.Raw}); err != nil {
		return nil, fmt.Errorf("agenttls: record generated agent CA: %w", err)
	}
	if afterInsert != nil {
		if err := afterInsert(); err != nil {
			return nil, err
		}
	}
	for name, key := range map[string]*ecdsa.PrivateKey{CAKeyFile: activeKey, CABackupKeyFile: backupKey} {
		if ok, err := rollForward(dir, name, &key.PublicKey); err != nil || !ok {
			return nil, errors.Join(fmt.Errorf("agenttls: install %s (installed=%v)", name, ok), err)
		}
	}

	warnBackupPresent(dir, "agent CA generated: move ca-backup.key offline", log)
	return &CA{Active: active, ActiveKey: activeKey, Backup: backup}, nil
}

// unrecordedFiles lists the ca*.key and agent.* files in dir. Hidden files
// (the lock, staging files) and *.reset-<ts> leftovers from "ca reset" do not
// count.
//
// It matches with path.Match on directory entries rather than filepath.Glob on
// dir/pattern so a dir containing glob metacharacters cannot hide a match.
func unrecordedFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("agenttls: scan %s: %w", dir, err)
	}
	var found []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.Contains(name, ".reset-") {
			continue
		}
		for _, pattern := range []string{"ca*.key", "agent.*"} {
			if ok, _ := path.Match(pattern, name); ok { // patterns are constant and valid
				found = append(found, name)
				break
			}
		}
	}
	return found, nil
}

// warnBackupPresent logs msg when ca-backup.key is still on the volume.
func warnBackupPresent(dir, msg string, log *slog.Logger) {
	p := filepath.Join(dir, CABackupKeyFile)
	if _, err := os.Stat(p); err == nil {
		log.Warn(msg, "path", p)
	}
}

// ecPublicKey returns cert's public key as an ECDSA key.
func ecPublicKey(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("agenttls: recorded CA %q has a %T key, want ECDSA", cert.Subject.CommonName, cert.PublicKey)
	}
	return pub, nil
}
