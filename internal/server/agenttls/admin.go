//go:build linux || darwin

package agenttls

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jacaudi/diyddns/internal/shared/atomicfile"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrBackupKeyMismatch means the key given to PromoteBackup is neither the
// recorded backup CA's key nor, for a rerun, the recorded active CA's key.
var ErrBackupKeyMismatch = errors.New("agenttls: backup key does not match the recorded backup CA")

// Audit identity of the one agent_ca row; both operator commands write it.
const (
	auditTargetType     = "agent_ca"
	auditTargetID       = "1"
	eventBackupPromoted = "agent_ca.backup_promoted"
	eventReset          = "agent_ca.reset"
)

// noLocalBackupKeyMsg is logged when a rerun restored ca.key and no
// ca-backup.key is in the dir: without the offline copy, a new backup CA
// needs "ca reset".
const noLocalBackupKeyMsg = "no " + CABackupKeyFile + " in agent.tls.dir: the recorded backup CA's key must exist offline; " +
	`without it a new backup CA requires "diyddns-server ca reset"`

// PromoteResult reports what PromoteBackup did.
type PromoteResult struct {
	// Notes say, one operator-facing line each, what a rerun found and did;
	// empty on the run that promotes.
	Notes []string
	// NewBackupKeyPath is where a new ca-backup.key was installed by this call
	// and must be moved offline; empty when none was.
	NewBackupKeyPath string
}

// PromoteBackup makes the backup CA the active one. backupKeyPath is the
// offline copy of the backup CA's private key.
//
// It holds the dir lock throughout, so it fails with ErrLocked while the
// server runs. The key is checked against the backup certificate recorded in
// the database, so this works after the data directory is lost. The order is:
// generate a new backup CA and stage both keys under pending names, commit one
// transaction (active <- old backup, backup <- new, device certificates
// cleared), rename the staged keys into place, delete agent.crt/agent.key so
// the next start issues them from the new active CA, then write the audit
// entry. Re-running with the same key after any interruption finishes the
// leftovers and exits cleanly.
func PromoteBackup(ctx context.Context, st *store.Store, dir, backupKeyPath string, now time.Time, log *slog.Logger) (PromoteResult, error) {
	return promoteBackup(ctx, st, dir, backupKeyPath, now, log, nil)
}

// promoteBackup is PromoteBackup with afterTx, nil in production, which runs
// after the promotion transaction commits and before the key files are renamed
// into place, so a test can simulate a crash there.
func promoteBackup(ctx context.Context, st *store.Store, dir, backupKeyPath string, now time.Time, log *slog.Logger, afterTx func() error) (res PromoteResult, err error) {
	lock, err := AcquireLock(dir)
	if err != nil {
		return PromoteResult{}, err
	}
	defer func() { err = errors.Join(err, lock.Release()) }()

	rec, err := st.AgentCA().Get(ctx)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("agenttls: read recorded agent CA: %w", err)
	}
	active, backup, err := parseRecorded(rec)
	if err != nil {
		return PromoteResult{}, err
	}
	key, err := readKey(backupKeyPath)
	if err != nil {
		return PromoteResult{}, err
	}

	switch {
	case key.PublicKey.Equal(active.PublicKey):
		return finishPromotion(ctx, st, dir, active, backup, key, log)
	case !key.PublicKey.Equal(backup.PublicKey):
		return PromoteResult{}, fmt.Errorf("%w: %s", ErrBackupKeyMismatch, backupKeyPath)
	}

	newBackup, newBackupKey, err := newCACert(now)
	if err != nil {
		return PromoteResult{}, err
	}
	if err := writePending(dir, CAKeyFile, key); err != nil {
		return PromoteResult{}, err
	}
	if err := writePending(dir, CABackupKeyFile, newBackupKey); err != nil {
		return PromoteResult{}, err
	}
	if err := st.AgentCA().Promote(ctx, store.AgentCA{ActiveDER: rec.BackupDER, BackupDER: newBackup.Raw}); err != nil {
		return PromoteResult{}, fmt.Errorf("agenttls: record promoted agent CA: %w", err)
	}
	if afterTx != nil {
		if err := afterTx(); err != nil {
			return PromoteResult{}, err
		}
	}
	if err := installAndAudit(ctx, st, dir, backup, newBackup); err != nil {
		return PromoteResult{}, err
	}
	return PromoteResult{NewBackupKeyPath: filepath.Join(dir, CABackupKeyFile)}, nil
}

// installAndAudit is the post-commit tail of a promotion: both staged keys
// must land, the serving cert is dropped for re-issue, and the audit row
// records the promotion with the CAs now active and standing by.
func installAndAudit(ctx context.Context, st *store.Store, dir string, active, backup *x509.Certificate) error {
	rolledActive, rolledBackup, err := rollBoth(dir, active, backup)
	if err != nil {
		return err
	}
	if !rolledActive || !rolledBackup {
		return fmt.Errorf("agenttls: install promoted CA keys (active=%v backup=%v)", rolledActive, rolledBackup)
	}
	if err := removeAgentFiles(dir); err != nil {
		return err
	}
	return auditPromoted(ctx, st, active, backup)
}

// finishPromotion is the rerun path: the database already holds the promoted
// pair. It completes whatever a crashed run left (staged key renames, agent
// files), writes the audit row that run never reached when it had to, and
// restores ca.key from the supplied key (which is the active CA's) when the
// volume lost or replaced it after the transaction committed; startup would
// otherwise refuse under rule 2 and point back at this command.
func finishPromotion(ctx context.Context, st *store.Store, dir string, active, backup *x509.Certificate, key *ecdsa.PrivateKey, log *slog.Logger) (PromoteResult, error) {
	rolledActive, rolledBackup, err := rollBoth(dir, active, backup)
	if err != nil {
		return PromoteResult{}, err
	}
	if err := removeAgentFiles(dir); err != nil {
		return PromoteResult{}, err
	}
	restored, err := restoreActiveKey(dir, key)
	if err != nil {
		return PromoteResult{}, err
	}
	var res PromoteResult
	switch {
	case restored:
		res.Notes = []string{"Backup CA already promoted.", fmt.Sprintf("Restored %s from --backup-key.", filepath.Join(dir, CAKeyFile))}
		if _, statErr := os.Stat(filepath.Join(dir, CABackupKeyFile)); errors.Is(statErr, fs.ErrNotExist) {
			log.Warn(noLocalBackupKeyMsg, "dir", dir)
		}
	case rolledBackup:
		res.Notes = []string{"Backup CA already promoted."}
	default:
		res.Notes = []string{"Backup CA already promoted; nothing to do."}
	}
	if rolledBackup {
		res.NewBackupKeyPath = filepath.Join(dir, CABackupKeyFile)
	}
	if rolledActive || rolledBackup {
		// The crashed run's renames come before its audit write, so a rename
		// happening now means that audit row is missing.
		if err := auditPromoted(ctx, st, active, backup); err != nil {
			return PromoteResult{}, err
		}
	}
	return res, nil
}

// restoreActiveKey installs key as ca.key unless ca.key already holds it. A
// ca.key that is missing, unreadable, or someone else's counts as lost.
func restoreActiveKey(dir string, key *ecdsa.PrivateKey) (bool, error) {
	if cur, err := readKey(filepath.Join(dir, CAKeyFile)); err == nil && cur.PublicKey.Equal(&key.PublicKey) {
		return false, nil
	}
	if err := writePending(dir, CAKeyFile, key); err != nil {
		return false, err
	}
	ok, err := rollForward(dir, CAKeyFile, &key.PublicKey)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("agenttls: restore %s did not install", CAKeyFile)
	}
	return true, nil
}

// parseRecorded parses the recorded pair; both certificates must be ECDSA.
func parseRecorded(rec store.AgentCA) (active, backup *x509.Certificate, err error) {
	if active, err = x509.ParseCertificate(rec.ActiveDER); err != nil {
		return nil, nil, fmt.Errorf("agenttls: parse recorded active CA: %w", err)
	}
	if backup, err = x509.ParseCertificate(rec.BackupDER); err != nil {
		return nil, nil, fmt.Errorf("agenttls: parse recorded backup CA: %w", err)
	}
	for _, c := range []*x509.Certificate{active, backup} {
		if _, err := ecPublicKey(c); err != nil {
			return nil, nil, err
		}
	}
	return active, backup, nil
}

// rollBoth renames whichever staged CA key files match the given (ECDSA)
// certificates into place and reports which it renamed.
func rollBoth(dir string, active, backup *x509.Certificate) (rolledActive, rolledBackup bool, err error) {
	activePub, err := ecPublicKey(active)
	if err != nil {
		return false, false, err
	}
	backupPub, err := ecPublicKey(backup)
	if err != nil {
		return false, false, err
	}
	if rolledActive, err = rollForward(dir, CAKeyFile, activePub); err != nil {
		return false, false, err
	}
	if rolledBackup, err = rollForward(dir, CABackupKeyFile, backupPub); err != nil {
		return false, false, err
	}
	return rolledActive, rolledBackup, nil
}

// removeAgentFiles deletes the serving cert and key, ignoring absent ones, so
// the next start issues them from the now-active CA.
func removeAgentFiles(dir string) error {
	for _, name := range []string{AgentCertFile, AgentKeyFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("agenttls: remove %s: %w", name, err)
		}
	}
	return atomicfile.SyncDir(dir)
}

// Reset is the last resort: it deletes the recorded CA pair, clears every
// device's certificate, and renames each ca*.key and agent.* file in dir to
// <name>.reset-<now UTC 20060102T150405Z>, returning the new paths. The next
// start generates a fresh pair. It takes the dir lock, so it fails with
// ErrLocked while the server runs, and re-running it is harmless (it still
// writes an audit row: each invocation is an operator action).
func Reset(ctx context.Context, st *store.Store, dir string, now time.Time) ([]string, error) {
	lock, err := AcquireLock(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Release() }() // closing a flock'd fd cannot lose data

	if err := st.AgentCA().Reset(ctx); err != nil {
		return nil, fmt.Errorf("agenttls: reset recorded agent CA: %w", err)
	}
	// Same selection the startup rules use for stray files: ca*.key and
	// agent.*, excluding dotfiles and earlier *.reset-<ts> leftovers.
	files, err := unrecordedFiles(dir)
	if err != nil {
		return nil, err
	}
	suffix := ".reset-" + now.UTC().Format("20060102T150405Z")
	var renamed []string
	for _, name := range files {
		to := filepath.Join(dir, name+suffix)
		if err := os.Rename(filepath.Join(dir, name), to); err != nil {
			return renamed, fmt.Errorf("agenttls: rename %s: %w", name, err)
		}
		renamed = append(renamed, to)
	}
	if len(renamed) > 0 {
		if err := atomicfile.SyncDir(dir); err != nil {
			return renamed, err
		}
	}
	if err := appendAudit(ctx, st, eventReset, map[string]int{"renamed": len(renamed)}); err != nil {
		return renamed, err
	}
	return renamed, nil
}

// auditPromoted records a promotion with the CAs now active and standing by.
func auditPromoted(ctx context.Context, st *store.Store, active, backup *x509.Certificate) error {
	return appendAudit(ctx, st, eventBackupPromoted,
		map[string]string{"active_cn": active.Subject.CommonName, "backup_cn": backup.Subject.CommonName})
}

// appendAudit records an operator action on the agent CA; there is no acting
// user for a command run on the host.
func appendAudit(ctx context.Context, st *store.Store, event string, details any) error {
	b, err := json.Marshal(details) // map[string]string / map[string]int cannot fail to marshal
	if err != nil {
		return fmt.Errorf("agenttls: audit details: %w", err)
	}
	_, err = st.AuditLog().Append(ctx, store.AuditEntry{
		EventType:   event,
		TargetType:  auditTargetType,
		TargetID:    auditTargetID,
		DetailsJSON: string(b),
	})
	if err != nil {
		return fmt.Errorf("agenttls: audit %s: %w", event, err)
	}
	return nil
}
