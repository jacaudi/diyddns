package server

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// prunerInterval is how often the background pruner sweeps. It is deliberately
// a constant and deliberately does NOT join the retention.* config section:
// retention windows are day-granular, so an hourly sweep is already 24x finer
// than the finest policy any operator can express, and no present requirement
// is served by making it configurable.
const prunerInterval = time.Hour

// pruneBatchSize bounds how many rows a single retention DELETE removes, so a
// sweep of a large backlog cannot monopolise the process's single SQLite
// connection (store.Open sets SetMaxOpenConns(1), so a long statement blocks
// every database access, not just writes).
//
// It is a var rather than a const solely so the drain test can lower it; there
// is no YAML key, env var or flag, and any test that writes it MUST restore it
// via t.Cleanup — package server uses no t.Parallel(), so an unrestored write
// silently lowers the batch size for every later test in the package.
var pruneBatchSize = 5000

// runPruner sweeps expired records every prunerInterval until ctx is
// cancelled. Started as a goroutine by Server.Run; ctx cancellation is its
// only shutdown path.
func runPruner(ctx context.Context, st *store.Store, ret config.RetentionSection, log *slog.Logger) {
	ticker := time.NewTicker(prunerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune(ctx, st, ret, log)
		}
	}
}

// prune sweeps replay_nonces, sessions, enrollment_codes, oidc_device_flows and
// account_recovery_tokens for expired rows, then applies the operator's
// retention policy to ip_history and audit_log, and logs the counts removed.
//
// Each sweep runs independently — a failure in one does not block the others —
// and failures are logged (there is no caller to report them to).
func prune(ctx context.Context, st *store.Store, ret config.RetentionSection, log *slog.Logger) {
	now := store.NowUnix()

	nonces, err := st.ReplayNonces().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune replay_nonces failed", slog.Any("error", err))
	}
	sessions, err := st.Sessions().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune sessions failed", slog.Any("error", err))
	}
	codes, err := st.EnrollmentCodes().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune enrollment_codes failed", slog.Any("error", err))
	}
	flows, err := st.OIDCDeviceFlows().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune oidc_device_flows failed", slog.Any("error", err))
	}
	recovery, err := st.AccountRecovery().PruneExpired(ctx, now)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune account_recovery_tokens failed", slog.Any("error", err))
	}

	ipRows, auditRows := pruneRetention(ctx, st, ret, log)
	if ipRows+auditRows > 0 {
		// The empty actor is the established encoding for a system event; the
		// web UI renders it as "system". Logged rather than swallowed on
		// failure: every other audit writer goes through service.AuditSink,
		// which discards Append errors by design, but prune() has no AuditSink
		// and this row is the only durable record that deletion happened.
		if _, err := st.AuditLog().Append(ctx, store.AuditEntry{EventType: "retention.prune"}); err != nil {
			log.LogAttrs(ctx, slog.LevelWarn, "append retention.prune audit event failed", slog.Any("error", err))
		}
	}

	log.LogAttrs(ctx, slog.LevelDebug, "pruned expired records",
		slog.Int("replay_nonces", nonces),
		slog.Int("sessions", sessions),
		slog.Int("enrollment_codes", codes),
		slog.Int("oidc_device_flows", flows),
		slog.Int("account_recovery", recovery),
		slog.Int("ip_history", ipRows),
		slog.Int("audit_log", auditRows),
	)
}

// pruneRetention applies the operator's retention policy. It returns the number
// of ip_history and audit_log rows actually deleted; both are running totals of
// COMMITTED rows, so a drain that commits one batch and then fails still
// reports what it committed. Zeroing them on error would suppress the audit
// record of thousands of irreversible deletions.
//
// A policy whose keys are all zero costs nothing: neither pass is entered.
func pruneRetention(ctx context.Context, st *store.Store, ret config.RetentionSection, log *slog.Logger) (ipRows, auditRows int) {
	now := store.NowUnix()
	if ret.IPHistoryDays > 0 || ret.IPHistoryPerDeviceMax > 0 {
		ipRows = pruneIPHistory(ctx, st, ret, now, log)
	}
	if ret.AuditLogDays > 0 {
		auditRows = pruneAuditLog(ctx, st, now-int64(ret.AuditLogDays)*86400, log)
	}
	return ipRows, auditRows
}

// pruneIPHistory drains ip_history for every device.
//
// INVARIANT: a disabled age window is math.MinInt64, NEVER now. IPHistoryRepo
// .Prune ORs the age and cap policies, so olderThan = now matches every row and
// would silently delete every device's whole history but its newest row.
//
// A failed batch ends THAT DEVICE's drain and moves to the next device: it
// never retries (retrying inside a sweep holding the sole connection turns a
// transient error into sustained contention — the next hourly tick is the
// retry), and it never aborts the outer loop (ListAll orders by created_at
// DESC, so aborting would let one bad device permanently starve every device
// ordered after it, visible only as a Warn line).
func pruneIPHistory(ctx context.Context, st *store.Store, ret config.RetentionSection, now int64, log *slog.Logger) int {
	olderThan := int64(math.MinInt64)
	if ret.IPHistoryDays > 0 {
		olderThan = now - int64(ret.IPHistoryDays)*86400
	}
	devices, err := st.Devices().ListAll(ctx)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelWarn, "prune ip_history: list devices failed", slog.Any("error", err))
		return 0
	}
	var deleted int
	for _, dev := range devices {
		for {
			n, err := st.IPHistory().Prune(ctx, dev.ID, olderThan, ret.IPHistoryPerDeviceMax, pruneBatchSize)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelWarn, "prune ip_history failed",
					slog.String("device_id", dev.ID), slog.Any("error", err))
				break
			}
			deleted += n
			if n == 0 {
				break
			}
		}
	}
	return deleted
}

// pruneAuditLog drains audit_log rows older than cutoff. A failed batch ends the
// drain and keeps the count already committed.
func pruneAuditLog(ctx context.Context, st *store.Store, cutoff int64, log *slog.Logger) int {
	var deleted int
	for {
		n, err := st.AuditLog().Prune(ctx, cutoff, pruneBatchSize)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelWarn, "prune audit_log failed", slog.Any("error", err))
			break
		}
		deleted += n
		if n == 0 {
			break
		}
	}
	return deleted
}
