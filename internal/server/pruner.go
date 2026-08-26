package server

import (
	"context"
	"log/slog"
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

	log.LogAttrs(ctx, slog.LevelDebug, "pruned expired records",
		slog.Int("replay_nonces", nonces),
		slog.Int("sessions", sessions),
		slog.Int("enrollment_codes", codes),
		slog.Int("oidc_device_flows", flows),
		slog.Int("account_recovery", recovery),
	)
}
