package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestPrune_RemovesExpiredRecords seeds one expired row in each of the three
// pruned tables and confirms prune() deletes all of them and reports
// accurate counts.
func TestPrune_RemovesExpiredRecords(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)

	past := store.NowUnix() - int64(time.Hour/time.Second)

	u, err := st.Users().Create(ctx, store.User{Email: "prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	if err := st.ReplayNonces().Insert(ctx, "expired-sig", past); err != nil {
		t.Fatalf("ReplayNonces().Insert: %v", err)
	}
	sess, err := st.Sessions().Create(ctx, store.Session{UserID: u.ID, ExpiresAt: past})
	if err != nil {
		t.Fatalf("Sessions().Create: %v", err)
	}
	if _, err := st.EnrollmentCodes().Create(ctx, store.EnrollmentCode{
		Code: "expired-code", UserID: u.ID, Label: "x", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("EnrollmentCodes().Create: %v", err)
	}

	prune(ctx, st, config.RetentionSection{}, discardLog())

	if exists, err := st.ReplayNonces().Exists(ctx, "expired-sig"); err != nil {
		t.Fatalf("ReplayNonces().Exists: %v", err)
	} else if exists {
		t.Error("expired replay nonce was not pruned")
	}
	if _, err := st.Sessions().GetByID(ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session was not pruned, GetByID err = %v", err)
	}
	if _, err := st.EnrollmentCodes().Get(ctx, "expired-code"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired enrollment code was not pruned, Get err = %v", err)
	}
}

// TestPrune_SweepsOIDCDeviceFlows confirms prune() also sweeps expired
// oidc_device_flows rows (T15) alongside the three tables covered above.
func TestPrune_SweepsOIDCDeviceFlows(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)

	if _, err := st.OIDCDeviceFlows().Create(ctx, store.OIDCDeviceFlow{
		FlowID: "old", DeviceCode: "d", Interval: 5, ExpiresAt: 1, CreatedAt: 1,
	}); err != nil {
		t.Fatalf("OIDCDeviceFlows().Create: %v", err)
	}

	prune(ctx, st, config.RetentionSection{}, discardLog())

	if _, err := st.OIDCDeviceFlows().Get(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expired oidc device flow pruned, got %v", err)
	}
}

// TestRunPruner_StopsOnContextCancel confirms the ticker goroutine exits
// promptly once ctx is cancelled — its only shutdown path.
func TestRunPruner_StopsOnContextCancel(t *testing.T) {
	st := openTestStore(t)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		runPruner(ctx, st, config.RetentionSection{}, discardLog())
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runPruner did not stop within 5s of ctx cancellation")
	}
}

// TestNew_WiresRetentionIntoTheServer guards the exact hazard #73 exists to
// fix: a Prune path that is fully implemented, fully tested, and never actually
// called in production. Every other retention test drives prune() or
// pruneRetention() directly, so dropping cfg.Retention on the floor in New
// would leave retention silently dead with the whole suite still green.
func TestNew_WiresRetentionIntoTheServer(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))
	v.Set("server.base_url", "https://ddns.example.com")
	v.Set("retention.ip_history_days", 90)
	v.Set("retention.ip_history_per_device_max", 500)
	v.Set("retention.audit_log_days", 365)
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	srv, err := New(cfg, openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.retention != cfg.Retention {
		t.Errorf("Server.retention = %+v, want %+v — retention never reaches runPruner", srv.retention, cfg.Retention)
	}
}

// TestPrune_SweepsExpiredAccountRecoveryTokens confirms step 5 runs even with
// retention fully disabled — it is expiry hygiene, not operator policy.
func TestPrune_SweepsExpiredAccountRecoveryTokens(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)

	u, err := st.Users().Create(ctx, store.User{Email: "ar-prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	past := store.NowUnix() - 3600
	// AccountRecoveryRepo.Create returns only an error, not the token.
	if err := st.AccountRecovery().Create(ctx, store.RecoveryToken{
		UserID: u.ID, TokenHash: "expired-recovery", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("AccountRecovery().Create: %v", err)
	}

	prune(ctx, st, config.RetentionSection{}, discardLog())

	var n int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_recovery_tokens WHERE token_hash = ?`, "expired-recovery",
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("expired recovery token survived prune(), count = %d, want 0", n)
	}
}
