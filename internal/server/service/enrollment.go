// Package service implements DIYDDNS's server application services — the
// workflow layer between HTTP handlers and internal/store. Services own
// business logic (validation, compensating actions, auditing) and depend on
// the concrete *store.Store, which is itself integration-tested against a
// real SQLite database.
package service

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// codeRejectedMsg is the log message for a rejected enrollment code.
const codeRejectedMsg = "enrollment code rejected"

// ClientMeta captures device-identifying details reported by a client during
// enrollment or check-in.
type ClientMeta struct {
	Hostname      string
	OS            string
	ClientVersion string
}

// EnrollResult is returned to a freshly-enrolled device. Secret is the
// plaintext HMAC secret — it is shown to the caller exactly once and is
// never persisted or logged in the clear (the store only ever holds the
// AEAD-sealed form).
type EnrollResult struct {
	DeviceID string
	Secret   []byte
}

// AuditSink records audit log entries. Implementations must never fail the
// caller's primary operation — auditing is a side effect, not a
// precondition.
type AuditSink interface {
	Log(ctx context.Context, e store.AuditEntry)
}

// auditWriter is the concrete AuditSink backed by a *store.Store. Append
// failures are swallowed by design: auditing must never fail the operation
// it is attached to.
type auditWriter struct {
	st *store.Store
}

// NewAuditWriter returns an AuditSink that persists entries via
// st.AuditLog().Append, ignoring append errors.
func NewAuditWriter(st *store.Store) AuditSink {
	return &auditWriter{st: st}
}

// Log appends e to the audit log. Append errors are intentionally discarded;
// a failed audit write must never fail the caller's primary operation.
func (w *auditWriter) Log(ctx context.Context, e store.AuditEntry) {
	_, _ = w.st.AuditLog().Append(ctx, e)
}

// EnrollmentService turns single-use enrollment codes into registered devices
// with AEAD-sealed HMAC secrets.
type EnrollmentService struct {
	st      *store.Store
	key     []byte
	codeTTL time.Duration
	audit   AuditSink
	log     *slog.Logger
}

// NewEnrollmentService constructs an EnrollmentService. key is the 32-byte
// AEAD key used to seal device secrets (see auth.SealSecret); codeTTL is how
// long a freshly-minted enrollment code stays valid; log receives the reason
// ConsumeCode rejects a code.
func NewEnrollmentService(st *store.Store, key []byte, codeTTL time.Duration, audit AuditSink, log *slog.Logger) *EnrollmentService {
	return &EnrollmentService{st: st, key: key, codeTTL: codeTTL, audit: audit, log: log}
}

// CreateCode mints a single-use enrollment code for userID, valid for the
// service's codeTTL, and returns the code plus its expiry (unix seconds).
// label becomes the enrolled device's label once the code is consumed. No
// audit entry is written here — device.enroll.code fires on ConsumeCode.
func (s *EnrollmentService) CreateCode(ctx context.Context, userID, label string) (string, int64, error) {
	code, err := auth.RandToken(16)
	if err != nil {
		return "", 0, fmt.Errorf("service.CreateCode: %w", err)
	}
	expiresAt := store.NowUnix() + int64(s.codeTTL/time.Second)
	if _, err := s.st.EnrollmentCodes().Create(ctx, store.EnrollmentCode{
		Code:      code,
		UserID:    userID,
		Label:     label,
		ExpiresAt: expiresAt,
	}); err != nil {
		return "", 0, fmt.Errorf("service.CreateCode: %w", err)
	}
	return code, expiresAt, nil
}

// createSealedDevice mints a fresh HMAC secret, seals it under the service's
// AEAD key, and creates the device record. Shared by ConsumeCode and
// EnrollForUser: issuing a device's sealed secret is the same operation
// regardless of how the caller authenticated, so both flows must stay in
// lockstep if it changes.
func (s *EnrollmentService) createSealedDevice(ctx context.Context, userID, label string, meta ClientMeta) (store.Device, []byte, error) {
	secret, err := auth.GenerateSecret()
	if err != nil {
		return store.Device{}, nil, err
	}
	sealed, err := auth.SealSecret(s.key, secret)
	if err != nil {
		return store.Device{}, nil, err
	}
	dev, err := s.st.Devices().Create(ctx, store.Device{
		UserID:        userID,
		Label:         label,
		SecretHash:    sealed,
		Hostname:      meta.Hostname,
		OS:            meta.OS,
		ClientVersion: meta.ClientVersion,
	})
	if err != nil {
		return store.Device{}, nil, err
	}
	return dev, secret, nil
}

// ConsumeCode redeems a single-use enrollment code: validates it, mints and
// seals a fresh HMAC secret, and creates the device. If the code's single-use
// Consume fails after the device was created, the device is
// compensating-deleted so a failed code-consume never leaves an orphan
// device behind.
//
// A code that cannot be redeemed (unknown, expired, used, or lost to a
// concurrent redeem) is logged with its reason at Info and returned as a
// wrapped store.ErrNotFound, so the response stays uniform. A valid, unused
// code whose label is already taken on the account is logged the same way
// (label_conflict) and returned as a wrapped store.ErrConflict, leaving the code
// unconsumed; see conflictRejection for how that is told apart from a lost
// race. The code itself is never logged.
func (s *EnrollmentService) ConsumeCode(ctx context.Context, code string, meta ClientMeta) (EnrollResult, error) {
	c, err := s.st.EnrollmentCodes().Get(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			logRejected(ctx, s.log, codeRejectedMsg, rejectUnknown, "")
		}
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", err) // ErrNotFound flows up
	}
	now := store.NowUnix()
	switch {
	case c.UsedAt != 0:
		logRejected(ctx, s.log, codeRejectedMsg, rejectUsed, c.UserID)
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound)
	case c.ExpiresAt <= now:
		logRejected(ctx, s.log, codeRejectedMsg, rejectExpired, c.UserID)
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound)
	}

	dev, secret, err := s.createSealedDevice(ctx, c.UserID, c.Label, meta)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return EnrollResult{}, s.conflictRejection(ctx, code, c, err)
		}
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", err)
	}

	if _, err := s.st.EnrollmentCodes().Consume(ctx, code, dev.ID, now); err != nil {
		s.rollbackDevice(ctx, dev.ID) // compensating delete: no orphan device on a failed consume
		if errors.Is(err, store.ErrNotFound) {
			// The pre-check passed, so a concurrent redeem won the atomic Consume.
			logRejected(ctx, s.log, codeRejectedMsg, rejectLostRace, c.UserID)
		}
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", err)
	}

	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: c.UserID,
		EventType:   "device.enroll.code",
		TargetType:  "device",
		TargetID:    dev.ID,
	})
	return EnrollResult{DeviceID: dev.ID, Secret: secret}, nil
}

// conflictRejection classifies a store.ErrConflict from creating the code's
// device and returns the error ConsumeCode must return. A conflict has two
// causes. A same-code race looks like one: two requests redeem one code, both
// pass the pre-check, and the winner's device already holds the (user, label),
// so the loser's insert fails before it reaches Consume. A real label clash is
// a different code (or device) holding the label. They are told apart by
// re-reading the code, which happens only on this conflict path: if it is now
// used, a concurrent redeem of this same code won, so the reason is lost_race and
// the error is a wrapped store.ErrNotFound (the uniform 401). Otherwise the
// reason is label_conflict and the original conflict is returned wrapped (the
// 409); a failed re-read is treated the same way.
//
// Residual window: between the winner's insert and its consume the code still
// reads as unused, so a loser landing in that instant is answered 409. Closing
// it needs the insert and the consume in one store transaction, which is
// outside this change.
func (s *EnrollmentService) conflictRejection(ctx context.Context, code string, c store.EnrollmentCode, err error) error {
	if fresh, getErr := s.st.EnrollmentCodes().Get(ctx, code); getErr == nil && fresh.UsedAt != 0 {
		logRejected(ctx, s.log, codeRejectedMsg, rejectLostRace, c.UserID)
		return fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound)
	}
	logRejected(ctx, s.log, codeRejectedMsg, rejectLabelConflict, c.UserID)
	return fmt.Errorf("service.ConsumeCode: %w", err)
}

// rollbackDevice is ConsumeCode's compensating delete. It runs on a context
// that survives cancellation: a Consume that failed because the request's
// context ended would otherwise make this delete fail for the same reason and
// leave an orphan device, which the next redeem of the same code would then
// meet as a label conflict. A failed delete is logged at Error with the device
// id, never discarded: an orphan device is a real, operator-visible fault.
func (s *EnrollmentService) rollbackDevice(ctx context.Context, deviceID string) {
	if err := s.st.Devices().Delete(context.WithoutCancel(ctx), deviceID); err != nil {
		s.log.LogAttrs(ctx, slog.LevelError, "enrollment compensating delete failed",
			slog.String("device_id", deviceID), slog.Any("error", err))
	}
}

// EnrollForUser mints and seals a fresh device for an already-authenticated
// user — the shared tail of every non-code enrollment path (e.g. the OIDC
// device-code poll). label defaults to meta.Hostname, or "device" when
// empty. eventType is the audit event to record (e.g.
// "device.enroll.oidc"), letting each authenticated path own its own audit
// trail while sharing this single enrollment operation.
func (s *EnrollmentService) EnrollForUser(ctx context.Context, userID, eventType string, meta ClientMeta) (EnrollResult, error) {
	label := cmp.Or(meta.Hostname, "device")
	dev, secret, err := s.createSealedDevice(ctx, userID, label, meta)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.EnrollForUser: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID,
		EventType:   eventType,
		TargetType:  "device",
		TargetID:    dev.ID,
	})
	return EnrollResult{DeviceID: dev.ID, Secret: secret}, nil
}
