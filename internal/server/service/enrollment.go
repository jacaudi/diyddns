// Package service implements DIYDDNS's server application services — the
// workflow layer between HTTP handlers and internal/store. Services own
// business logic (validation, compensating actions, auditing) and depend on
// the concrete *store.Store, which is itself integration-tested against a
// real SQLite database.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

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

// errInvalidCredentials is returned uniformly for every credential-enrollment
// failure mode (unknown email, disabled account, OIDC-only account with no
// password hash, wrong password) so callers cannot distinguish "no such
// user" from "wrong password".
var errInvalidCredentials = errors.New("service: invalid credentials")

// EnrollmentService turns single-use enrollment codes and email/password
// credentials into registered devices with AEAD-sealed HMAC secrets.
type EnrollmentService struct {
	st      *store.Store
	key     []byte
	codeTTL time.Duration
	audit   AuditSink
}

// NewEnrollmentService constructs an EnrollmentService. key is the 32-byte
// AEAD key used to seal device secrets (see auth.SealSecret); codeTTL is how
// long a freshly-minted enrollment code stays valid.
func NewEnrollmentService(st *store.Store, key []byte, codeTTL time.Duration, audit AuditSink) *EnrollmentService {
	return &EnrollmentService{st: st, key: key, codeTTL: codeTTL, audit: audit}
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
// EnrollCredentials: issuing a device's sealed secret is the same operation
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
func (s *EnrollmentService) ConsumeCode(ctx context.Context, code string, meta ClientMeta) (EnrollResult, error) {
	c, err := s.st.EnrollmentCodes().Get(ctx, code)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", err) // ErrNotFound flows up
	}
	now := store.NowUnix()
	if c.UsedAt != 0 || c.ExpiresAt <= now {
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound)
	}

	dev, secret, err := s.createSealedDevice(ctx, c.UserID, c.Label, meta)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.ConsumeCode: %w", err)
	}

	if _, err := s.st.EnrollmentCodes().Consume(ctx, code, dev.ID, now); err != nil {
		_ = s.st.Devices().Delete(ctx, dev.ID) // compensating-delete: no orphan device on a failed consume
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

// EnrollForUser mints and seals a fresh device for an already-authenticated
// user — the shared tail of every non-code enrollment path (e.g. the OIDC
// device-code poll). label defaults to meta.Hostname, or "device" when
// empty. eventType is the audit event to record (e.g.
// "device.enroll.oidc"), letting each authenticated path own its own audit
// trail while sharing this single enrollment operation.
func (s *EnrollmentService) EnrollForUser(ctx context.Context, userID, eventType string, meta ClientMeta) (EnrollResult, error) {
	label := meta.Hostname
	if label == "" {
		label = "device"
	}
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

// EnrollCredentials authenticates a user by email/password and enrolls a new
// device for them — the credential-based counterpart to ConsumeCode. label
// defaults to "device" when meta.Hostname is empty.
func (s *EnrollmentService) EnrollCredentials(ctx context.Context, email, password string, meta ClientMeta) (EnrollResult, error) {
	u, err := s.st.Users().GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return EnrollResult{}, errInvalidCredentials
		}
		return EnrollResult{}, fmt.Errorf("service.EnrollCredentials: %w", err)
	}
	if u.Disabled || u.PasswordHash == "" {
		return EnrollResult{}, errInvalidCredentials
	}
	ok, err := auth.VerifyPassword(u.PasswordHash, password)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.EnrollCredentials: %w", err)
	}
	if !ok {
		return EnrollResult{}, errInvalidCredentials
	}

	label := meta.Hostname
	if label == "" {
		label = "device"
	}
	dev, secret, err := s.createSealedDevice(ctx, u.ID, label, meta)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("service.EnrollCredentials: %w", err)
	}

	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: u.ID,
		EventType:   "device.enroll.credentials",
		TargetType:  "device",
		TargetID:    dev.ID,
	})
	return EnrollResult{DeviceID: dev.ID, Secret: secret}, nil
}
