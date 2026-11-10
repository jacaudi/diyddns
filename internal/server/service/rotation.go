package service

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

var (
	// ErrInvalidRotationTarget is returned for a target other than secret,
	// cert or both. Mapped to HTTP 400 by the web UI (the REST API rejects it as
	// 422 first).
	ErrInvalidRotationTarget = errors.New("service: invalid rotation target")

	// ErrDeviceDisabled is returned when an admin asks to rotate a
	// device that, or whose owner account, is disabled.
	ErrDeviceDisabled = errors.New("service: device or its owner account is disabled")

	// ErrCertRotationUnavailable is returned for a cert rotation request when
	// the agent listener is not configured.
	ErrCertRotationUnavailable = errors.New("service: certificate rotation needs the agent listener")

	// ErrNoSecretRotationPending is returned by StorePendingSecret when no
	// secret rotation is marked on the device, or the device's secret changed
	// since the caller read it.
	ErrNoSecretRotationPending = errors.New("service: no secret rotation is pending")
)

// RotationTarget names which credential track a rotation request covers.
type RotationTarget string

// The three targets a rotation request can name.
const (
	RotateSecret RotationTarget = "secret"
	RotateCert   RotationTarget = "cert"
	RotateBoth   RotationTarget = "both"
)

// tracks reports which tracks the target covers; ok is false for an unknown
// target (including the zero value).
func (t RotationTarget) tracks() (secret, cert, ok bool) {
	switch t {
	case RotateSecret:
		return true, false, true
	case RotateCert:
		return false, true, true
	case RotateBoth:
		return true, true, true
	}
	return false, false, false
}

// TrackStatus is why a marked rotation track has not completed. Precedence
// when several apply: awaiting_upgrade, then awaiting_mtls, then pending.
type TrackStatus string

// The states a marked rotation track can report.
const (
	StatusPending         TrackStatus = "pending"
	StatusAwaitingUpgrade TrackStatus = "awaiting_upgrade"
	StatusAwaitingMTLS    TrackStatus = "awaiting_mtls"
)

// TrackState is one track's rotation state. Since is the unix second the
// rotation was requested; Since 0 and Status "" mean nothing is pending.
type TrackState struct {
	Since  int64
	Status TrackStatus
}

// RotationState is a device's pending rotation, per track.
type RotationState struct{ Secret, Cert TrackState }

// Pending reports whether either track has a rotation outstanding.
func (s RotationState) Pending() bool { return s.Secret.Since != 0 || s.Cert.Since != 0 }

// RotationStateOf derives a device's rotation state from its row.
func RotationStateOf(d store.Device) RotationState {
	var s RotationState
	if d.RotateSecretAt != 0 {
		s.Secret = TrackState{Since: d.RotateSecretAt, Status: StatusPending}
		if !d.SupportsRotation {
			s.Secret.Status = StatusAwaitingUpgrade
		}
	}
	if d.RotateCertAt != 0 {
		s.Cert = TrackState{Since: d.RotateCertAt, Status: StatusPending}
		switch {
		case !d.SupportsRotation:
			s.Cert.Status = StatusAwaitingUpgrade
		case !d.LastCheckinMTLS:
			s.Cert.Status = StatusAwaitingMTLS
		}
	}
	return s
}

// RotationService marks, cancels and completes credential rotations (#175).
// Crypto (seal, open, compare) always runs outside a store call: the pool is
// one connection.
type RotationService struct {
	st          *store.Store
	key         []byte
	audit       AuditSink
	certEnabled bool
	now         func() time.Time
}

// NewRotationService constructs a RotationService. key is the 32-byte AEAD key
// that seals device secrets (see auth.SealSecret); certEnabled is whether the
// agent listener, which cert rotation needs, is configured.
func NewRotationService(st *store.Store, key []byte, audit AuditSink, certEnabled bool) *RotationService {
	return &RotationService{st: st, key: key, audit: audit, certEnabled: certEnabled, now: time.Now}
}

// CertEnabled reports whether certificate rotation can be requested.
func (s *RotationService) CertEnabled() bool { return s.certEnabled }

// checkTarget validates t and that its tracks are available, returning the
// tracks to mark.
func (s *RotationService) checkTarget(t RotationTarget) (secret, cert bool, err error) {
	secret, cert, ok := t.tracks()
	if !ok {
		return false, false, fmt.Errorf("target %q: %w", t, ErrInvalidRotationTarget)
	}
	if cert && !s.certEnabled {
		return false, false, ErrCertRotationUnavailable
	}
	return secret, cert, nil
}

// Mark requests a rotation of the target tracks on one device and returns the
// re-read device. It returns ErrInvalidRotationTarget, ErrCertRotationUnavailable,
// ErrDeviceDisabled (device or owner disabled) or store.ErrNotFound, in that
// order of precedence.
func (s *RotationService) Mark(ctx context.Context, actor store.Session, id string, t RotationTarget) (store.Device, error) {
	secret, cert, err := s.checkTarget(t)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Mark: %w", err)
	}
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Mark: %w", err)
	}
	owner, err := s.st.Users().GetByID(ctx, dev.UserID)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Mark: %w", err)
	}
	if dev.Disabled || owner.Disabled {
		return store.Device{}, fmt.Errorf("service.Mark: %w", ErrDeviceDisabled)
	}
	if err := s.st.Devices().MarkRotation(ctx, id, secret, cert, s.now().Unix()); err != nil {
		return store.Device{}, fmt.Errorf("service.Mark: %w", err)
	}
	details, _ := json.Marshal(map[string]string{"owner_user_id": owner.ID, "target": string(t)})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actor.UserID, EventType: "device.rotation.requested",
		TargetType: "device", TargetID: id, DetailsJSON: string(details), IP: actor.IP,
	})
	updated, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Mark: %w", err)
	}
	return updated, nil
}

// MarkAll requests a rotation of the target tracks on every enabled device of
// an enabled owner and records one audit row for the whole request. The target
// is validated first: with no track selected the store call would be a
// pointless write to every device.
func (s *RotationService) MarkAll(ctx context.Context, actor store.Session, t RotationTarget) (store.RotationCounts, error) {
	secret, cert, err := s.checkTarget(t)
	if err != nil {
		return store.RotationCounts{}, fmt.Errorf("service.MarkAll: %w", err)
	}
	c, err := s.st.Devices().MarkAllRotation(ctx, secret, cert, s.now().Unix())
	if err != nil {
		return store.RotationCounts{}, fmt.Errorf("service.MarkAll: %w", err)
	}
	details, _ := json.Marshal(struct {
		Target          string `json:"target"`
		Marked          int    `json:"marked"`
		AwaitingUpgrade int    `json:"awaiting_upgrade"`
		AwaitingMTLS    int    `json:"awaiting_mtls"`
		SkippedDisabled int    `json:"skipped_disabled"`
	}{string(t), c.Marked, c.AwaitingUpgrade, c.AwaitingMTLS, c.SkippedDisabled})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actor.UserID, EventType: "device.rotation.requested",
		TargetType: "device", DetailsJSON: string(details), IP: actor.IP,
	})
	return c, nil
}

// Cancel ends any pending rotation on the device. It audits only when
// something was pending. Returns store.ErrNotFound for an unknown device.
func (s *RotationService) Cancel(ctx context.Context, actor store.Session, id string) error {
	cleared, err := s.st.Devices().CancelRotation(ctx, id)
	if err != nil {
		return fmt.Errorf("service.Cancel: %w", err)
	}
	if !cleared {
		return nil
	}
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("service.Cancel: %w", err)
	}
	details, _ := json.Marshal(map[string]string{"owner_user_id": dev.UserID})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actor.UserID, EventType: "device.rotation.cancelled",
		TargetType: "device", TargetID: id, DetailsJSON: string(details), IP: actor.IP,
	})
	return nil
}

// StorePendingSecret records the client's proposed new secret, sealed, for a
// device with a marked secret rotation. A secret equal to the current one is a
// no-op returning nil. Returns ErrNoSecretRotationPending when no rotation is
// marked or the device's secret changed since it was read (an owner rotation),
// and store.ErrNotFound for an unknown device.
func (s *RotationService) StorePendingSecret(ctx context.Context, deviceID string, secret []byte) error {
	dev, err := s.st.Devices().GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("service.StorePendingSecret: %w", err)
	}
	current, err := auth.OpenSecret(s.key, dev.SecretHash)
	if err != nil {
		return fmt.Errorf("service.StorePendingSecret: open current secret: %w", err)
	}
	if hmac.Equal(secret, current) {
		return nil
	}
	sealed, err := auth.SealSecret(s.key, secret)
	if err != nil {
		return fmt.Errorf("service.StorePendingSecret: seal: %w", err)
	}
	stored, err := s.st.Devices().SetPendingSecret(ctx, deviceID, sealed, dev.SecretHash)
	if err != nil {
		return fmt.Errorf("service.StorePendingSecret: %w", err)
	}
	if !stored {
		return fmt.Errorf("service.StorePendingSecret: %w", ErrNoSecretRotationPending)
	}
	return nil
}

// PromoteSecret makes the pending secret current, provided it is still the
// sealed value the caller verified. It reports accepted: true also when a
// concurrent request already promoted the same value. The completion is
// audited once, by the call that changed the row.
func (s *RotationService) PromoteSecret(ctx context.Context, deviceID, sealed string) (bool, error) {
	promoted, accepted, err := s.st.Devices().PromoteSecret(ctx, deviceID, sealed)
	if err != nil {
		return false, fmt.Errorf("service.PromoteSecret: %w", err)
	}
	if promoted {
		auditRotationCompleted(ctx, s.audit, deviceID, map[string]string{"track": "secret"})
	}
	return accepted, nil
}

// PromoteCert makes the pending certificate current, provided serial is still
// the one the caller verified, and reports accepted as PromoteSecret does.
// requested is whether a cert rotation was marked on the row the caller read;
// only then is the completion audited, so a routine renewal promotes silently.
func (s *RotationService) PromoteCert(ctx context.Context, deviceID, serial string, notAfter int64, requested bool) (bool, error) {
	promoted, accepted, err := s.st.Devices().PromoteCert(ctx, deviceID, serial, notAfter)
	if err != nil {
		return false, fmt.Errorf("service.PromoteCert: %w", err)
	}
	if promoted && requested {
		auditRotationCompleted(ctx, s.audit, deviceID, map[string]string{"track": "cert", "serial": serial})
	}
	return accepted, nil
}

// auditRotationCompleted writes the system-actor device.rotation.completed row.
// Every way a requested rotation completes writes it through here: the two
// promotions and the two paths that complete it by clearing the mark (a
// main-port certificate issuance, an owner rotate-secret).
func auditRotationCompleted(ctx context.Context, sink AuditSink, deviceID string, details map[string]string) {
	b, _ := json.Marshal(details)
	sink.Log(ctx, store.AuditEntry{
		EventType: "device.rotation.completed", TargetType: "device", TargetID: deviceID,
		DetailsJSON: string(b),
	})
}
