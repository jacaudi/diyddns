package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// SecretCacheInvalidator evicts a device's cached HMAC secret so a rotated
// secret takes effect immediately. Satisfied by *auth.Verifier.
type SecretCacheInvalidator interface {
	Invalidate(deviceID string)
}

// DeviceService provides owner-scoped device read and management operations. A
// device owned by a different user is always reported as store.ErrNotFound, so
// callers cannot distinguish "not yours" from "doesn't exist".
type DeviceService struct {
	st          *store.Store
	key         []byte
	invalidator SecretCacheInvalidator
	audit       AuditSink
	notify      DeviceNotifier
}

// NewDeviceService constructs a DeviceService. key is the 32-byte AEAD key used
// to seal rotated device secrets (see auth.SealSecret); invalidator evicts the
// HMAC verifier's secret cache on rotation; audit records lifecycle events;
// notify is told when a device joins or leaves the gateway feed (#106).
func NewDeviceService(st *store.Store, key []byte, invalidator SecretCacheInvalidator, audit AuditSink, notify DeviceNotifier) *DeviceService {
	return &DeviceService{st: st, key: key, invalidator: invalidator, audit: audit, notify: notify}
}

// List returns all devices belonging to userID.
func (s *DeviceService) List(ctx context.Context, userID string) ([]store.Device, error) {
	devices, err := s.st.Devices().ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.List: %w", err)
	}
	return devices, nil
}

// Get returns the device identified by id, but only if it belongs to userID.
func (s *DeviceService) Get(ctx context.Context, userID, id string) (store.Device, error) {
	dev, err := s.ownedDevice(ctx, userID, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Get: %w", err)
	}
	return dev, nil
}

// ownedDevice fetches id and confirms it belongs to userID, returning
// store.ErrNotFound if it does not exist or is owned by someone else.
func (s *DeviceService) ownedDevice(ctx context.Context, userID, id string) (store.Device, error) {
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, err
	}
	if dev.UserID != userID {
		return store.Device{}, store.ErrNotFound
	}
	return dev, nil
}

// Rename changes a device's label. Returns store.ErrNotFound for a foreign or
// missing device, store.ErrConflict if the new label is already used.
func (s *DeviceService) Rename(ctx context.Context, userID, id, newLabel string) (store.Device, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	if err := s.st.Devices().Rename(ctx, id, newLabel); err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.renamed", TargetType: "device", TargetID: id,
	})
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Rename: %w", err)
	}
	return dev, nil
}

// SetEnabled toggles a device's disabled flag and emits device.added /
// device.removed when the flip changes the device's feed membership (design
// #106 §6.2, §7.2). before is evaluated on the pre-write rows; after on the
// same snapshot with Disabled set to the requested value.
func (s *DeviceService) SetEnabled(ctx context.Context, userID, id string, disabled bool) (store.Device, error) {
	dev, err := s.ownedDevice(ctx, userID, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	owner, err := s.st.Users().GetByID(ctx, dev.UserID)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	if err := s.st.Devices().SetDisabled(ctx, id, disabled); err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	event := "device.enabled"
	if disabled {
		event = "device.disabled"
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: event, TargetType: "device", TargetID: id,
	})

	after := dev
	after.Disabled = disabled
	emitMembership(ctx, s.notify, after, inFeed(dev, owner), inFeed(after, owner))

	updated, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetEnabled: %w", err)
	}
	return updated, nil
}

// Delete removes a device (its ip_history cascades; a consumed enrollment code
// survives with a nulled device_id, per the schema FKs) and emits
// device.removed if it was a feed member.
func (s *DeviceService) Delete(ctx context.Context, userID, id string) error {
	dev, err := s.ownedDevice(ctx, userID, id)
	if err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	owner, err := s.st.Users().GetByID(ctx, dev.UserID)
	if err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	if err := s.st.Devices().Delete(ctx, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.deleted", TargetType: "device", TargetID: id,
	})
	emitMembership(ctx, s.notify, dev, inFeed(dev, owner), false)
	return nil
}

// RotateSecret mints a fresh HMAC secret, re-seals it into the device row,
// evicts the verifier's cached secret, and returns the new plaintext secret —
// shown to the caller exactly once and never persisted or logged in the clear.
func (s *DeviceService) RotateSecret(ctx context.Context, userID, id string) ([]byte, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	sealed, err := auth.SealSecret(s.key, secret)
	if err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	if err := s.st.Devices().RotateSecret(ctx, id, sealed); err != nil {
		return nil, fmt.Errorf("service.RotateSecret: %w", err)
	}
	s.invalidator.Invalidate(id)
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "device.secret.rotated", TargetType: "device", TargetID: id,
	})
	return secret, nil
}

// History returns a cursor-paginated page of a device's IP history.
func (s *DeviceService) History(ctx context.Context, userID, id, cursor string, limit int) (store.HistoryPage, error) {
	if _, err := s.ownedDevice(ctx, userID, id); err != nil {
		return store.HistoryPage{}, fmt.Errorf("service.History: %w", err)
	}
	page, err := s.st.IPHistory().Page(ctx, id, cursor, limit)
	if err != nil {
		return store.HistoryPage{}, fmt.Errorf("service.History: %w", err)
	}
	return page, nil
}
