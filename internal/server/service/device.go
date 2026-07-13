package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/store"
)

// DeviceService provides device read access scoped to a device's owner.
type DeviceService struct {
	st *store.Store
}

// NewDeviceService constructs a DeviceService.
func NewDeviceService(st *store.Store) *DeviceService {
	return &DeviceService{st: st}
}

// List returns all devices belonging to userID.
func (s *DeviceService) List(ctx context.Context, userID string) ([]store.Device, error) {
	devices, err := s.st.Devices().ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.List: %w", err)
	}
	return devices, nil
}

// Get returns the device identified by id, but only if it belongs to
// userID. A device owned by a different user is reported as
// store.ErrNotFound, the same as a nonexistent device — callers must not be
// able to distinguish "not yours" from "doesn't exist".
func (s *DeviceService) Get(ctx context.Context, userID, id string) (store.Device, error) {
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Get: %w", err)
	}
	if dev.UserID != userID {
		return store.Device{}, fmt.Errorf("service.Get: %w", store.ErrNotFound)
	}
	return dev, nil
}
