package service

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func TestDeviceService_Get_ReturnsOwnedDevice(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewDeviceService(st)

	got, err := svc.Get(t.Context(), usr.ID, dev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != dev.ID {
		t.Fatalf("Get: ID = %q, want %q", got.ID, dev.ID)
	}
}

func TestDeviceService_Get_OtherUsersDeviceErrNotFound(t *testing.T) {
	st := openTestStore(t)
	owner := seedUser(t, st, "owner@b.co", "user")
	other := seedUser(t, st, "other@b.co", "user")
	dev := seedDevice(t, st, owner.ID, "laptop")
	svc := NewDeviceService(st)

	_, err := svc.Get(t.Context(), other.ID, dev.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: err = %v, want store.ErrNotFound", err)
	}
}

func TestDeviceService_List_ReturnsOnlyCallersDevices(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	other := seedUser(t, st, "other@b.co", "user")
	seedDevice(t, st, usr.ID, "laptop")
	seedDevice(t, st, usr.ID, "phone")
	seedDevice(t, st, other.ID, "tablet")
	svc := NewDeviceService(st)

	got, err := svc.List(t.Context(), usr.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List: len = %d, want 2", len(got))
	}
	for _, d := range got {
		if d.UserID != usr.ID {
			t.Fatalf("List: returned device %+v belongs to another user", d)
		}
	}
}
