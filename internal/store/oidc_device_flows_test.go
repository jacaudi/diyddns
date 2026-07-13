package store

import (
	"errors"
	"testing"
)

func TestOIDCDeviceFlows_CreateGetTryPoll(t *testing.T) {
	st, ctx := newTestStore(t) // store package helper: returns (*Store, context.Context)
	r := st.OIDCDeviceFlows()

	f := OIDCDeviceFlow{FlowID: "flow-1", DeviceCode: "dc-1", Interval: 5, ExpiresAt: 1000, CreatedAt: 100}
	if _, err := r.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.Get(ctx, "flow-1")
	if err != nil || got.DeviceCode != "dc-1" {
		t.Fatalf("Get: %v, %+v", err, got)
	}

	// First poll at now=200: last_polled_at(0) + interval(5) <= 200 → allowed.
	row, ok, err := r.TryPoll(ctx, "flow-1", 200)
	if err != nil || !ok || row.LastPolledAt != 200 {
		t.Fatalf("TryPoll first: err=%v ok=%v row=%+v", err, ok, row)
	}
	// Immediate second poll at now=201: 201 - 200 < interval(5) → paced.
	_, ok, err = r.TryPoll(ctx, "flow-1", 201)
	if err != nil || ok {
		t.Fatalf("TryPoll paced: err=%v ok=%v (want ok=false)", err, ok)
	}
	// After the interval, now=206: allowed again.
	_, ok, err = r.TryPoll(ctx, "flow-1", 206)
	if err != nil || !ok {
		t.Fatalf("TryPoll after interval: err=%v ok=%v", err, ok)
	}

	// Expired flow → ErrNotFound.
	if _, _, err := r.TryPoll(ctx, "flow-1", 2000); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TryPoll expired: want ErrNotFound, got %v", err)
	}
}

func TestOIDCDeviceFlows_DeleteAndPrune(t *testing.T) {
	st, ctx := newTestStore(t) // store package helper: returns (*Store, context.Context)
	r := st.OIDCDeviceFlows()
	_, _ = r.Create(ctx, OIDCDeviceFlow{FlowID: "a", DeviceCode: "x", Interval: 5, ExpiresAt: 500, CreatedAt: 1})
	_, _ = r.Create(ctx, OIDCDeviceFlow{FlowID: "b", DeviceCode: "y", Interval: 5, ExpiresAt: 5000, CreatedAt: 1})

	n, err := r.PruneExpired(ctx, 1000)
	if err != nil || n != 1 {
		t.Fatalf("PruneExpired: n=%d err=%v (want 1)", n, err)
	}
	if err := r.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: want ErrNotFound, got %v", err)
	}
}
