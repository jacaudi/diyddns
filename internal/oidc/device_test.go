package oidc_test

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestDeviceStartAndPoll(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	m := newManager(t, idp, true)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	da, err := m.DeviceStart(t.Context())
	if err != nil {
		t.Fatalf("DeviceStart: %v", err)
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		t.Fatalf("incomplete device auth: %+v", da)
	}

	// Before approval → pending.
	res, err := m.DevicePoll(t.Context(), da.DeviceCode)
	if err != nil {
		t.Fatalf("DevicePoll pending: %v", err)
	}
	if res.Status != oidc.PollPending {
		t.Fatalf("want PollPending, got %v", res.Status)
	}

	// Approve → complete with claims.
	idp.ApproveDevice(da.DeviceCode, oidctest.Claims{Subject: "dev-sub", Email: "d@example.com", EmailVerified: true, Audience: "test-client"})
	res, err = m.DevicePoll(t.Context(), da.DeviceCode)
	if err != nil {
		t.Fatalf("DevicePoll complete: %v", err)
	}
	if res.Status != oidc.PollComplete || res.Claims.Subject != "dev-sub" {
		t.Fatalf("want PollComplete for dev-sub, got %v %+v", res.Status, res.Claims)
	}
}

func TestDeviceStart_UnsupportedProvider(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := m.DeviceStart(t.Context()); !errors.Is(err, oidc.ErrDeviceUnsupported) {
		t.Fatalf("want ErrDeviceUnsupported, got %v", err)
	}
}
