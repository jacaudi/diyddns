package oidc_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func TestBeginAuth_BuildsPKCERedirect(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	req, err := m.BeginAuth()
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("expected PKCE S256 challenge, got %v", q)
	}
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Fatal("state/nonce not reflected in redirect URL")
	}
	if !strings.HasPrefix(req.URL, idp.Issuer+"/authorize") {
		t.Fatalf("redirect not to IdP authorize endpoint: %s", req.URL)
	}
}

func TestCompleteAuth_VerifiesTokenAndNonce(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	req, _ := m.BeginAuth()
	idp.SetAuthCodeClaims(oidctest.Claims{
		Subject: "sub-1", Email: "u@example.com", EmailVerified: true,
		Nonce: req.Nonce, Audience: "test-client",
	})

	claims, err := m.CompleteAuth(t.Context(), "test-auth-code", req.Verifier, req.Nonce)
	if err != nil {
		t.Fatalf("CompleteAuth: %v", err)
	}
	if claims.Subject != "sub-1" || claims.Email != "u@example.com" || !claims.EmailVerified {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Nonce mismatch must fail.
	idp.SetAuthCodeClaims(oidctest.Claims{Subject: "sub-1", Nonce: "WRONG", Audience: "test-client"})
	if _, err := m.CompleteAuth(t.Context(), "test-auth-code", req.Verifier, req.Nonce); err == nil {
		t.Fatal("CompleteAuth must reject an ID token whose nonce != expected")
	}
}

func TestBeginAuth_NotReady(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false) // no Discover
	if _, err := m.BeginAuth(); err == nil {
		t.Fatal("BeginAuth must return ErrNotReady before Discover")
	}
}
