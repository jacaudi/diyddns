package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jacaudi/diyddns/internal/auth"
)

// Claims is the subset of ID-token claims the link/signup policy needs.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// AuthRequest carries the redirect URL plus the per-request secrets the caller
// must persist (sealed in a cookie) to validate the callback.
type AuthRequest struct {
	URL      string
	State    string
	Verifier string
	Nonce    string
}

// BeginAuth generates state, a PKCE verifier, and a nonce, and builds the
// authorization-endpoint redirect URL. Returns ErrNotReady if not discovered.
func (m *Manager) BeginAuth() (AuthRequest, error) {
	s := m.st.Load()
	if s == nil {
		return AuthRequest{}, ErrNotReady
	}
	state, err := auth.RandToken(32)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("oidc.BeginAuth: state: %w", err)
	}
	nonce, err := auth.RandToken(32)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("oidc.BeginAuth: nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	redirectURL := s.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
	return AuthRequest{URL: redirectURL, State: state, Verifier: verifier, Nonce: nonce}, nil
}

// CompleteAuth exchanges the authorization code (with the PKCE verifier),
// verifies the returned ID token, checks the nonce, and returns its claims.
func (m *Manager) CompleteAuth(ctx context.Context, code, verifier, expectedNonce string) (Claims, error) {
	s := m.st.Load()
	if s == nil {
		return Claims{}, ErrNotReady
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	tok, err := s.oauth2.Exchange(cctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: token response has no id_token")
	}
	idt, err := s.verifier.Verify(cctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: verify: %w", err)
	}
	// go-oidc does NOT check nonce; the caller must.
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(expectedNonce)) != 1 {
		return Claims{}, fmt.Errorf("oidc.CompleteAuth: nonce mismatch")
	}
	return claimsFrom(idt)
}

// claimsFrom extracts the policy-relevant claims from a verified ID token.
func claimsFrom(idt *oidc.IDToken) (Claims, error) {
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("oidc: parse claims: %w", err)
	}
	return Claims{Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified}, nil
}
