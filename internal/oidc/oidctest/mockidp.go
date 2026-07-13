// Package oidctest provides an in-process mock OpenID Provider for tests.
// It is a normal (non-_test) package so tests across internal/oidc and
// internal/server/api can import it. Never use it outside tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims are the ID-token claims a test wants minted.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
	Audience      string
	ExpiresIn     int64 // seconds from now; default 300 when 0
}

// Options configures the mock provider.
type Options struct {
	SupportDevice bool // advertise + serve the RFC 8628 device endpoints
}

// IdP is a running mock OpenID Provider.
//
//nolint:revive // "IdP" is the task-5 interface contract's exported name; not "IDP".
type IdP struct {
	Issuer string

	srv     *httptest.Server
	key     *rsa.PrivateKey
	keyID   string
	support bool

	mu           sync.Mutex
	authCode     Claims            // claims to mint for the next auth-code /token
	device       map[string]Claims // device_code → approved claims (absent = pending)
	pollInterval int64
}

// New starts a mock IdP and registers cleanup on t.
func New(t *testing.T, opts Options) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: gen key: %v", err)
	}
	i := &IdP{
		key:          key,
		keyID:        "test-key-1",
		support:      opts.SupportDevice,
		device:       map[string]Claims{},
		pollInterval: 1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("/jwks", i.handleJWKS)
	mux.HandleFunc("/authorize", i.handleAuthorize)
	mux.HandleFunc("/token", i.handleToken)
	if opts.SupportDevice {
		mux.HandleFunc("/device", i.handleDevice)
	}
	i.srv = httptest.NewServer(mux)
	i.Issuer = i.srv.URL
	t.Cleanup(i.srv.Close)
	return i
}

// SetAuthCodeClaims sets the claims the next auth-code /token exchange returns.
func (i *IdP) SetAuthCodeClaims(c Claims) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.authCode = c
}

// ApproveDevice marks a device_code approved, so the next /token device poll
// returns an id_token with the given claims (before this it returns
// authorization_pending).
func (i *IdP) ApproveDevice(deviceCode string, c Claims) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.device[deviceCode] = c
}

func (i *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                i.Issuer,
		"authorization_endpoint":                i.Issuer + "/authorize",
		"token_endpoint":                        i.Issuer + "/token",
		"jwks_uri":                              i.Issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	if i.support {
		doc["device_authorization_endpoint"] = i.Issuer + "/device"
	}
	writeJSON(w, doc)
}

func (i *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{Key: &i.key.PublicKey, KeyID: i.keyID, Algorithm: "RS256", Use: "sig"}
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (i *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	rq := redirect.Query()
	rq.Set("code", "test-auth-code")
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound) //nolint:gosec // G710: intentional open redirect — this mock IdP's whole job is to redirect back to the caller-supplied redirect_uri, like a real /authorize endpoint. Test-only, in-process, never deployed.
}

func (i *IdP) handleDevice(w http.ResponseWriter, _ *http.Request) {
	dc := "test-device-code"
	writeJSON(w, map[string]any{
		"device_code":      dc,
		"user_code":        "WXYZ-1234",
		"verification_uri": i.Issuer + "/verify",
		"expires_in":       600,
		"interval":         i.pollInterval,
	})
}

func (i *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	grant := r.Form.Get("grant_type")
	i.mu.Lock()
	defer i.mu.Unlock()

	if grant == "urn:ietf:params:oauth:grant-type:device_code" {
		dc := r.Form.Get("device_code")
		claims, ok := i.device[dc]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "authorization_pending"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": i.sign(claims)})
		return
	}
	// auth-code grant
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": i.sign(i.authCode)})
}

func (i *IdP) sign(c Claims) string {
	if c.Audience == "" {
		c.Audience = "test-client"
	}
	exp := c.ExpiresIn
	if exp == 0 {
		exp = 300
	}
	now := time.Now().Unix()
	payload := map[string]any{
		"iss": i.Issuer,
		"sub": c.Subject,
		"aud": c.Audience,
		"exp": now + exp,
		"iat": now,
	}
	if c.Email != "" {
		payload["email"] = c.Email
		payload["email_verified"] = c.EmailVerified
	}
	if c.Nonce != "" {
		payload["nonce"] = c.Nonce
	}
	b, _ := json.Marshal(payload)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.keyID),
	)
	if err != nil {
		panic(fmt.Sprintf("oidctest: signer: %v", err))
	}
	obj, err := signer.Sign(b)
	if err != nil {
		panic(fmt.Sprintf("oidctest: sign: %v", err))
	}
	s, _ := obj.CompactSerialize()
	return s
}

// SignIDToken exposes signing for tests that verify tokens directly.
func (i *IdP) SignIDToken(c Claims) string { return i.sign(c) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
