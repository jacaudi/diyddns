// Package oidc implements diyddns's OpenID Connect client: provider discovery,
// ID-token verification, and the browser authorization-code and agent device-code
// flows. It is the ONLY package that imports go-oidc/oauth2, keeping those
// server-only dependencies out of the client binary.
package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jacaudi/diyddns/internal/config"
)

// ErrNotReady is returned by flow methods when the provider has not been
// discovered yet (degraded state).
var ErrNotReady = errors.New("oidc: provider not ready")

// ErrDeviceUnsupported is returned when the IdP advertises no device endpoint.
var ErrDeviceUnsupported = errors.New("oidc: device flow not supported by provider")

// idpCallTimeout bounds every outbound call to the IdP.
const idpCallTimeout = 10 * time.Second

// state is the published, ready-to-use provider snapshot, swapped atomically.
type state struct {
	verifier      *oidc.IDTokenVerifier
	oauth2        oauth2.Config
	deviceAuthURL string
}

// Manager owns OIDC provider discovery and the resulting verifier/oauth2 config.
// It is always constructed; when cfg.Enabled is false, or before the first
// successful Discover, it is simply not ready (Enabled() == false).
type Manager struct {
	cfg     config.OIDCCfg
	baseURL string
	log     *slog.Logger
	hc      *http.Client
	st      atomic.Pointer[state]
}

// NewManager constructs a Manager. It performs no network I/O.
func NewManager(cfg config.OIDCCfg, baseURL string, log *slog.Logger) *Manager {
	return &Manager{
		cfg:     cfg,
		baseURL: baseURL,
		log:     log,
		hc: &http.Client{
			Timeout:   idpCallTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		},
	}
}

// clientCtx returns a context carrying the Manager's bounded HTTP client for
// both go-oidc and oauth2 calls.
func (m *Manager) clientCtx(ctx context.Context) context.Context {
	return context.WithValue(oidc.ClientContext(ctx, m.hc), oauth2.HTTPClient, m.hc)
}

// Discover performs one synchronous discovery attempt. On success it publishes
// the verifier + oauth2 config atomically. Safe to call repeatedly.
func (m *Manager) Discover(ctx context.Context) error {
	if !m.cfg.Enabled {
		return nil
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(cctx, m.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc.Manager.Discover: %w", err)
	}
	m.st.Store(&state{
		verifier: provider.Verifier(&oidc.Config{ClientID: m.cfg.ClientID}),
		oauth2: oauth2.Config{
			ClientID:     m.cfg.ClientID,
			ClientSecret: m.cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  m.baseURL + "/api/v1/auth/oidc/callback",
			Scopes:       m.cfg.Scopes,
		},
		deviceAuthURL: provider.Endpoint().DeviceAuthURL,
	})
	return nil
}

// Enabled reports whether OIDC is configured AND discovery has succeeded.
// Nil-receiver-safe: a nil Manager (never constructed) reports false, so the
// api layer can call it unconditionally without a nil check.
func (m *Manager) Enabled() bool { return m != nil && m.cfg.Enabled && m.st.Load() != nil }

// DeviceEnabled reports whether the device-code flow is available. Nil-safe.
func (m *Manager) DeviceEnabled() bool {
	if m == nil {
		return false
	}
	s := m.st.Load()
	return m.cfg.Enabled && s != nil && s.deviceAuthURL != ""
}
