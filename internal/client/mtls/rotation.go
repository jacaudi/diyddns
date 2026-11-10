package mtls

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/shared"
)

// loadKeys builds the device's key pair from cfg.Creds. A pending secret that
// cannot be decoded is dropped (droppedPending), not fatal: the current secret
// still signs, and the server re-marks the rotation. A bad current secret is an
// error.
func loadKeys(cfg Config) (keys *checkin.Keys, droppedPending bool, err error) {
	keys, err = checkin.NewKeys(cfg.Creds.Secret, cfg.Creds.PendingSecret)
	if err == nil {
		return keys, false, nil
	}
	keys, curErr := checkin.NewKeys(cfg.Creds.Secret, "")
	if curErr != nil {
		return nil, false, curErr
	}
	return keys, true, nil
}

// saveKeys writes m.keys to the credentials file and, only on success, records
// the result in m.cfg.Creds. The error names the path (credentials.Save does)
// and never carries the credentials.
func (m *Manager) saveKeys() error {
	c := m.cfg.Creds
	c.Secret = base64.StdEncoding.EncodeToString(m.keys.Current)
	c.PendingSecret = ""
	if m.keys.Pending != nil {
		c.PendingSecret = base64.StdEncoding.EncodeToString(m.keys.Pending)
	}
	if err := credentials.Save(m.cfg.CredentialsPath, c, true); err != nil {
		return fmt.Errorf("mtls: save credentials: %w", err)
	}
	m.cfg.Creds = c
	return nil
}

// saveKeysBestEffort saves m.keys where a failure must not stop the cycle (the
// in-memory state is right either way and the next save repeats it): a WARN,
// rate-limited, is all it says.
func (m *Manager) saveKeysBestEffort() {
	if err := m.saveKeys(); err != nil {
		m.warnThrottled(&m.lastRotateSaveErr, "secret rotation: could not update credentials; will retry", "error", err)
	}
}

// afterCheckin acts on the rotation request a successful check-in carried:
// the secret track first, then the certificate track. c is the client the
// check-in went over.
func (m *Manager) afterCheckin(ctx context.Context, c *checkin.Client, res checkin.Result) {
	m.rotateSecret(ctx, c, res.Rotation)
	m.rotateCert(ctx, res.Rotation)
}

// rotateSecret runs the client's side of a secret rotation (#175). The new
// secret is generated and saved before it is sent, never regenerated while a
// pending one exists, and travels only inside a request signed with the
// current secret.
func (m *Manager) rotateSecret(ctx context.Context, c *checkin.Client, rot checkin.Rotation) {
	if !rot.Secret {
		if m.keys.Pending != nil {
			// The server dropped its side: only reachable after an old-key 2xx, because a
			// pending-key 2xx already cleared Pending.
			m.keys.Pending = nil
			m.cfg.Log.Warn("secret rotation: the server no longer expects our pending secret; dropped it")
			m.saveKeysBestEffort()
		}
		return
	}
	// B5 gates the hop step 3 really takes: c's URL, not the configured main
	// URL, so a device committed to mTLS rotates over its agent port.
	if !strings.HasPrefix(c.BaseURL(), "https://") {
		if !m.cfg.InsecureProvision {
			if m.due(&m.lastInsecureRotate) {
				m.cfg.Log.Error("refusing to rotate the device secret over insecure http://: set run.insecure_provision to allow it")
			}
			return
		}
		m.cfg.Log.Warn("rotating the device secret over insecure http:// (run.insecure_provision is set): a network attacker can read the new secret")
	}
	if m.keys.Pending == nil {
		p := make([]byte, shared.DeviceSecretLen)
		if _, err := rand.Read(p); err != nil {
			if m.due(&m.lastRotateSaveErr) {
				m.cfg.Log.Error("secret rotation: cannot generate a new secret", "error", err)
			}
			return
		}
		m.keys.Pending = p
		if err := m.saveKeys(); err != nil {
			// Sending a secret that could not be persisted would lose it on a restart.
			m.keys.Pending = nil
			if m.due(&m.lastRotateSaveErr) {
				m.cfg.Log.Error("secret rotation: cannot save credentials; the credentials directory must be writable", "error", err)
			}
			return
		}
	}
	switch err := c.SubmitPendingSecret(ctx); {
	case err == nil:
		m.cfg.Log.Info("secret rotation: new secret sent; it takes effect on the next request")
	case errors.Is(err, checkin.ErrNoSecretRotationPending):
		m.keys.Pending = nil
		m.saveKeysBestEffort()
		m.cfg.Log.Info("secret rotation: the server has no rotation pending; dropped our pending secret")
	default:
		m.cfg.Log.Warn("secret rotation: sending the new secret failed; will retry next cycle", "error", err)
	}
}

// rotateCert renews the device certificate now, ahead of renewBefore, when the
// admin asked for it. Only a committed device renews: one on probation has not
// shown its certificate works yet.
func (m *Manager) rotateCert(ctx context.Context, rot checkin.Rotation) {
	if rot.Cert && m.cur != nil && m.cur.state.Committed {
		m.renew(ctx, true)
	}
}
