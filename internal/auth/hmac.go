package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrUnauthorized is the single sentinel returned for EVERY HMAC failure, so the
// HTTP layer maps one 401 and never leaks which check failed.
var ErrUnauthorized = errors.New("auth: unauthorized")

// DeviceReader is the narrow device-lookup surface Verify depends on.
type DeviceReader interface {
	GetByID(ctx context.Context, id string) (store.Device, error)
}

// UserReader is the narrow user-lookup surface Verify depends on.
type UserReader interface {
	GetByID(ctx context.Context, id string) (store.User, error)
}

// NonceInserter is the narrow replay-nonce-recording surface Verify depends on.
type NonceInserter interface {
	Insert(ctx context.Context, signature string, expiresAt int64) error
}

// RequestParts is the parsed, framework-agnostic view of an agent request.
type RequestParts struct {
	Device, Timestamp, Nonce, Signature, Method, Path string
	Body                                              []byte
}

// Verifier authenticates agent HMAC requests. It holds a process-local cache of
// decrypted secret bytes (populate-only in Plan 04 — secrets never rotate here;
// device disable is checked live from the DB each request).
type Verifier struct {
	devices  DeviceReader
	users    UserReader
	nonces   NonceInserter
	key      []byte
	skew     time.Duration
	nonceTTL time.Duration

	mu    sync.RWMutex
	cache map[string][]byte // deviceID -> secret bytes
}

// NewVerifier constructs a Verifier. key is the 32-byte AES-256-GCM key used to
// decrypt device secrets; skew bounds the allowed request-timestamp drift;
// nonceTTL controls how long a recorded signature blocks replay.
func NewVerifier(d DeviceReader, u UserReader, n NonceInserter, key []byte, skew, nonceTTL time.Duration) *Verifier {
	return &Verifier{devices: d, users: u, nonces: n, key: key, skew: skew, nonceTTL: nonceTTL, cache: map[string][]byte{}}
}

// Verify authenticates one request and returns the device_id on success. Order:
// device/user liveness -> skew -> secret -> constant-time compare -> nonce insert
// (verify BEFORE nonce insert so forged requests never pollute replay_nonces).
func (v *Verifier) Verify(ctx context.Context, p RequestParts, now int64) (string, error) {
	dev, err := v.devices.GetByID(ctx, p.Device)
	if err != nil || dev.Disabled {
		return "", ErrUnauthorized
	}
	usr, err := v.users.GetByID(ctx, dev.UserID)
	if err != nil || usr.Disabled {
		return "", ErrUnauthorized
	}

	ts, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil {
		return "", ErrUnauthorized
	}
	if d := now - ts; d > int64(v.skew.Seconds()) || d < -int64(v.skew.Seconds()) {
		return "", ErrUnauthorized
	}

	secret, err := v.secretFor(dev)
	if err != nil {
		return "", ErrUnauthorized
	}

	canonical := shared.CanonicalRequest(p.Method, p.Path, p.Timestamp, p.Nonce, shared.BodyHashHex(p.Body))
	expected := shared.Sign(secret, canonical)
	if !hmac.Equal([]byte(expected), []byte(p.Signature)) {
		return "", ErrUnauthorized
	}

	if err := v.nonces.Insert(ctx, p.Signature, ts+int64(v.nonceTTL.Seconds())); err != nil {
		return "", ErrUnauthorized // ErrConflict => replay; any insert error is fail-closed
	}
	return dev.ID, nil
}

func (v *Verifier) secretFor(dev store.Device) ([]byte, error) {
	v.mu.RLock()
	s, ok := v.cache[dev.ID]
	v.mu.RUnlock()
	if ok {
		return s, nil
	}
	secret, err := OpenSecret(v.key, dev.SecretHash)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.cache[dev.ID] = secret
	v.mu.Unlock()
	return secret, nil
}
