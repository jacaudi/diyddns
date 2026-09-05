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

// rejection carries the reason for the server log only. It is unexported and
// its Error() is identical to the sentinel's, so a caller that formats the
// error into a response body cannot leak the distinction even by accident.
type rejection struct{ reason string }

func (r *rejection) Error() string { return ErrUnauthorized.Error() }
func (r *rejection) Unwrap() error { return ErrUnauthorized }

// ReasonOf returns the rejection reason for logging. It returns "unknown" for
// any error that is not a *rejection, so a return path that forgets to attach
// a reason degrades to a useless log field rather than to a panic.
func ReasonOf(err error) string {
	var r *rejection
	if errors.As(err, &r) {
		return r.reason
	}
	return "unknown"
}

// storeRejection classifies one failed store lookup three ways: the row is
// missing, the request went away, or the store is broken. ctx.Err() is
// consulted rather than errors.Is(err, context.Canceled) so a deadline is
// caught alongside a cancellation. store.ErrNotFound is checked first so a
// lookup that genuinely found nothing before the client hung up still reports
// as missing.
func storeRejection(ctx context.Context, err error, missing, cancelled, broken string) *rejection {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &rejection{reason: missing}
	case ctx.Err() != nil:
		return &rejection{reason: cancelled}
	default:
		return &rejection{reason: broken}
	}
}

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
// decrypted secret bytes; a cache entry is evicted via Invalidate when a
// device's secret is rotated, so the next Verify re-opens it from the DB
// (device disable is checked live from the DB each request).
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
	if err != nil {
		// A missing device is a client problem, an abandoned request is
		// nobody's, and a failing store is an operator problem. All three
		// produce the same 401 and must not produce the same log line.
		return "", storeRejection(ctx, err, "unknown_device", "device_lookup_cancelled", "device_store_error")
	}
	if dev.Disabled {
		return "", &rejection{reason: "device_disabled"}
	}
	usr, err := v.users.GetByID(ctx, dev.UserID)
	if err != nil {
		return "", storeRejection(ctx, err, "unknown_user", "user_lookup_cancelled", "user_store_error")
	}
	if usr.Disabled {
		return "", &rejection{reason: "user_disabled"}
	}

	ts, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil {
		return "", &rejection{reason: "bad_timestamp"}
	}
	if d := now - ts; d > int64(v.skew.Seconds()) || d < -int64(v.skew.Seconds()) {
		return "", &rejection{reason: "clock_skew"}
	}

	secret, err := v.secretFor(dev)
	if err != nil {
		return "", &rejection{reason: "secret_unavailable"}
	}

	canonical := shared.CanonicalRequest(p.Method, p.Path, p.Timestamp, p.Nonce, shared.BodyHashHex(p.Body))
	expected := shared.Sign(secret, canonical)
	if !hmac.Equal([]byte(expected), []byte(p.Signature)) {
		return "", &rejection{reason: "bad_signature"}
	}

	// Fail closed on any insert error, but tell the log which kind: ErrConflict
	// is a replayed signature (a client/attacker), anything else is the nonce
	// store itself failing (an operator).
	if err := v.nonces.Insert(ctx, p.Signature, ts+int64(v.nonceTTL.Seconds())); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", &rejection{reason: "replay"}
		}
		return "", &rejection{reason: "nonce_store_error"}
	}
	return dev.ID, nil
}

// Invalidate evicts the cached decrypted secret for deviceID, forcing the next
// Verify to re-open the stored (possibly rotated) sealed secret from the DB.
// Called after a device's secret is rotated so the stale secret stops
// authenticating.
func (v *Verifier) Invalidate(deviceID string) {
	v.mu.Lock()
	delete(v.cache, deviceID)
	v.mu.Unlock()
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
