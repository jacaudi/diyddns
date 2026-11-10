package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"
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
	if r, ok := errors.AsType[*rejection](err); ok {
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

// SecretPromoter promotes a device's verified pending secret. It returns
// whether the request is accepted. It never sees or returns plaintext:
// sealed is the stored pending_secret_hash value.
type SecretPromoter interface {
	PromoteSecret(ctx context.Context, deviceID, sealed string) (bool, error)
}

// Verifier authenticates agent HMAC requests. It holds no secret cache: the
// device row read on each request is the authority, so a rotated or promoted
// secret takes effect on the next request and a disabled device is refused
// the same way.
type Verifier struct {
	devices  DeviceReader
	users    UserReader
	nonces   NonceInserter
	promoter SecretPromoter
	key      []byte
	skew     time.Duration
	nonceTTL time.Duration
}

// NewVerifier constructs a Verifier. key is the 32-byte AES-256-GCM key used to
// decrypt device secrets; p promotes a pending secret that just verified; skew
// bounds the allowed request-timestamp drift; nonceTTL controls how long a
// recorded signature blocks replay.
func NewVerifier(d DeviceReader, u UserReader, n NonceInserter, p SecretPromoter, key []byte, skew, nonceTTL time.Duration) *Verifier {
	return &Verifier{devices: d, users: u, nonces: n, promoter: p, key: key, skew: skew, nonceTTL: nonceTTL}
}

// Verify authenticates one request and returns the device_id on success. Order:
// device/user liveness -> skew -> secret match (current, then pending) -> nonce
// insert -> promote a matched pending secret (verify BEFORE nonce insert so
// forged requests never pollute replay_nonces, and nonce BEFORE promote so a
// replay never reaches the promotion).
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

	viaPending, err := v.matchSecret(dev, p)
	if err != nil {
		return "", err
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
	if viaPending {
		if err := v.promotePending(ctx, dev); err != nil {
			return "", err
		}
	}
	return dev.ID, nil
}

// matchSecret opens the device's secrets and compares the request signature
// in constant time: the current secret first, then the pending one if any.
// viaPending reports that the pending secret matched. A current secret that
// cannot be opened is secret_unavailable; a pending one that cannot be opened
// counts as no match, as does a signature that fits neither.
func (v *Verifier) matchSecret(dev store.Device, p RequestParts) (viaPending bool, err error) {
	// ponytail: no secret cache (#175 P1); re-add a sealed-keyed cache only if profiling shows GCM open on the hot path.
	secret, err := OpenSecret(v.key, dev.SecretHash)
	if err != nil {
		return false, &rejection{reason: "secret_unavailable"}
	}
	canonical := shared.CanonicalRequest(p.Method, p.Path, p.Timestamp, p.Nonce, shared.BodyHashHex(p.Body))
	if hmac.Equal([]byte(shared.Sign(secret, canonical)), []byte(p.Signature)) {
		return false, nil
	}
	if dev.PendingSecretHash != "" {
		if pending, err := OpenSecret(v.key, dev.PendingSecretHash); err == nil &&
			hmac.Equal([]byte(shared.Sign(pending, canonical)), []byte(p.Signature)) {
			return true, nil
		}
	}
	return false, &rejection{reason: "bad_signature"}
}

// promotePending makes the pending secret that just verified current. A store
// error is promote_error; a refusal (the owner rotated or cancelled meanwhile)
// is pending_superseded, so the superseded secret never overwrites the row.
func (v *Verifier) promotePending(ctx context.Context, dev store.Device) error {
	accepted, err := v.promoter.PromoteSecret(ctx, dev.ID, dev.PendingSecretHash)
	if err != nil {
		return &rejection{reason: "promote_error"}
	}
	if !accepted {
		return &rejection{reason: "pending_superseded"}
	}
	return nil
}
