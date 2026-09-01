package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// --- fakes satisfying the consumer interfaces ---
type fakeDevices struct {
	d   store.Device
	err error
}

func (f fakeDevices) GetByID(_ context.Context, _ string) (store.Device, error) { return f.d, f.err }

type fakeUsers struct {
	u   store.User
	err error
}

func (f fakeUsers) GetByID(_ context.Context, _ string) (store.User, error) { return f.u, f.err }

type fakeNonces struct{ seen map[string]bool }

func (f *fakeNonces) Insert(_ context.Context, sig string, _ int64) error {
	if f.seen[sig] {
		return store.ErrConflict
	}
	f.seen[sig] = true
	return nil
}

func newFixture(t *testing.T) (*Verifier, store.Device, []byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	dev := store.Device{ID: "dev1", UserID: "usr1", SecretHash: sealed}
	usr := store.User{ID: "usr1"}
	v := NewVerifier(fakeDevices{d: dev}, fakeUsers{u: usr}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	return v, dev, key, secret
}

func signedParts(secret []byte, now int64, body []byte) RequestParts {
	ts := "1720000000"
	nonce := "nonce-abc"
	sig := shared.Sign(secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(body)))
	return RequestParts{Device: "dev1", Timestamp: ts, Nonce: nonce, Signature: sig, Method: "POST", Path: "/agent/v1/checkin", Body: body}
}

func TestVerify_Success(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, []byte(`{"ipv4":"1.2.3.4"}`))
	id, err := v.Verify(context.Background(), p, 1720000000)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if id != "dev1" {
		t.Fatalf("device id = %q", id)
	}
}

func TestVerify_SkewOut(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	_, err := v.Verify(context.Background(), p, 1720000000+121)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	p.Signature = "deadbeef"
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay must be rejected, got %v", err)
	}
}

func TestVerify_DisabledDevice(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed, Disabled: true}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled device must be rejected, got %v", err)
	}
}

func TestVerify_DisabledUser(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed}},
		fakeUsers{u: store.User{ID: "u", Disabled: true}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled user must be rejected, got %v", err)
	}
}

func TestVerify_UnknownDevice(t *testing.T) {
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{err: store.ErrNotFound}, fakeUsers{}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "nope", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown device must be rejected, got %v", err)
	}
}

// fakeRotatingDevices is a pointer-based DeviceReader whose stored device can be
// mutated between calls, so a test can simulate a secret rotation mid-flight.
// (fakeDevices above is a value type copied into the Verifier at construction
// time and can't be mutated afterward.)
type fakeRotatingDevices struct{ dev store.Device }

func (f *fakeRotatingDevices) GetByID(_ context.Context, _ string) (store.Device, error) {
	return f.dev, nil
}

func TestVerifier_Invalidate_EvictsCachedSecret(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	secretA, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	secretB, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealedA, err := SealSecret(key, secretA)
	if err != nil {
		t.Fatal(err)
	}
	sealedB, err := SealSecret(key, secretB)
	if err != nil {
		t.Fatal(err)
	}

	dr := &fakeRotatingDevices{dev: store.Device{ID: "dev1", UserID: "usr1", SecretHash: sealedA}}
	v := NewVerifier(dr, fakeUsers{u: store.User{ID: "usr1"}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)

	const now int64 = 1720000000
	parts := func(secret []byte, nonce string) RequestParts {
		ts := "1720000000"
		sig := shared.Sign(secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(nil)))
		return RequestParts{Device: "dev1", Timestamp: ts, Nonce: nonce, Signature: sig, Method: "POST", Path: "/agent/v1/checkin"}
	}

	// Seed the cache with secretA by verifying a request signed with it.
	if _, err := v.Verify(context.Background(), parts(secretA, "n1"), now); err != nil {
		t.Fatalf("seed verify with secretA: %v", err)
	}

	// Rotate the stored secret to secretB; the cache still holds secretA.
	dr.dev.SecretHash = sealedB

	// Without Invalidate: a request signed with the NEW secretB must FAIL
	// (stale cache still serves secretA).
	if _, err := v.Verify(context.Background(), parts(secretB, "n2"), now); err == nil {
		t.Fatal("expected stale cache to reject the new secret before Invalidate")
	}

	// After Invalidate: the new secretB must now verify.
	v.Invalidate(dr.dev.ID)
	if _, err := v.Verify(context.Background(), parts(secretB, "n3"), now); err != nil {
		t.Fatalf("expected new secret to verify after Invalidate, got %v", err)
	}
}

// The next two cover the remaining Verify/secretFor error branches for 100% coverage.
func TestVerify_NonNumericTimestamp(t *testing.T) {
	v, _, _, _ := newFixture(t)
	p := RequestParts{Device: "dev1", Timestamp: "not-a-number", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-numeric timestamp must be rejected, got %v", err)
	}
}

func TestVerify_CorruptSecretHash(t *testing.T) { // OpenSecret fails in secretFor
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: "not-valid-sealed"}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "dev1", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(context.Background(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("corrupt secret_hash must be rejected, got %v", err)
	}
}

// D11: every reason still collapses to the one exported sentinel, and its
// Error() string is unchanged, so a caller that formats the error into a
// response body cannot leak the distinction even by accident.
func TestReasonOf_PreservesSentinelIdentity(t *testing.T) {
	err := &rejection{reason: "device_disabled"}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatal("errors.Is(err, ErrUnauthorized) = false; every caller in the tree relies on this")
	}
	if err.Error() != ErrUnauthorized.Error() {
		t.Fatalf("Error() = %q, want %q", err.Error(), ErrUnauthorized.Error())
	}
	if got := ReasonOf(err); got != "device_disabled" {
		t.Fatalf("ReasonOf = %q, want device_disabled", got)
	}
	// Survives wrapping, and degrades rather than panicking.
	if got := ReasonOf(fmt.Errorf("context: %w", err)); got != "device_disabled" {
		t.Fatalf("ReasonOf through %%w = %q, want device_disabled", got)
	}
	if got := ReasonOf(ErrUnauthorized); got != "unknown" {
		t.Fatalf("ReasonOf(bare sentinel) = %q, want unknown", got)
	}
	if got := ReasonOf(nil); got != "unknown" {
		t.Fatalf("ReasonOf(nil) = %q, want unknown", got)
	}
}

// errNonces is a NonceInserter that fails with something other than
// store.ErrConflict, so the nonce_store_error branch is reachable. The
// existing fakeNonces returns ErrConflict, which is the replay branch.
type errNonces struct{ err error }

func (e errNonces) Insert(context.Context, string, int64) error { return e.err }

// All twelve Verify reasons, each driven by the one condition that produces
// it. Built on this file's existing fakeDevices/fakeUsers/fakeNonces and
// signedParts helpers.
func TestVerify_ReasonPerBranch(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)

	goodDev := store.Device{ID: "dev1", UserID: "u", SecretHash: sealed}
	goodUsr := store.User{ID: "u"}
	errBoom := errors.New("database is on fire")
	const ts = 1720000000

	newV := func(d DeviceReader, u UserReader, n NonceInserter) *Verifier {
		return NewVerifier(d, u, n, key, 120*time.Second, 120*time.Second)
	}
	fresh := func() *fakeNonces { return &fakeNonces{seen: map[string]bool{}} }
	ok := func() RequestParts { return signedParts(secret, ts, nil) }

	// replay: the same signature already recorded.
	replayed := fresh()
	_ = replayed.Insert(t.Context(), ok().Signature, 0)

	// secret_unavailable: a device whose sealed secret cannot be opened.
	corrupt := goodDev
	corrupt.SecretHash = "not-a-sealed-secret"

	badTS := ok()
	badTS.Timestamp = "not-a-number"

	badSig := ok()
	badSig.Signature = "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name       string
		v          *Verifier
		parts      RequestParts
		now        int64
		wantReason string
	}{
		{"unknown_device", newV(fakeDevices{err: store.ErrNotFound}, fakeUsers{u: goodUsr}, fresh()), ok(), ts, "unknown_device"},
		{"device_store_error", newV(fakeDevices{err: errBoom}, fakeUsers{u: goodUsr}, fresh()), ok(), ts, "device_store_error"},
		{"device_disabled", newV(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed, Disabled: true}}, fakeUsers{u: goodUsr}, fresh()), ok(), ts, "device_disabled"},
		{"unknown_user", newV(fakeDevices{d: goodDev}, fakeUsers{err: store.ErrNotFound}, fresh()), ok(), ts, "unknown_user"},
		{"user_store_error", newV(fakeDevices{d: goodDev}, fakeUsers{err: errBoom}, fresh()), ok(), ts, "user_store_error"},
		{"user_disabled", newV(fakeDevices{d: goodDev}, fakeUsers{u: store.User{ID: "u", Disabled: true}}, fresh()), ok(), ts, "user_disabled"},
		{"bad_timestamp", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh()), badTS, ts, "bad_timestamp"},
		{"clock_skew", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh()), ok(), ts + 3600, "clock_skew"},
		{"secret_unavailable", newV(fakeDevices{d: corrupt}, fakeUsers{u: goodUsr}, fresh()), ok(), ts, "secret_unavailable"},
		{"bad_signature", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh()), badSig, ts, "bad_signature"},
		{"replay", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, replayed), ok(), ts, "replay"},
		{"nonce_store_error", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, errNonces{err: errBoom}), ok(), ts, "nonce_store_error"},
	}

	seen := map[string]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.v.Verify(t.Context(), tt.parts, tt.now)
			// The property that must survive: one sentinel for every reason.
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("errors.Is(err, ErrUnauthorized) = false (err=%v)", err)
			}
			if err.Error() != ErrUnauthorized.Error() {
				t.Fatalf("Error() = %q, want %q", err.Error(), ErrUnauthorized.Error())
			}
			if got := ReasonOf(err); got != tt.wantReason {
				t.Fatalf("ReasonOf = %q, want %q", got, tt.wantReason)
			}
		})
		seen[tt.wantReason] = true
	}
	if len(seen) != 12 {
		t.Fatalf("covered %d distinct reasons, want 12", len(seen))
	}
}
