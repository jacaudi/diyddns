package auth

import (
	"context"
	"errors"
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
