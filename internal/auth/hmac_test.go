package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	v := NewVerifier(fakeDevices{d: dev}, fakeUsers{u: usr}, &fakeNonces{seen: map[string]bool{}}, &fakePromoter{accept: true}, key, 120*time.Second, 120*time.Second)
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
	id, err := v.Verify(t.Context(), p, 1720000000)
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
	_, err := v.Verify(t.Context(), p, 1720000000+121)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	p.Signature = "deadbeef"
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	v, _, _, secret := newFixture(t)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(t.Context(), p, 1720000000); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay must be rejected, got %v", err)
	}
}

func TestVerify_DisabledDevice(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed, Disabled: true}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, &fakePromoter{accept: true}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled device must be rejected, got %v", err)
	}
}

func TestVerify_DisabledUser(t *testing.T) {
	key := make([]byte, 32)
	secret, _ := GenerateSecret()
	sealed, _ := SealSecret(key, secret)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed}},
		fakeUsers{u: store.User{ID: "u", Disabled: true}}, &fakeNonces{seen: map[string]bool{}}, &fakePromoter{accept: true}, key, 120*time.Second, 120*time.Second)
	p := signedParts(secret, 1720000000, nil)
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled user must be rejected, got %v", err)
	}
}

func TestVerify_UnknownDevice(t *testing.T) {
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{err: store.ErrNotFound}, fakeUsers{}, &fakeNonces{seen: map[string]bool{}}, &fakePromoter{accept: true}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "nope", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
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

// fakePromoter is a SecretPromoter that records the sealed value it is asked to
// promote and answers with a canned result.
type fakePromoter struct {
	accept bool
	err    error
	calls  []string // sealed values
}

func (f *fakePromoter) PromoteSecret(_ context.Context, _ string, sealed string) (bool, error) {
	f.calls = append(f.calls, sealed)
	return f.accept, f.err
}

// rotFixture is a device mid-rotation: current secret A, pending secret B.
type rotFixture struct {
	v       *Verifier
	dev     *fakeRotatingDevices
	pr      *fakePromoter
	key     []byte
	a, b    []byte
	sealedA string
	sealedB string
}

func newRotFixture(t *testing.T, pr *fakePromoter) rotFixture {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	f := rotFixture{pr: pr, key: key}
	var err error
	if f.a, err = GenerateSecret(); err != nil {
		t.Fatal(err)
	}
	if f.b, err = GenerateSecret(); err != nil {
		t.Fatal(err)
	}
	if f.sealedA, err = SealSecret(key, f.a); err != nil {
		t.Fatal(err)
	}
	if f.sealedB, err = SealSecret(key, f.b); err != nil {
		t.Fatal(err)
	}
	f.dev = &fakeRotatingDevices{dev: store.Device{ID: "dev1", UserID: "usr1", SecretHash: f.sealedA, PendingSecretHash: f.sealedB}}
	f.v = NewVerifier(f.dev, fakeUsers{u: store.User{ID: "usr1"}}, &fakeNonces{seen: map[string]bool{}}, pr, key, 120*time.Second, 120*time.Second)
	return f
}

// parts signs a checkin request with secret and the given nonce.
func parts(secret []byte, nonce string) RequestParts {
	const ts = "1720000000"
	sig := shared.Sign(secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(nil)))
	return RequestParts{Device: "dev1", Timestamp: ts, Nonce: nonce, Signature: sig, Method: "POST", Path: "/agent/v1/checkin"}
}

const verifyNow int64 = 1720000000

func TestVerify_PendingSecretVerifiesAndPromotes(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	id, err := f.v.Verify(t.Context(), parts(f.b, "n1"), verifyNow)
	if err != nil {
		t.Fatalf("pending-signed request: %v", err)
	}
	if id != "dev1" {
		t.Fatalf("device id = %q, want dev1", id)
	}
	if got, want := f.pr.calls, []string{f.sealedB}; !slices.Equal(got, want) {
		t.Fatalf("promoter calls = %v, want %v", got, want)
	}
}

func TestVerify_CurrentSecretDoesNotPromote(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	if _, err := f.v.Verify(t.Context(), parts(f.a, "n1"), verifyNow); err != nil {
		t.Fatalf("current-signed request: %v", err)
	}
	if len(f.pr.calls) != 0 {
		t.Fatalf("promoter calls = %v, want none", f.pr.calls)
	}
}

func TestVerify_PromoteRejectedIs401(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: false})
	_, err := f.v.Verify(t.Context(), parts(f.b, "n1"), verifyNow)
	if !errors.Is(err, ErrUnauthorized) || ReasonOf(err) != "pending_superseded" {
		t.Fatalf("err = %v reason = %q, want ErrUnauthorized / pending_superseded", err, ReasonOf(err))
	}
}

func TestVerify_PromoteErrorIs401(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{err: errors.New("db")})
	_, err := f.v.Verify(t.Context(), parts(f.b, "n1"), verifyNow)
	if !errors.Is(err, ErrUnauthorized) || ReasonOf(err) != "promote_error" {
		t.Fatalf("err = %v reason = %q, want ErrUnauthorized / promote_error", err, ReasonOf(err))
	}
}

// The nonce is recorded before promotion, so a replayed pending-signed request
// is rejected without a second promote attempt.
func TestVerify_NonceBeforePromote(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	p := parts(f.b, "n1")
	if _, err := f.v.Verify(t.Context(), p, verifyNow); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := f.v.Verify(t.Context(), p, verifyNow)
	if ReasonOf(err) != "replay" {
		t.Fatalf("second request reason = %q, want replay", ReasonOf(err))
	}
	if len(f.pr.calls) != 1 {
		t.Fatalf("promoter calls = %d, want 1", len(f.pr.calls))
	}
}

// With no cache, a rotated secret_hash takes effect on the very next request.
func TestVerify_RotatedSecretVerifiesImmediately(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	f.dev.dev.PendingSecretHash = ""
	if _, err := f.v.Verify(t.Context(), parts(f.a, "n1"), verifyNow); err != nil {
		t.Fatalf("verify with A before rotation: %v", err)
	}
	c, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealedC, err := SealSecret(f.key, c)
	if err != nil {
		t.Fatal(err)
	}
	f.dev.dev.SecretHash = sealedC
	if _, err := f.v.Verify(t.Context(), parts(f.a, "n2"), verifyNow); ReasonOf(err) != "bad_signature" {
		t.Fatalf("old secret after rotation: reason = %q, want bad_signature", ReasonOf(err))
	}
	if _, err := f.v.Verify(t.Context(), parts(c, "n3"), verifyNow); err != nil {
		t.Fatalf("new secret after rotation: %v", err)
	}
}

func TestVerify_NeitherKeyIsBadSignature(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	d, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.v.Verify(t.Context(), parts(d, "n1"), verifyNow)
	if ReasonOf(err) != "bad_signature" {
		t.Fatalf("reason = %q, want bad_signature", ReasonOf(err))
	}
	if len(f.pr.calls) != 0 {
		t.Fatalf("promoter calls = %v, want none", f.pr.calls)
	}
}

// A pending hash that cannot be opened counts as no match, not as an error
// that would mask a good current-secret verdict or leak a distinct reason.
func TestVerify_CorruptPendingIsBadSignature(t *testing.T) {
	f := newRotFixture(t, &fakePromoter{accept: true})
	f.dev.dev.PendingSecretHash = "not-a-sealed-secret"
	if _, err := f.v.Verify(t.Context(), parts(f.b, "n1"), verifyNow); ReasonOf(err) != "bad_signature" {
		t.Fatalf("reason = %q, want bad_signature", ReasonOf(err))
	}
	if _, err := f.v.Verify(t.Context(), parts(f.a, "n2"), verifyNow); err != nil {
		t.Fatalf("current secret with corrupt pending: %v", err)
	}
}

// The next two cover the remaining Verify/secretFor error branches for 100% coverage.
func TestVerify_NonNumericTimestamp(t *testing.T) {
	v, _, _, _ := newFixture(t)
	p := RequestParts{Device: "dev1", Timestamp: "not-a-number", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-numeric timestamp must be rejected, got %v", err)
	}
}

func TestVerify_CorruptSecretHash(t *testing.T) { // OpenSecret fails in secretFor
	key := make([]byte, 32)
	v := NewVerifier(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: "not-valid-sealed"}},
		fakeUsers{u: store.User{ID: "u"}}, &fakeNonces{seen: map[string]bool{}}, &fakePromoter{accept: true}, key, 120*time.Second, 120*time.Second)
	p := RequestParts{Device: "dev1", Timestamp: "1720000000", Nonce: "n", Signature: "x", Method: "GET", Path: "/agent/v1/self"}
	if _, err := v.Verify(t.Context(), p, 1720000000); !errors.Is(err, ErrUnauthorized) {
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

// All sixteen Verify reasons, each driven by the one condition that produces
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

	newV := func(d DeviceReader, u UserReader, n NonceInserter, p SecretPromoter) *Verifier {
		return NewVerifier(d, u, n, p, key, 120*time.Second, 120*time.Second)
	}
	accept := &fakePromoter{accept: true}

	// pending_superseded / promote_error: a device mid-rotation, request signed
	// with the pending secret B, and a promoter that refuses or fails.
	secretB, _ := GenerateSecret()
	sealedB, _ := SealSecret(key, secretB)
	pendingDev := goodDev
	pendingDev.PendingSecretHash = sealedB
	signedB := signedParts(secretB, ts, nil)

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

	// *_lookup_cancelled: net/http cancels the request context when a client
	// disconnects mid-request, and store.DeviceRepo.GetByID wraps whatever the
	// driver returns (internal/store/devices.go: `devices.GetByID: %w`). The
	// fake reproduces that exact wrap so the classification is tested against
	// the shape the real store produces, not against a bare context.Canceled.
	errCancelled := fmt.Errorf("devices.GetByID: %w", context.Canceled)

	tests := []struct {
		name       string
		v          *Verifier
		parts      RequestParts
		now        int64
		wantReason string
		cancelCtx  bool // run with an already-cancelled context
	}{
		{"unknown_device", newV(fakeDevices{err: store.ErrNotFound}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts, "unknown_device", false},
		{"device_lookup_cancelled", newV(fakeDevices{err: errCancelled}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts, "device_lookup_cancelled", true},
		{"device_store_error", newV(fakeDevices{err: errBoom}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts, "device_store_error", false},
		{"device_disabled", newV(fakeDevices{d: store.Device{ID: "dev1", UserID: "u", SecretHash: sealed, Disabled: true}}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts, "device_disabled", false},
		{"unknown_user", newV(fakeDevices{d: goodDev}, fakeUsers{err: store.ErrNotFound}, fresh(), accept), ok(), ts, "unknown_user", false},
		{"user_lookup_cancelled", newV(fakeDevices{d: goodDev}, fakeUsers{err: errCancelled}, fresh(), accept), ok(), ts, "user_lookup_cancelled", true},
		{"user_store_error", newV(fakeDevices{d: goodDev}, fakeUsers{err: errBoom}, fresh(), accept), ok(), ts, "user_store_error", false},
		{"user_disabled", newV(fakeDevices{d: goodDev}, fakeUsers{u: store.User{ID: "u", Disabled: true}}, fresh(), accept), ok(), ts, "user_disabled", false},
		{"bad_timestamp", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh(), accept), badTS, ts, "bad_timestamp", false},
		{"clock_skew", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts + 3600, "clock_skew", false},
		{"secret_unavailable", newV(fakeDevices{d: corrupt}, fakeUsers{u: goodUsr}, fresh(), accept), ok(), ts, "secret_unavailable", false},
		{"bad_signature", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, fresh(), accept), badSig, ts, "bad_signature", false},
		{"replay", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, replayed, accept), ok(), ts, "replay", false},
		{"nonce_store_error", newV(fakeDevices{d: goodDev}, fakeUsers{u: goodUsr}, errNonces{err: errBoom}, accept), ok(), ts, "nonce_store_error", false},
		{"pending_superseded", newV(fakeDevices{d: pendingDev}, fakeUsers{u: goodUsr}, fresh(), &fakePromoter{accept: false}), signedB, ts, "pending_superseded", false},
		{"promote_error", newV(fakeDevices{d: pendingDev}, fakeUsers{u: goodUsr}, fresh(), &fakePromoter{err: errBoom}), signedB, ts, "promote_error", false},
	}

	seen := map[string]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if tt.cancelCtx {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			_, err := tt.v.Verify(ctx, tt.parts, tt.now)
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
	// Counted outside the subtest on purpose: a Fatalf-ing subtest must not
	// also trip this guard and bury the real failure under a second one.
	if len(seen) != 16 {
		t.Fatalf("table covers %d distinct reasons, want 16", len(seen))
	}
}
