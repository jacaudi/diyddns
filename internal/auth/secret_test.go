package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func testKey() []byte { return bytes.Repeat([]byte{0x2a}, 32) } // 32 bytes = AES-256

func TestSealOpen_RoundTrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret len = %d", len(secret))
	}

	sealed, err := SealSecret(testKey(), secret)
	if err != nil {
		t.Fatal(err)
	}

	got, err := OpenSecret(testKey(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("round-trip mismatch")
	}
}

func TestSeal_NonDeterministic(t *testing.T) { // random nonce per seal
	s := []byte("0123456789abcdef0123456789abcdef")
	a, _ := SealSecret(testKey(), s)
	b, _ := SealSecret(testKey(), s)
	if a == b {
		t.Fatal("seal must use a fresh random nonce each time")
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	sealed, _ := SealSecret(testKey(), []byte("0123456789abcdef0123456789abcdef"))
	wrong := make([]byte, 32)
	if _, err := OpenSecret(wrong, sealed); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

func TestOpen_TamperedFails(t *testing.T) {
	sealed, _ := SealSecret(testKey(), []byte("0123456789abcdef0123456789abcdef"))
	// flip a byte in the base64 payload
	b := []byte(sealed)
	b[len(b)-2] ^= 0x01
	if _, err := OpenSecret(testKey(), string(b)); err == nil {
		t.Fatal("expected GCM auth failure on tamper")
	}
}

// The next three cover OpenSecret/newGCM error branches required for 100% coverage.
func TestOpen_MalformedBase64(t *testing.T) {
	if _, err := OpenSecret(testKey(), "!!!not base64!!!"); err == nil {
		t.Fatal("expected base64 decode error")
	}
}

func TestOpen_CiphertextTooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}) // < GCM nonce size
	if _, err := OpenSecret(testKey(), short); err == nil {
		t.Fatal("expected ciphertext-too-short error")
	}
}

func TestSeal_NonceReadError(t *testing.T) { // covers SealSecret's nonce-read error branch
	sentinel := errors.New("rng failure")
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, sentinel }

	_, err := SealSecret(testKey(), []byte("0123456789abcdef0123456789abcdef"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped rng failure, got %v", err)
	}
}

func TestGenerateSecret_ReadError(t *testing.T) { // covers GenerateSecret's read error branch
	sentinel := errors.New("rng failure")
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, sentinel }

	if _, err := GenerateSecret(); !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped rng failure, got %v", err)
	}
}

func TestSealOpen_WrongKeyLength(t *testing.T) { // exercises newGCM's len!=32 guard on both paths
	if _, err := SealSecret(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("Seal: expected 16-byte key rejection")
	}
	if _, err := OpenSecret(make([]byte, 16), "AAAA"); err == nil {
		t.Fatal("Open: expected 16-byte key rejection")
	}
}
