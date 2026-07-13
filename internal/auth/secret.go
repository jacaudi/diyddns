package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// randRead is the source of cryptographic randomness, indirected so tests can
// exercise the RNG-failure branches. Production always uses crypto/rand.Read.
var randRead = rand.Read

// GenerateSecret returns 32 cryptographically-random bytes — a device's HMAC secret.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return nil, fmt.Errorf("auth.GenerateSecret: %w", err)
	}
	return b, nil
}

// SealSecret AES-256-GCM-encrypts secret under key (must be 32 bytes) and returns
// base64(nonce || ciphertext). A fresh random 96-bit nonce is used per call.
func SealSecret(key, secret []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return "", fmt.Errorf("auth.SealSecret: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, secret, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// OpenSecret reverses SealSecret. Returns an error if the key is wrong, the
// payload is malformed, or the GCM tag fails to authenticate.
func OpenSecret(key []byte, sealed string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenSecret: decode: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("auth.OpenSecret: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenSecret: %w", err)
	}
	return pt, nil
}

// SealWithAAD AES-256-GCM-encrypts plaintext under key (32 bytes) binding aad
// as additional authenticated data, and returns base64(nonce || ciphertext).
// aad is not encrypted but is authenticated: OpenWithAAD must be given the same
// aad or authentication fails. Used to domain-separate sealed contexts that
// share the master key (e.g. the OIDC flow cookie vs. device secrets).
func SealWithAAD(key, plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return "", fmt.Errorf("auth.SealWithAAD: nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// OpenWithAAD reverses SealWithAAD. It returns an error if the key is wrong,
// the payload is malformed, aad differs, or the GCM tag fails to authenticate.
func OpenWithAAD(key []byte, sealed string, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenWithAAD: decode: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("auth.OpenWithAAD: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("auth.OpenWithAAD: %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("auth: AEAD key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: new gcm: %w", err)
	}
	return gcm, nil
}
