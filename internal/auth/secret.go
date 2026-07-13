package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecret returns 32 cryptographically-random bytes — a device's HMAC secret.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
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
	if _, err := rand.Read(nonce); err != nil {
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
