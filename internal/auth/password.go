// Package auth implements argon2id password hashing and AES-256-GCM secret
// sealing for diyddns-server. Device HMAC secrets are sealed (reversible,
// design decision D1) rather than hashed, since the server must recover the
// plaintext secret to verify inbound HMAC signatures; passwords and the
// bootstrap token are one-way hashed with argon2id.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters (from server config).
type Argon2Params struct {
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
}

const argon2SaltLen, argon2KeyLen = 16, 32

// HashPassword returns a PHC-encoded argon2id hash embedding a fresh random salt
// and the params, so VerifyPassword is self-describing.
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth.HashPassword: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Parallelism, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether pw matches the PHC-encoded argon2id hash, using
// a constant-time comparison. A malformed encoding is an error, not a false.
func VerifyPassword(encoded, pw string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("auth.VerifyPassword: bad encoding")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: version: %w", err)
	}
	var mem, time uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &par); err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("auth.VerifyPassword: key: %w", err)
	}
	got := argon2.IDKey([]byte(pw), salt, time, mem, par, uint32(len(want))) //nolint:gosec // want is a decoded argon2 key (fixed 32-byte length by HashPassword), never near uint32 max
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
