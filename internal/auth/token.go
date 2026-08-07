// Package auth implements diyddns-server's credential primitives: agent HMAC
// request signing, AES-256-GCM sealing of device secrets (reversible, design
// decision D1 — the server must recover the plaintext to verify inbound HMAC
// signatures), SHA-256 hashing of high-entropy machine tokens (registration
// grants and the bootstrap token), browser session management, and WebAuthn
// passkey helpers. Local password hashing was removed with the Plan 10 flip
// to passkeys + OIDC only.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// HashToken returns a base64-encoded SHA-256 digest of token. It is
// deliberately unsalted and deterministic: it is meant for high-entropy,
// machine-generated tokens (RandToken(32) registration grants and the
// bootstrap token), where a slow salted KDF's brute-force resistance is
// unnecessary and determinism lets a token double as a lookup key (see
// store.AccountRecoveryRepo, keyed by token_hash).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// VerifyToken reports whether token hashes to hash, using a constant-time
// comparison so a caller holding both values never introduces a
// timing side-channel by comparing them directly.
func VerifyToken(hash, token string) bool {
	return subtle.ConstantTimeCompare([]byte(HashToken(token)), []byte(hash)) == 1
}
