// Package shared holds the HMAC request-signing wire contract used by the
// server to verify agent requests and (in a later plan) by the client to sign
// them. Stdlib-only: it must remain importable by the huma-free client binary.
package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HTTP headers carrying the HMAC request-signing contract: the device
// identifier, the request timestamp, a per-request nonce, and the resulting
// signature.
const (
	HeaderDevice    = "X-Diyddns-Device"
	HeaderTimestamp = "X-Diyddns-Timestamp"
	HeaderNonce     = "X-Diyddns-Nonce"
	HeaderSignature = "X-Diyddns-Signature"
)

// BodyHashHex returns lowercase-hex SHA256(body). A nil/empty body hashes the
// SHA256 of the empty string.
func BodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalRequest builds the LF-joined signing input:
// METHOD\nPATH\nTIMESTAMP\nNONCE\nBODYHASH
func CanonicalRequest(method, path, timestamp, nonce, bodyHashHex string) string {
	return strings.Join([]string{method, path, timestamp, nonce, bodyHashHex}, "\n")
}

// Sign returns lowercase-hex HMAC-SHA256(secret, canonical).
func Sign(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// CanonicalNotification builds the LF-joined signing input for outbound
// notifications:
//
//	diyddns-notify-v1\nTIMESTAMP\nNONCE\nBODYHASH
//
// Unlike CanonicalRequest it omits method and path, because a receiver behind a
// path-rewriting reverse proxy cannot reconstruct what we sent — a normal
// deployment for the gateway-shaped targets this feature serves, whose symptom
// would be an invalid signature.
//
// The literal first line is domain separation: this package now holds two
// signing schemes sharing Sign and the same header names, and a MAC input that
// cannot be confused for the other scheme's is cheap to establish now and
// expensive later.
func CanonicalNotification(timestamp, nonce, bodyHashHex string) string {
	return strings.Join([]string{"diyddns-notify-v1", timestamp, nonce, bodyHashHex}, "\n")
}
