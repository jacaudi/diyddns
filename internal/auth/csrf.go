package auth

import (
	"crypto/subtle"

	"github.com/jacaudi/diyddns/internal/store"
)

// ValidCSRF reports whether token matches sess.CSRFToken in constant time.
//
// A session with an empty CSRF token never validates, so a half-built or
// expired session cannot be used to satisfy the check by submitting "".
//
// This is the single home for the comparison rule. Both transports call it: the
// JSON API reads the token from the X-CSRF-Token header, and the web UI reads it
// from a hidden form field, because a browser form POST cannot set headers. Only
// where the token comes from differs; what makes it valid does not.
func ValidCSRF(sess store.Session, token string) bool {
	return sess.CSRFToken != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) == 1
}
