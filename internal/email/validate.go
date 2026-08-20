package email

import (
	"errors"
	"fmt"
	"net/mail"
	"unicode"
)

// ErrNotASCII reports that a value carries a byte above 0x7F and therefore
// cannot be put on the wire by this package.
//
// buildMessage declares Content-Type: text/plain; charset="utf-8" with NO
// Content-Transfer-Encoding, which RFC 2045 defaults to 7bit, and writes From:,
// To: and Subject: raw with no RFC 2047 encoded-word. Anything non-ASCII is
// therefore a message that lies about its own encoding.
//
// This is a deliberate boundary rejection, not a limitation of net/smtp:
// net/smtp DOES add BODY=8BITMIME and SMTPUTF8 to MAIL FROM when the peer
// advertises them (net/smtp/smtp.go). DIYDDNS does not attempt SMTPUTF8 even
// where the peer offers it, because doing it properly also means handling peers
// that do not — a materially larger feature. Do not describe this as "net/smtp
// cannot"; that claim is false.
var ErrNotASCII = errors.New("email: value is not 7-bit ASCII")

// ErrAddressUnsupported reports an address whose canonical form this transport
// cannot emit. In practice that is a QUOTED local part: mail.ParseAddress
// accepts `"john doe"@example.com` and reports its Address as the UNQUOTED
// `john doe@example.com`, which does not itself re-parse. Normalizing to that
// value would store something no later Send could ever validate — a
// permanently unmailable account manufactured by the very check meant to
// prevent one. Reject at the boundary instead, loudly, so the operator learns
// immediately rather than after the first failed delivery.
//
// Measured: `"john doe"@example.com` -> `john doe@example.com` -> `mail: no
// angle-addr`; `"a@b"@example.com` -> `a@b@example.com` -> `expected single
// address`. Every unquoted form round-trips cleanly, including
// `user@[192.168.1.1]`, `a+b@example.com` and `Bob@Example.COM`.
var ErrAddressUnsupported = errors.New("email: address form is not supported by this transport")

// ErrAddressNotCanonical reports an address that parses and is ASCII but is not
// already in bare addr-spec form — "Bob <bob@example.test>" or a
// whitespace-padded address. Such a value goes out as
// RCPT TO:<Bob <bob@example.test>>, which is malformed, and it is pure ASCII so
// the charset check alone does not catch it. Rows created before the boundary
// validations existed can carry it.
var ErrAddressNotCanonical = errors.New("email: address is not in canonical addr-spec form")

// IsASCII reports whether s is entirely 7-bit ASCII.
//
// It iterates BYTES, not runes: the question is what goes on the wire, and any
// byte above 0x7F is a violation regardless of which rune it belongs to.
func IsASCII(s string) bool {
	for i := range len(s) {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// NormalizeAddress parses addr, returns its canonical addr-spec form, and
// rejects any address that is not 7-bit ASCII.
//
// Normalization is a SEPARATE defect from the charset one and both must be
// fixed here. mail.ParseAddress accepts "Bob <bob@example.test>" and
// "  spaced@example.test  " and both were previously stored RAW, because the
// two call sites wrote `if _, err := mail.ParseAddress(email)` and discarded
// the parse result.
//
// A charset rejection wraps ErrNotASCII so callers can distinguish "not an
// address" from "not mailable by this transport".
func NormalizeAddress(addr string) (string, error) {
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("email: %q is not a valid address: %w", addr, err)
	}
	if !IsASCII(parsed.Address) {
		return "", fmt.Errorf("%w: address %q", ErrNotASCII, parsed.Address)
	}
	// Idempotence gate. The canonical form must itself re-parse to itself, or
	// storing it would create an address no later Send can validate. See
	// ErrAddressUnsupported.
	again, err := mail.ParseAddress(parsed.Address)
	if err != nil || again.Address != parsed.Address {
		return "", fmt.Errorf("%w: %q normalizes to a form that cannot be re-parsed (a quoted local part)", ErrAddressUnsupported, addr)
	}
	return parsed.Address, nil
}

// checkAddress applies the ADDRESS predicate to one envelope address: it must
// parse, be 7-bit, and ALREADY be in canonical form. The last clause is what
// catches a display-name-form value stored before the boundary validations
// existed.
func checkAddress(field, addr string) error {
	normalized, err := NormalizeAddress(addr)
	if err != nil {
		return fmt.Errorf("%s header: %w", field, err)
	}
	if normalized != addr {
		return fmt.Errorf("%w: %s header", ErrAddressNotCanonical, field)
	}
	return nil
}

// checkSendable rejects any buildMessage argument the transport cannot carry.
// It covers ALL FOUR arguments, not just the addresses: AdminNotifyBody
// interpolates a user-controlled email address into the BODY, so a check on
// from/to alone passes the highest-severity vector (design §5.5).
//
// The offending VALUE is deliberately not included in the subject/body errors —
// a body can carry a live one-time registration link. The field name is enough
// to diagnose, and Send already logs the recipient.
func checkSendable(from, to, subject, body string) error {
	if err := checkAddress("From", from); err != nil {
		return err
	}
	if err := checkAddress("To", to); err != nil {
		return err
	}
	if !IsASCII(subject) {
		return fmt.Errorf("%w: Subject header", ErrNotASCII)
	}
	if !IsASCII(body) {
		return fmt.Errorf("%w: message body", ErrNotASCII)
	}
	return nil
}
