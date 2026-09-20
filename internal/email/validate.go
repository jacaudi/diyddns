package email

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// ErrNotASCII reports that a value carries a byte above 0x7F and therefore
// is refused by this package.
//
// This is a boundary POLICY, not a transport limitation. The net/smtp client
// this package once carried wrote headers raw and declared a 7-bit body, so
// non-ASCII was a message that lied about its own encoding; the transport
// that replaced it (unraid/apprise-go's mailto service) quoted-printable-
// encodes the body and RFC 2047-encodes the subject, and could carry UTF-8.
// The 7-bit rule stays anyway (#80): every stored address is validated
// against it at the boundary (NormalizeAddress), the send path applies the
// same rule (checkSendable), and the two must agree -- widening one without
// the other creates addresses that are accepted at creation and refused at
// every send. Lifting the rule is its own change, taken deliberately, with
// the SMTPUTF8 / non-ASCII-address consequences worked through; it is not
// something the transport swap does as a side effect.
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
// whitespace-padded address. It is pure ASCII, so the charset check alone
// does not catch it, and no transport this package has used carries it
// correctly: the net/smtp client put it on the wire verbatim as a malformed
// RCPT TO, and the current transport splits it on its list delimiters and
// either mangles it or drops it and mails From instead (see
// ErrAddressUnroutable). Rows created before the boundary validations
// existed can carry it.
var ErrAddressNotCanonical = errors.New("email: address is not in canonical addr-spec form")

// ErrHeaderInjection reports a header VALUE that carries a CR or LF. IsASCII
// alone does not catch this — CR (0x0D) and LF (0x0A) are both 7-bit ASCII,
// and are pinned as such by design (IsASCII's "control characters are still
// ascii" test case), because a message BODY legitimately contains \n line
// breaks. A header field does not: a subject with an embedded CR/LF written
// raw would terminate the Subject header early and let the rest of the value
// inject additional headers or a premature blank-line body boundary. The
// current transport RFC 2047-encodes the subject, which neutralises that;
// the check stays as the transport-independent guarantee this package makes
// about what it hands to ANY transport. checkSendable applies it to the
// Subject only — never to From/To (already constrained to a canonical
// addr-spec by checkAddress, which cannot contain CR/LF) or to the body
// (which legitimately contains \n).
var ErrHeaderInjection = errors.New("email: header value contains a CR or LF")

// ErrAddressUnroutable reports an address the transport would not carry as
// written. unraid/apprise-go filters every mailto address through
// parseDelimitedList (split on `[\[\];,\s]+`, internal/notify/parse_helpers.go:10)
// and then isSimpleEmail (`^[^@\s]+@[^@\s]+\.[^@\s]+$`, internal/notify/smtp2go.go:13).
// A To that fails is NOT refused: it is dropped, and the message is sent to
// From instead (internal/notify/mailto_target.go:129-132). The From address
// takes a different path (parseMailtoFrom, mailto_target.go:180-217):
// mail.ParseAddress, then isSimpleEmail, with NO delimiter split -- so a
// domain literal such as noreply@[192.168.1.1] is a working From and an
// unroutable To. A From that fails is refused loudly ("invalid from email")
// before anything reaches the wire. Refuse both here, each by its own rule.
// This is a different defect from ErrAddressUnsupported (a quoted local
// part that cannot be canonicalised): `user@[192.168.1.1]` canonicalises
// fine and is unroutable as a recipient, because the brackets are list
// delimiters to the library. IsRoutable and IsRoutableFrom must stay in
// lockstep with the pinned library version (go.mod); re-read both library
// sites on every bump.
var ErrAddressUnroutable = errors.New("email: address cannot be carried by the transport as written")

var (
	// libraryListDelims is the library's parseDelimitedList separator set.
	libraryListDelims = regexp.MustCompile(`[\[\];,\s]+`)
	// libraryRecipientRe is the library's isSimpleEmail predicate.
	libraryRecipientRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// IsRoutable reports whether the transport would carry addr as a RECIPIENT
// exactly as written: after the library splits it on its list delimiters,
// exactly one element must survive, it must be the whole input, and it must
// match the library's recipient predicate. It is at least as strict as the
// library (a value the library would mangle rather than drop, such as one
// with a trailing space, is also refused; checkAddress rejects those
// earlier anyway). Exported for the external test package; IsRoutableFrom
// is the one internal/config pins its duplicate against.
func IsRoutable(addr string) bool {
	parts := libraryListDelims.Split(addr, -1)
	parts = slices.DeleteFunc(parts, func(p string) bool { return p == "" })
	return len(parts) == 1 && parts[0] == addr && libraryRecipientRe.MatchString(addr)
}

// IsRoutableFrom reports whether the transport would accept addr as the
// FROM address: the library's isSimpleEmail predicate alone, no delimiter
// split. checkAddress has already required addr to be a canonical
// addr-spec, so only the dotted-domain requirement can still fail here.
// Exported for the same reason as IsRoutable.
func IsRoutableFrom(addr string) bool {
	return libraryRecipientRe.MatchString(addr)
}

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

// ASCIIFold returns s with every rune the SMTP transport cannot carry
// replaced by '?': anything above 0x7F — which includes utf8.RuneError, the
// value range yields for an invalid byte — and every control rune (below
// 0x20, or 0x7F). Printable ASCII passes through unchanged, so the result
// always satisfies IsASCII and contains no CR or LF.
//
// A display concession for one transport, applied where a user-controlled
// value (a device label, #132) is rendered into a message body. Nothing
// stored changes. Folding control characters is a choice, not a transport
// rule: checkSendable does not CR/LF-check a body, but a label must not be
// able to forge a line of the notice.
func ASCIIFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > unicode.MaxASCII || r < 0x20 || r == 0x7F {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
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
// parse, be 7-bit, ALREADY be in canonical form, and be routable by the
// transport under that field's own rule (IsRoutableFrom for From, IsRoutable
// for To). The canonical clause is what catches a display-name-form value
// stored before the boundary validations existed; the routable clause is
// what stops the transport from silently swapping in the From address for a
// recipient it cannot carry.
func checkAddress(field, addr string) error {
	normalized, err := NormalizeAddress(addr)
	if err != nil {
		return fmt.Errorf("%s header: %w", field, err)
	}
	if normalized != addr {
		return fmt.Errorf("%w: %s header", ErrAddressNotCanonical, field)
	}
	routable := IsRoutable
	if field == "From" {
		routable = IsRoutableFrom
	}
	if !routable(addr) {
		return fmt.Errorf("%w: %s header", ErrAddressUnroutable, field)
	}
	return nil
}

// checkSendable rejects the Send arguments this package refuses to hand to
// the transport: non-ASCII anywhere, a non-canonical or unroutable address,
// a subject with a line break. It covers ALL FOUR arguments, not just the
// addresses: AdminNotifyBody interpolates a user-controlled email address
// into the BODY, so a check on from/to alone passes the highest-severity
// vector (design §5.5). It does NOT guarantee the transport can carry
// everything it admits — IsASCII deliberately allows CR/LF (see its "control
// characters are still ascii" test case), and the body is not CR/LF-checked
// at all because a legitimate body contains \n line breaks; only the subject
// is a single header value, so only the subject is checked for that.
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
	if strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("%w: Subject header", ErrHeaderInjection)
	}
	if !IsASCII(body) {
		return fmt.Errorf("%w: message body", ErrNotASCII)
	}
	return nil
}
