package email_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/email"
)

func TestIsASCII(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain ascii", in: "bob@example.test", want: true},
		{name: "empty", in: "", want: true},
		{name: "control characters are still ascii", in: "a\r\nb", want: true},
		{name: "accented letter", in: "josé@example.test", want: false},
		{name: "non-ascii domain", in: "user@exämple.test", want: false},
		{name: "cjk local part", in: "日本@example.test", want: false},
		{name: "em dash in a body", in: "an administrator — reset it", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := email.IsASCII(tt.in); got != tt.want {
				t.Errorf("IsASCII(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
		// wantNotASCII asserts the failure is specifically the charset one, so a
		// parse failure cannot pass for a charset rejection.
		wantNotASCII bool
		// wantUnsupported asserts the failure is specifically the idempotence one.
		wantUnsupported bool
	}{
		{name: "already normal", in: "bob@example.test", want: "bob@example.test"},
		{name: "display-name form is unwrapped", in: "Bob <bob@example.test>", want: "bob@example.test"},
		{name: "surrounding whitespace is stripped", in: "  spaced@example.test  ", want: "spaced@example.test"},

		{name: "accented local part", in: "josé@example.test", wantErr: true, wantNotASCII: true},
		{name: "non-ascii domain", in: "user@exämple.test", wantErr: true, wantNotASCII: true},
		{name: "cjk local part", in: "日本@example.test", wantErr: true, wantNotASCII: true},

		{name: "not an address at all", in: "not-an-address", wantErr: true},
		{name: "empty", in: "", wantErr: true},

		// Idempotence: a quoted local part parses, but its canonical form does
		// NOT re-parse, so storing it would create a permanently unmailable
		// account. Reject at the boundary instead. Without this, the send path
		// would fail forever on an address that works today.
		{name: "quoted local part with a space", in: `"john doe"@example.com`, wantErr: true, wantUnsupported: true},
		{name: "quoted local part with an at sign", in: `"a@b"@example.com`, wantErr: true, wantUnsupported: true},

		// These DO round-trip and must keep working.
		{name: "domain literal", in: "user@[192.168.1.1]", want: "user@[192.168.1.1]"},
		{name: "plus addressing", in: "a+b@example.com", want: "a+b@example.com"},
		{name: "mixed case is preserved", in: "Bob@Example.COM", want: "Bob@Example.COM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := email.NormalizeAddress(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAddress(%q) = %q, nil; want an error", tt.in, got)
				}
				if tt.wantNotASCII && !errors.Is(err, email.ErrNotASCII) {
					t.Errorf("NormalizeAddress(%q) err = %v, want it to wrap ErrNotASCII", tt.in, err)
				}
				if tt.wantUnsupported && !errors.Is(err, email.ErrAddressUnsupported) {
					t.Errorf("NormalizeAddress(%q) err = %v, want it to wrap ErrAddressUnsupported", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAddress(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Idempotence: feeding the output back must be a no-op, or the send
			// path could reject what the boundary just accepted.
			again, err := email.NormalizeAddress(got)
			if err != nil || again != got {
				t.Errorf("NormalizeAddress(%q) = %q is not idempotent: re-normalizing gave (%q, %v)", tt.in, got, again, err)
			}
		})
	}
}

// TestRenderedMessagesAreASCII is the static guard #80 asks for, widened to
// cover SUBJECTS as well as bodies. A header is worse off than a body: it has
// no charset declaration available at all.
//
// The inputs are FIXED ASCII on purpose. AdminNotifyBody takes a
// user-controlled address, so feeding it a non-ASCII argument would make this
// guard fail spuriously — this asserts the TEMPLATES are clean, not the
// callers. The caller vectors are covered by the wire assertions below and by
// the per-route tests in B1.3–B1.5.
//
// Do NOT replace this with `rg '[^\x00-\x7F]' templates.go`: that hits em dashes
// in Go // comments, which never reach the wire. Measure the RENDERED output.
func TestRenderedMessagesAreASCII(t *testing.T) {
	const (
		link      = "https://ddns.example.test/register?token=abc123"
		userEmail = "user@example.test"
	)
	rendered := map[string]func() (string, string){
		"RecoveryLinkBody":      func() (string, string) { return email.RecoveryLinkBody(link) },
		"InviteLinkBody":        func() (string, string) { return email.InviteLinkBody(link) },
		"AdminRecoveryLinkBody": func() (string, string) { return email.AdminRecoveryLinkBody(link) },
		"AdminNotifyBody":       func() (string, string) { return email.AdminNotifyBody(userEmail) },
	}
	for name, render := range rendered {
		t.Run(name, func(t *testing.T) {
			subject, body := render()
			if !email.IsASCII(subject) {
				t.Errorf("%s subject is not 7-bit ASCII: %q", name, subject)
			}
			if !email.IsASCII(body) {
				t.Errorf("%s body is not 7-bit ASCII: %q", name, body)
			}
			if strings.TrimSpace(subject) == "" || strings.TrimSpace(body) == "" {
				t.Errorf("%s rendered empty output — the guard would pass vacuously", name)
			}
		})
	}
}
