package email_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
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

// testUserID is an ASCII account id (a UUIDv7 shape) for renderers that take one.
const testUserID = "0192f0c1-7a2b-7c3d-8e4f-000000000001"

// hostileUserValue is what a user-controlled value can hold: non-ASCII, plus a
// CR/LF that would forge a header line or a line of the notice if it survived.
const hostileUserValue = "josé\r\nBcc: x@evil.test"

// renderers is every exported function in templates.go that returns
// (subject, body string).
// Each takes one user-controlled string: an address or a device label. Where a
// renderer has none, the argument is ignored. TestEveryTemplateRendererIsCovered
// fails if a new renderer is not listed here, so the rule below cannot be
// skipped by adding a renderer and forgetting this table.
var renderers = map[string]func(user string) (subject, body string){
	"RecoveryLinkBody": func(string) (string, string) {
		return email.RecoveryLinkBody("https://ddns.example.test/register?token=abc123", "15 minutes")
	},
	"InviteLinkBody": func(string) (string, string) {
		return email.InviteLinkBody("https://ddns.example.test/register?token=abc123", "15 minutes")
	},
	"AdminRecoveryLinkBody": func(string) (string, string) {
		return email.AdminRecoveryLinkBody("https://ddns.example.test/register?token=abc123", "15 minutes")
	},
	"ReRegistrationLinkBody": func(string) (string, string) {
		return email.ReRegistrationLinkBody("https://ddns.example.test/register?token=abc123", "15 minutes")
	},
	"ChangeConfirmBody": func(string) (string, string) {
		return email.ChangeConfirmBody("https://ddns.example.test/account/email/confirm?token=abc123")
	},
	"AdminNotifyBody":  func(u string) (string, string) { return email.AdminNotifyBody(u, testUserID) },
	"ChangeNoticeBody": email.ChangeNoticeBody,
	"ChangedBody":      email.ChangedBody,
	"AdminChangedBody": email.AdminChangedBody,
	"DeviceStateChangedByAdminBody": func(u string) (string, string) {
		return email.DeviceStateChangedByAdminBody(u, testUserID, true)
	},
}

// TestRenderedMessagesAreASCII is the static guard #80 asks for, widened to
// cover SUBJECTS as well as bodies (a header has no charset declaration at
// all), and to hostile input (#90, #184).
//
// The benign run checks the TEMPLATES are clean. The hostile run checks the
// FOLD: every user-controlled value is folded before rendering (ASCIIFold), so
// no value one account controls can make a message the transport refuses, and
// no CR/LF in it can forge a line. That matters most for a body rendered once
// and sent to many recipients, like the admin notice.
//
// Do NOT replace this with `rg '[^\x00-\x7F]' templates.go`: that hits em dashes
// in Go // comments, which never reach the wire. Measure the RENDERED output.
func TestRenderedMessagesAreASCII(t *testing.T) {
	for name, render := range renderers {
		for _, in := range []struct{ label, user string }{
			{label: "benign", user: "user@example.test"},
			{label: "hostile", user: hostileUserValue},
		} {
			t.Run(name+"/"+in.label, func(t *testing.T) {
				subject, body := render(in.user)
				if !email.IsASCII(subject) {
					t.Errorf("%s subject is not 7-bit ASCII: %q", name, subject)
				}
				if !email.IsASCII(body) {
					t.Errorf("%s body is not 7-bit ASCII: %q", name, body)
				}
				if strings.ContainsAny(subject, "\r\n") {
					t.Errorf("%s subject contains CR or LF: %q", name, subject)
				}
				if strings.Contains(body, "\nBcc:") || strings.Contains(body, "\rBcc:") {
					t.Errorf("%s body lets a user-controlled value forge a line: %q", name, body)
				}
				if strings.TrimSpace(subject) == "" || strings.TrimSpace(body) == "" {
					t.Errorf("%s rendered empty output -- the guard would pass vacuously", name)
				}
			})
		}
	}
}

// TestEveryTemplateRendererIsCovered makes the renderers table complete by
// construction: it parses the email package and fails for any exported
// function returning exactly two strings (named or not) that the table does
// not list, and for any table entry naming no such function.
func TestEveryTemplateRendererIsCovered(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			var types []string
			for _, field := range fn.Type.Results.List {
				ident, ok := field.Type.(*ast.Ident)
				if !ok {
					types = nil
					break
				}
				for range max(len(field.Names), 1) { // `(subject, body string)` is one field with two names
					types = append(types, ident.Name)
				}
			}
			if !slices.Equal(types, []string{"string", "string"}) {
				continue
			}
			found[fn.Name.Name] = true
			if _, ok := renderers[fn.Name.Name]; !ok {
				t.Errorf("the email package renderer %s is missing from the renderers table in validate_test.go", fn.Name.Name)
			}
		}
	}
	for name := range renderers {
		if !found[name] {
			t.Errorf("renderers table lists %s, which is not an exported two-string-returning function in the email package", name)
		}
	}
	if len(found) == 0 {
		t.Fatal("found no renderers in the email package -- the completeness check would pass vacuously")
	}
}

// TestIsRoutable pins the transport predicate against the cases the library
// treats differently from mail.ParseAddress. A false here for a value
// NormalizeAddress accepts is exactly the misdelivery the predicate exists
// to stop: unraid/apprise-go drops such a recipient and mails From instead.
func TestIsRoutable(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "user@example.test", want: true},
		{in: "user+tag@example.test", want: true},
		{in: "a@b.c", want: true},
		{in: "Bob@Example.COM", want: true},
		{in: "user@localhost", want: false},     // no dot in the domain
		{in: "user@intranet", want: false},      // no dot in the domain
		{in: "user@[192.168.1.1]", want: false}, // brackets are list delimiters
		{in: "user@example.test ", want: false}, // the library would trim it, then send to a different string than it was given; refused as not-the-whole-input
		{in: "a@b.c;d@e.f", want: false},        // two addresses
		{in: `"john doe"@example.com`, want: false},
		{in: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := email.IsRoutable(tt.in); got != tt.want {
				t.Errorf("IsRoutable(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestIsRoutableFrom pins the From rule, which differs from the recipient
// rule in exactly one way: no delimiter split, so a domain literal is fine.
func TestIsRoutableFrom(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "noreply@example.test", want: true},
		{in: "noreply@[192.168.1.1]", want: true}, // measured: the library sends MAIL FROM:<noreply@[192.168.1.1]>
		{in: "noreply@localhost", want: false},    // no dot in the domain
		{in: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := email.IsRoutableFrom(tt.in); got != tt.want {
				t.Errorf("IsRoutableFrom(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestASCIIFold pins the one transport concession this package makes for a
// user-controlled value rendered into a message (#132 D10, design §7): every
// rune the 7-bit SMTP path cannot carry becomes '?', and printable ASCII is
// untouched, so the result always satisfies IsASCII and carries no CR/LF.
func TestASCIIFold(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain-pi", "plain-pi"},
		{"Büro-Pi", "B?ro-Pi"}, // one multi-byte rune, one '?'
		{"line\r\nbreak", "line??break"},
		{"nul\x00byte", "nul?byte"},
		{"del\x7f", "del?"},
		{"bad\xffutf8", "bad?utf8"}, // an invalid byte ranges as utf8.RuneError
		{"tab\tin", "tab?in"},
		{"", ""},
	} {
		got := email.ASCIIFold(tc.in)
		if got != tc.want {
			t.Errorf("ASCIIFold(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !email.IsASCII(got) || strings.ContainsAny(got, "\r\n") {
			t.Errorf("ASCIIFold(%q) = %q is not sendable", tc.in, got)
		}
	}
}

// TestSplitFrom pins #94's accepted email.from forms and the error contract
// (design D14): a bare address keeps exactly today's errors, and a display
// name must be plain ASCII atext words separated by single spaces, written
// exactly as `Name <address>`, because the transport writes an ASCII name
// UNQUOTED into the From header (unraid/apprise-go formatMIMEAddress).
func TestSplitFrom(t *testing.T) {
	tests := []struct {
		name, from         string
		wantName, wantAddr string
		wantErr            error
	}{
		{name: "bare", from: "noreply@example.com", wantAddr: "noreply@example.com"},
		{name: "display name", from: "DIYDDNS <noreply@example.com>", wantName: "DIYDDNS", wantAddr: "noreply@example.com"},
		{name: "multi-word name", from: "DIYDDNS Alerts <noreply@example.com>", wantName: "DIYDDNS Alerts", wantAddr: "noreply@example.com"},
		{name: "atext symbols", from: "O'Brien+Co <noreply@example.com>", wantName: "O'Brien+Co", wantAddr: "noreply@example.com"},
		{name: "name with domain literal", from: "DIYDDNS <noreply@[192.168.1.1]>", wantName: "DIYDDNS", wantAddr: "noreply@[192.168.1.1]"},
		{name: "quoted name", from: `"DIYDDNS" <noreply@example.com>`, wantErr: email.ErrAddressNotCanonical},
		{name: "non-ascii name", from: "Nöreply <noreply@example.com>", wantErr: email.ErrAddressNotCanonical},
		{name: "dot in name", from: "DIYDDNS.Alerts <noreply@example.com>", wantErr: email.ErrAddressNotCanonical},
		{name: "double space", from: "DIYDDNS  <noreply@example.com>", wantErr: email.ErrAddressNotCanonical},
		{name: "no space", from: "DIYDDNS<noreply@example.com>", wantErr: email.ErrAddressNotCanonical},
		{name: "bare trailing space", from: "noreply@example.com ", wantErr: email.ErrAddressNotCanonical},
		{name: "bare dot-less domain", from: "noreply@localhost", wantErr: email.ErrAddressUnroutable},
		{name: "named dot-less domain", from: "DIYDDNS <noreply@localhost>", wantErr: email.ErrAddressUnroutable},
		{name: "bare non-ascii", from: "nöreply@example.com", wantErr: email.ErrNotASCII},
		{name: "named non-ascii address", from: "DIYDDNS <nöreply@example.com>", wantErr: email.ErrNotASCII},
		{name: "bare quoted local part", from: `"john doe"@example.com`, wantErr: email.ErrAddressUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotAddr, err := email.SplitFrom(tt.from)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("SplitFrom(%q) err = %v, want it to wrap %v", tt.from, err, tt.wantErr)
				}
				if gotName != "" || gotAddr != "" {
					t.Errorf("SplitFrom(%q) = (%q, %q) with an error, want empty parts", tt.from, gotName, gotAddr)
				}
				return
			}
			if err != nil {
				t.Fatalf("SplitFrom(%q): %v", tt.from, err)
			}
			if gotName != tt.wantName || gotAddr != tt.wantAddr {
				t.Errorf("SplitFrom(%q) = (%q, %q), want (%q, %q)", tt.from, gotName, gotAddr, tt.wantName, tt.wantAddr)
			}
		})
	}
}
