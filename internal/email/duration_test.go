package email_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/email"
)

// TestFormatDuration pins the one formatter every registration-link surface
// uses (#179): round UP to whole minutes, pluralise each unit independently,
// no days unit, and "" for a non-positive duration.
func TestFormatDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{-time.Second, ""},
		{time.Second, "1 minute"},
		{59 * time.Second, "1 minute"},
		{60 * time.Second, "1 minute"},
		{61 * time.Second, "2 minutes"},
		{15 * time.Minute, "15 minutes"},
		{45 * time.Minute, "45 minutes"},
		{60 * time.Minute, "1 hour"},
		{61 * time.Minute, "1 hour 1 minute"},
		{90 * time.Minute, "1 hour 30 minutes"},
		{120 * time.Minute, "2 hours"},
		{121 * time.Minute, "2 hours 1 minute"},
		{48 * time.Hour, "48 hours"},
	}
	for _, c := range cases {
		if got := email.FormatDuration(c.in); got != c.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestGrantBodies_StateTheConfiguredWindow is the email half of the spec's
// "no hard-coded window" test: every grant body states the window it is
// given and none still says "shortly" or "one hour".
func TestGrantBodies_StateTheConfiguredWindow(t *testing.T) {
	const link = "https://ddns.example.test/register?token=abc123"
	expiresIn := email.FormatDuration(45 * time.Minute)
	bodies := map[string]func() (string, string){
		"InviteLinkBody":         func() (string, string) { return email.InviteLinkBody(link, expiresIn) },
		"RecoveryLinkBody":       func() (string, string) { return email.RecoveryLinkBody(link, expiresIn) },
		"AdminRecoveryLinkBody":  func() (string, string) { return email.AdminRecoveryLinkBody(link, expiresIn) },
		"ReRegistrationLinkBody": func() (string, string) { return email.ReRegistrationLinkBody(link, expiresIn) },
	}
	for name, render := range bodies {
		_, body := render()
		if !strings.Contains(body, "expires in 45 minutes") {
			t.Errorf("%s does not state the window:\n%s", name, body)
		}
		for _, stale := range []string{"shortly", "one hour"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still says %q:\n%s", name, stale, body)
			}
		}
	}
}
