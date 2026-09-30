package stale_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
)

// refusingMailer mirrors the clauses of internal/email's send-path check
// (checkSendable) that a RENDERED message can fail: a non-ASCII subject or
// body, and a CR/LF in the subject. checkSendable itself is unexported and
// this is an external test package, so these clauses are restated here.
// Messages it would send are recorded.
type refusingMailer struct {
	mu   sync.Mutex
	sent []sentMessage
}

type sentMessage struct{ to, subject, body string }

func (m *refusingMailer) Send(_ context.Context, to, subject, body string) error {
	if !email.IsASCII(subject) || !email.IsASCII(body) {
		return email.ErrNotASCII
	}
	if strings.ContainsAny(subject, "\r\n") {
		return email.ErrHeaderInjection
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMessage{to: to, subject: subject, body: body})
	return nil
}

const hostileLabel = "café\r\nBcc: x@evil.test"

func hostileNotices() []stale.Notice {
	return []stale.Notice{
		{Kind: stale.KindRemoved, Family: 4,
			Device: store.Device{Label: "nas"}, Owner: store.User{Email: "alice@example.test"}},
		{Kind: stale.KindWarning, Rung: 3, Family: 6, Remaining: 48 * time.Hour,
			Device: store.Device{Label: hostileLabel}, Owner: store.User{Email: "josé@example.test"}},
	}
}

// TestMailChannel_HostileLabelCannotSuppressTheAdminDigest is #184: the digest
// is ONE body for every admin, so one user-controlled label the transport
// refuses would suppress it for all of them.
func TestMailChannel_HostileLabelCannotSuppressTheAdminDigest(t *testing.T) {
	m := &refusingMailer{}
	ch := stale.NewMailChannel(m)
	d := stale.Delivery{Audience: stale.AudienceAdmin, Recipient: "admin@example.test", Notices: hostileNotices()}

	if err := ch.Send(t.Context(), d); err != nil {
		t.Fatalf("admin digest Send = %v, want nil -- one hostile label must not suppress the digest", err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(m.sent))
	}
	body := m.sent[0].body
	for _, want := range []string{"nas", "caf?", "alice@example.test", "jos?@example.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("digest body %q does not contain %q", body, want)
		}
	}
	if strings.Contains(body, "\nBcc:") || strings.Contains(body, "\rBcc:") {
		t.Errorf("digest body lets a label forge a line: %q", body)
	}
}

// TestMailChannel_HostileLabelCannotSuppressTheOwnerNotice: OwnerSubject puts
// the label in the SUBJECT, which a header check refuses outright.
func TestMailChannel_HostileLabelCannotSuppressTheOwnerNotice(t *testing.T) {
	m := &refusingMailer{}
	ch := stale.NewMailChannel(m)
	n := hostileNotices()[1]
	d := stale.Delivery{Audience: stale.AudienceOwner, Recipient: "owner@example.test", Notices: []stale.Notice{n}}

	if err := ch.Send(t.Context(), d); err != nil {
		t.Fatalf("owner notice Send = %v, want nil", err)
	}
	if len(m.sent) != 1 || !strings.Contains(m.sent[0].subject, "caf?") {
		t.Fatalf("sent = %+v, want one message whose subject names the folded label", m.sent)
	}
}

// TestMailChannel_DoesNotModifyTheCallersNotices: folding works on a copy. The
// Dispatcher reuses one []Notice for the digest it sends to every admin.
func TestMailChannel_DoesNotModifyTheCallersNotices(t *testing.T) {
	ns := hostileNotices()
	ch := stale.NewMailChannel(&refusingMailer{})
	if err := ch.Send(t.Context(), stale.Delivery{Audience: stale.AudienceAdmin, Recipient: "a@example.test", Notices: ns}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if ns[1].Device.Label != hostileLabel || ns[1].Owner.Email != "josé@example.test" {
		t.Errorf("caller's notices were modified: label %q, email %q", ns[1].Device.Label, ns[1].Owner.Email)
	}
}
