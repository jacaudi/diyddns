package service

import (
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// TestGrantService_MintsWithConfiguredTTL proves #179 end to end in the
// service: a grant expires linkTTL after it is minted, LinkTTL reports the
// value, and the emailed body states the same window.
func TestGrantService_MintsWithConfiguredTTL(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
	ttl := 45 * time.Minute
	grants := NewGrantService(st, newTestPasskeyService(t, st, discardAudit{}), mailer,
		"https://ddns.example.com", discardAudit{}, discardLogger(), ttl)
	if got := grants.LinkTTL(); got != ttl {
		t.Fatalf("LinkTTL() = %v, want %v", got, ttl)
	}
	u := seedUser(t, st, "ttl@example.com", "user")

	before := store.NowUnix()
	link, _, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	after := store.NowUnix()

	grant, err := st.AccountRecovery().Get(t.Context(), auth.HashToken(extractToken(t, link)))
	if err != nil {
		t.Fatalf("AccountRecovery.Get: %v", err)
	}
	lo, hi := before+int64(ttl.Seconds()), after+int64(ttl.Seconds())
	if grant.ExpiresAt < lo || grant.ExpiresAt > hi {
		t.Errorf("ExpiresAt = %d, want within [%d, %d] (now + 45m)", grant.ExpiresAt, lo, hi)
	}
	sent := mailer.Sent()
	if len(sent) != 1 || !strings.Contains(sent[0].body, "expires in 45 minutes") {
		t.Errorf("invite mail does not state the configured window: %+v", sent)
	}
}
