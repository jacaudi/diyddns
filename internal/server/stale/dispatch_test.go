package stale_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
)

// fakeChannel records every Delivery it is sent and, if err is set, returns
// it from Send without recording anything -- err is a Send-time failure, not
// a validation failure to inspect on the recorded slice.
type fakeChannel struct {
	sent []stale.Delivery
	err  error
}

func (c *fakeChannel) Send(_ context.Context, d stale.Delivery) error {
	if c.err != nil {
		return c.err
	}
	c.sent = append(c.sent, d)
	return nil
}

// byAudience splits the recorded deliveries by audience, for tests that need
// to count owner and admin deliveries separately.
func (c *fakeChannel) byAudience() (owner, admin []stale.Delivery) {
	for _, d := range c.sent {
		switch d.Audience {
		case stale.AudienceOwner:
			owner = append(owner, d)
		case stale.AudienceAdmin:
			admin = append(admin, d)
		}
	}
	return owner, admin
}

// adminLister returns an AdminLister that yields one store.User per email
// given, each with the "admin" role.
func adminLister(t *testing.T, emails ...string) stale.AdminLister {
	t.Helper()
	return func(context.Context) ([]store.User, error) {
		users := make([]store.User, 0, len(emails))
		for _, e := range emails {
			users = append(users, store.User{Email: e, Role: "admin"})
		}
		return users, nil
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeMailer records the context it was called with, so a test can inspect
// exactly what reaches email.Mailer.Send in production -- the layer that
// returns no later than the deadline ctx carries. Wired in via
// stale.NewMailChannel (not a fakeChannel) so these tests exercise the real
// Dispatcher -> Channel -> Mailer path, proving the bound survives the hop
// through mailChannel.Send unchanged.
type fakeMailer struct {
	gotCtx context.Context
}

func (m *fakeMailer) Send(ctx context.Context, _, _, _ string) error {
	m.gotCtx = ctx
	return nil
}

// The pruner goroutine's context (server.go's runPruner, ultimately
// Server.Run's ctx) has no deadline until shutdown -- context.Background()
// stands in for it here, since it has the same property (Deadline() reports
// ok=false) that made the un-bounded delivery hang the sweep tick.
//
// TestDispatcher_SendOwner_BoundsTheDeliveryContext and
// TestDispatcher_SendAdminDigest_BoundsTheDeliveryContext together pin: the
// context reaching Mailer.Send always carries a deadline, on both delivery
// paths, regardless of whether the caller's own context had one.
func TestDispatcher_SendOwner_BoundsTheDeliveryContext(t *testing.T) {
	fm := &fakeMailer{}
	d := stale.NewDispatcher(stale.NewMailChannel(fm), adminLister(t), discardLogger())

	d.SendOwner(context.Background(), stale.Notice{
		Owner: store.User{Email: "o@example.test"},
	})

	if fm.gotCtx == nil {
		t.Fatal("Mailer.Send was never called")
	}
	if _, ok := fm.gotCtx.Deadline(); !ok {
		t.Error("context passed to Mailer.Send has no deadline -- an unbounded SMTP conversation can hang the sweep tick forever")
	}
}

func TestDispatcher_SendAdminDigest_BoundsTheDeliveryContext(t *testing.T) {
	fm := &fakeMailer{}
	d := stale.NewDispatcher(stale.NewMailChannel(fm), adminLister(t, "a@example.test"), discardLogger())

	d.SendAdminDigest(context.Background(), []stale.Notice{
		{Owner: store.User{Email: "o@example.test"}},
	})

	if fm.gotCtx == nil {
		t.Fatal("Mailer.Send was never called")
	}
	if _, ok := fm.gotCtx.Deadline(); !ok {
		t.Error("context passed to Mailer.Send has no deadline -- an unbounded SMTP conversation can hang the sweep tick forever")
	}
}

// D16: owners one-to-one, admins one digest per tick. Recipients are pinned,
// not just counts: routing every admin delivery to admins[0].Email would
// still produce two admin deliveries and pass a count-only check, while
// violating one-digest-PER-ADMIN. For a feature whose entire subject is who
// hears what, the addressee is exactly what must be asserted.
func TestDispatcher_OwnerOneToOneAdminDigest(t *testing.T) {
	ch := &fakeChannel{}
	d := stale.NewDispatcher(ch, adminLister(t, "a1@example.test", "a2@example.test"), discardLogger())

	for range 5 {
		d.SendOwner(t.Context(), stale.Notice{
			Kind: stale.KindWarning, Rung: 3, Family: 4,
			Owner: store.User{Email: "o@example.test"},
		})
	}
	d.SendAdminDigest(t.Context(), make([]stale.Notice, 5))

	owner, admin := ch.byAudience()
	if len(owner) != 5 {
		t.Errorf("owner deliveries = %d, want 5", len(owner))
	}
	for _, o := range owner {
		if o.Recipient != "o@example.test" {
			t.Errorf("owner delivery recipient = %q, want %q", o.Recipient, "o@example.test")
		}
	}
	// One digest PER ADMIN, each carrying all five notices.
	if len(admin) != 2 {
		t.Fatalf("admin deliveries = %d, want 2 (one per admin)", len(admin))
	}
	gotRecipients := make([]string, 0, len(admin))
	for _, d := range admin {
		gotRecipients = append(gotRecipients, d.Recipient)
		if len(d.Notices) != 5 {
			t.Errorf("digest carried %d notices, want 5", len(d.Notices))
		}
	}
	slices.Sort(gotRecipients)
	wantRecipients := []string{"a1@example.test", "a2@example.test"}
	if !slices.Equal(gotRecipients, wantRecipients) {
		t.Errorf("admin digest recipients = %v, want %v (one delivery addressed to each admin)",
			gotRecipients, wantRecipients)
	}
}

// An empty digest must send nothing at all -- an hourly "nothing happened"
// email to every admin is how a feature gets muted. Both nil AND a non-nil
// empty slice are exercised: Task 6's sweeper builds its digest with
// make([]stale.Notice, 0, 8), which is non-nil and empty on every quiet
// tick, so a guard narrowed to `ns == nil` would pass this test's nil case
// while still mailing every admin an empty digest hourly in production.
func TestDispatcher_EmptyDigestSendsNothing(t *testing.T) {
	for _, name := range []string{"nil", "empty slice"} {
		t.Run(name, func(t *testing.T) {
			var ns []stale.Notice
			if name == "empty slice" {
				ns = []stale.Notice{}
			}
			ch := &fakeChannel{}
			d := stale.NewDispatcher(ch, adminLister(t, "a@example.test"), discardLogger())
			d.SendAdminDigest(t.Context(), ns)
			if n := len(ch.sent); n != 0 {
				t.Errorf("sent %d deliveries for an empty digest, want 0", n)
			}
		})
	}
}

// A failing channel must not fail the sweep: the sweep has already written the
// state, and the device list is the durable record. "Logged, never returned"
// is the stated contract and has two halves: SendOwner must return (no
// panic, no error to check -- there is nothing to assert there beyond the
// test completing) AND the failure must actually reach the log, not just
// vanish silently. discardLogger would let a deleted LogAttrs call pass this
// test, so a real handler backed by a buffer is used instead to pin the
// second half.
func TestDispatcher_SendFailureIsLoggedNotReturned(t *testing.T) {
	ch := &fakeChannel{err: errors.New("smtp down")}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	d := stale.NewDispatcher(ch, adminLister(t), log)
	// No panic, no return value to check -- the contract is that it returns.
	d.SendOwner(t.Context(), stale.Notice{
		Device: store.Device{ID: "dev-1"},
		Owner:  store.User{Email: "o@example.test"},
	})

	logged := logBuf.String()
	for _, want := range []string{"owner delivery failed", "dev-1", "smtp down"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %q:\n%s", want, logged)
		}
	}
}
