package service

import (
	"errors"
	"strings"
	"testing"

	emailpkg "github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// newEmailChangeSvc builds an EmailChangeService over a fresh store with a
// real audit writer, so audit assertions read real rows.
func newEmailChangeSvc(t *testing.T, mailer emailpkg.Mailer) (*store.Store, *EmailChangeService) {
	t.Helper()
	st := openTestStore(t)
	return st, NewEmailChangeService(st, mailer, "https://ddns.example.com", NewAuditWriter(st), discardLogger())
}

// auditRows returns every audit row of one event type, newest first.
func auditRows(t *testing.T, st *store.Store, eventType string) []store.AuditEntry {
	t.Helper()
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: eventType}, "", 50)
	if err != nil {
		t.Fatalf("list audit %s: %v", eventType, err)
	}
	return page.Rows
}

func TestAddressHeld(t *testing.T) {
	const now = int64(1_000_000)
	users := []store.User{
		{ID: "self", Email: "self@example.com"},
		{ID: "exact", Email: "bob@example.com"},
		{ID: "legacy", Email: "Carol <carol@example.com>"},
		{ID: "nonascii", Email: "josé@example.com"},
		{ID: "pending-live", Email: "dave@example.com", PendingEmail: "dave2@example.com", PendingEmailExpiresAt: now + 60},
		{ID: "pending-dead", Email: "erin@example.com", PendingEmail: "erin2@example.com", PendingEmailExpiresAt: now - 60},
	}
	cases := []struct {
		name      string
		canonical string
		exceptID  string
		want      bool
	}{
		{"exact match", "bob@example.com", "", true},
		{"case variant of a stored address", "Bob@Example.COM", "", true},
		{"legacy display-name row matches by canonical form", "carol@example.com", "", true},
		{"non-ASCII legacy row never matches", "jos@example.com", "", false},
		{"another row's live pending address", "DAVE2@example.com", "", true},
		{"another row's expired pending address is free", "erin2@example.com", "", false},
		{"the excepted row's own address is free", "SELF@example.com", "self", false},
		{"the excepted row's own pending address is free", "dave2@example.com", "pending-live", false},
		{"unheld address", "free@example.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := addressHeld(users, tc.canonical, tc.exceptID, now); got != tc.want {
				t.Errorf("addressHeld(%q, except %q) = %v, want %v", tc.canonical, tc.exceptID, got, tc.want)
			}
		})
	}
}

func TestEmailChange_Request_Guards(t *testing.T) {
	t.Run("mailer disabled", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: false})
		u := seedUser(t, st, "a@example.com", "user")
		if err := svc.Request(t.Context(), u, "b@example.com"); !errors.Is(err, ErrMailerUnavailable) {
			t.Fatalf("err = %v, want ErrMailerUnavailable", err)
		}
	})
	t.Run("nil mailer", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, nil)
		u := seedUser(t, st, "a@example.com", "user")
		if err := svc.Request(t.Context(), u, "b@example.com"); !errors.Is(err, ErrMailerUnavailable) {
			t.Fatalf("err = %v, want ErrMailerUnavailable", err)
		}
	})
	t.Run("oidc-linked account", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u, err := st.Users().Create(t.Context(), store.User{Email: "a@example.com", Role: "user", OIDCProvider: "https://idp.example.com", OIDCSubject: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Request(t.Context(), u, "b@example.com"); !errors.Is(err, ErrEmailManagedByOIDC) {
			t.Fatalf("err = %v, want ErrEmailManagedByOIDC", err)
		}
	})
	t.Run("invalid address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "a@example.com", "user")
		// NormalizeAddress STRIPS a display name rather than rejecting it (a
		// "Bob <bob@x>" input is accepted as bob@x), so that is not an invalid
		// case; a quoted local part is (ErrAddressUnsupported), as is non-ASCII.
		for _, bad := range []string{"not-an-email", `"john doe"@example.com`, "josé@example.com"} {
			if err := svc.Request(t.Context(), u, bad); !errors.Is(err, ErrInvalidEmail) {
				t.Errorf("%q: err = %v, want ErrInvalidEmail", bad, err)
			}
		}
	})
	t.Run("unchanged, including a case variant of the current address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "a@example.com", "user")
		for _, same := range []string{"a@example.com", "A@Example.COM"} {
			if err := svc.Request(t.Context(), u, same); !errors.Is(err, ErrEmailUnchanged) {
				t.Errorf("%q: err = %v, want ErrEmailUnchanged", same, err)
			}
		}
	})
	t.Run("held by another account", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "a@example.com", "user")
		seedUser(t, st, "taken@example.com", "user")
		other := seedUser(t, st, "c@example.com", "user")
		if err := svc.Request(t.Context(), other, "pending-elsewhere@example.com"); err != nil {
			t.Fatalf("seed a pending change on another row: %v", err)
		}
		for _, held := range []string{"taken@example.com", "TAKEN@example.com", "Pending-Elsewhere@example.com"} {
			if err := svc.Request(t.Context(), u, held); !errors.Is(err, store.ErrConflict) {
				t.Errorf("%q: err = %v, want store.ErrConflict", held, err)
			}
		}
		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got.PendingEmail != "" {
			t.Errorf("a rejected request staged %q", got.PendingEmail)
		}
	})
}

func TestEmailChange_Request_StagesMailsAndAudits(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	if err := svc.Request(t.Context(), u, "New@Example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	got, _ := st.Users().GetByID(t.Context(), u.ID)
	if got.PendingEmail != "New@Example.com" {
		t.Errorf("PendingEmail = %q, want the canonical (case-preserving) form New@Example.com", got.PendingEmail)
	}
	if got.Email != "old@example.com" {
		t.Errorf("Email changed to %q before confirmation", got.Email)
	}
	if lo, hi := store.NowUnix()+3500, store.NowUnix()+3700; got.PendingEmailExpiresAt < lo || got.PendingEmailExpiresAt > hi {
		t.Errorf("PendingEmailExpiresAt = %d, want about one hour from now", got.PendingEmailExpiresAt)
	}

	sent := mailer.Sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d mails, want 2 (confirmation to new, heads-up to old): %+v", len(sent), sent)
	}
	if sent[0].to != "New@Example.com" || !strings.Contains(sent[0].body, "https://ddns.example.com/account/email/confirm?token=") {
		t.Errorf("first mail = %+v, want the confirmation link to the new address", sent[0])
	}
	if sent[1].to != "old@example.com" || !strings.Contains(sent[1].body, "New@Example.com") {
		t.Errorf("second mail = %+v, want the heads-up to the old address naming the new one", sent[1])
	}

	rows := auditRows(t, st, "user.email_change_requested")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if rows[0].ActorUserID != u.ID || rows[0].TargetID != u.ID {
		t.Errorf("audit actor/target = %q/%q, want %q/%q", rows[0].ActorUserID, rows[0].TargetID, u.ID, u.ID)
	}
	if want := `{"new":"New@Example.com","old":"old@example.com"}`; rows[0].DetailsJSON != want {
		t.Errorf("DetailsJSON = %s, want %s", rows[0].DetailsJSON, want)
	}
}

func TestEmailChange_Request_SameAddressDoesNotResend(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")
	if err := svc.Request(t.Context(), u, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ = st.Users().GetByID(t.Context(), u.ID) // now carries the pending change

	if err := svc.Request(t.Context(), u, "NEW@example.com"); err != nil {
		t.Fatalf("repeat request: %v, want nil", err)
	}
	if n := len(mailer.Sent()); n != 2 {
		t.Errorf("sent %d mails after a repeat request, want still 2 (D12: no resend)", n)
	}
	if n := len(auditRows(t, st, "user.email_change_requested")); n != 1 {
		t.Errorf("requested audit rows = %d, want 1", n)
	}
}

func TestEmailChange_Request_DifferentAddressReplaces(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")
	if err := svc.Request(t.Context(), u, "first@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ = st.Users().GetByID(t.Context(), u.ID)
	if err := svc.Request(t.Context(), u, "second@example.com"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Users().GetByID(t.Context(), u.ID)
	if got.PendingEmail != "second@example.com" {
		t.Errorf("PendingEmail = %q, want second@example.com", got.PendingEmail)
	}
	if n := len(mailer.Sent()); n != 4 {
		t.Errorf("sent %d mails, want 4", n)
	}
}

func TestEmailChange_Request_FailedConfirmationSendRollsBack(t *testing.T) {
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("smtp down")}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	err := svc.Request(t.Context(), u, "new@example.com")
	if !errors.Is(err, ErrConfirmationNotSent) {
		t.Fatalf("err = %v, want ErrConfirmationNotSent", err)
	}
	got, _ := st.Users().GetByID(t.Context(), u.ID)
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("pending not rolled back: (%q, %d)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
	if n := len(mailer.Sent()); n != 1 {
		t.Errorf("sent %d mails, want 1 — the heads-up must not go out when the confirmation could not", n)
	}
	if n := len(auditRows(t, st, EventEmailSendFailed)); n != 1 {
		t.Errorf("email.send_failed rows = %d, want 1", n)
	}
	if n := len(auditRows(t, st, "user.email_change_requested")); n != 1 {
		t.Errorf("requested rows = %d, want 1 — the event log records the request even though it was rolled back", n)
	}
}

func TestEmailChange_Cancel(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	// Nothing pending: no write, no audit, nil.
	if err := svc.Cancel(t.Context(), u); err != nil {
		t.Fatalf("Cancel with nothing pending: %v", err)
	}
	if n := len(auditRows(t, st, "user.email_change_cancelled")); n != 0 {
		t.Fatalf("cancelled rows = %d after a no-op cancel, want 0", n)
	}

	if err := svc.Request(t.Context(), u, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ = st.Users().GetByID(t.Context(), u.ID)
	if err := svc.Cancel(t.Context(), u); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	got, _ := st.Users().GetByID(t.Context(), u.ID)
	if got.PendingEmail != "" {
		t.Errorf("PendingEmail = %q after cancel, want empty", got.PendingEmail)
	}
	rows := auditRows(t, st, "user.email_change_cancelled")
	if len(rows) != 1 || rows[0].DetailsJSON != `{"new":"new@example.com","old":"old@example.com"}` {
		t.Errorf("cancelled rows = %+v, want one with old/new details", rows)
	}
}
