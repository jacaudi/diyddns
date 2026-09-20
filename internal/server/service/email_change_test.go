package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
	t.Run("oidc-linked account", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u, err := st.Users().Create(t.Context(), store.User{Email: "a@example.com", Role: "user", OIDCProvider: "https://idp.example.com", OIDCSubject: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := svc.Request(t.Context(), u, "b@example.com"); !errors.Is(err, ErrEmailManagedByOIDC) {
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
			if _, _, _, err := svc.Request(t.Context(), u, bad); !errors.Is(err, ErrInvalidEmail) {
				t.Errorf("%q: err = %v, want ErrInvalidEmail", bad, err)
			}
		}
	})
	t.Run("unchanged, including a case variant of the current address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "a@example.com", "user")
		for _, same := range []string{"a@example.com", "A@Example.COM"} {
			if _, _, _, err := svc.Request(t.Context(), u, same); !errors.Is(err, ErrEmailUnchanged) {
				t.Errorf("%q: err = %v, want ErrEmailUnchanged", same, err)
			}
		}
	})
	t.Run("held by another account", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "a@example.com", "user")
		seedUser(t, st, "taken@example.com", "user")
		other := seedUser(t, st, "c@example.com", "user")
		if _, _, _, err := svc.Request(t.Context(), other, "pending-elsewhere@example.com"); err != nil {
			t.Fatalf("seed a pending change on another row: %v", err)
		}
		for _, held := range []string{"taken@example.com", "TAKEN@example.com", "Pending-Elsewhere@example.com"} {
			if _, _, _, err := svc.Request(t.Context(), u, held); !errors.Is(err, store.ErrConflict) {
				t.Errorf("%q: err = %v, want store.ErrConflict", held, err)
			}
		}
		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got.PendingEmail != "" {
			t.Errorf("a rejected request staged %q", got.PendingEmail)
		}
	})
}

// TestEmailChange_Request_WithoutMailerRevealsLink is #144: a self-service
// change is no longer blocked when no mailer is configured (neither a nil
// mailer nor one with Enabled() == false). Instead Request mints the same
// token it would otherwise email, stages the pending change exactly as
// usual, and returns the confirmation link for the caller to show on screen
// once -- mirroring the invite/recovery precedent (grants.go IssueInvite /
// IssueRecovery) -- with a not-Attempted Delivery so the caller knows to
// show it. AdminSet is untouched: it never had this restriction.
func TestEmailChange_Request_WithoutMailerRevealsLink(t *testing.T) {
	t.Run("nil mailer: the link works end-to-end", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, nil)
		u := seedUser(t, st, "a@example.com", "user")

		link, delivery, expiresAt, err := svc.Request(t.Context(), u, "b@example.com")
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if delivery.Attempted {
			t.Errorf("Delivery = %+v, want not Attempted with no mailer", delivery)
		}
		if !strings.Contains(link, "https://ddns.example.com/account/email/confirm?token=") {
			t.Fatalf("link = %q, want a confirm link", link)
		}

		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got.PendingEmail != "b@example.com" {
			t.Fatalf("PendingEmail = %q, want b@example.com", got.PendingEmail)
		}
		if expiresAt != got.PendingEmailExpiresAt {
			t.Errorf("expiresAt = %d, want the staged change's actual expiry %d", expiresAt, got.PendingEmailExpiresAt)
		}

		if err := svc.Confirm(t.Context(), got, extractToken(t, link)); err != nil {
			t.Fatalf("Confirm with the on-screen token: %v", err)
		}
		confirmed, _ := st.Users().GetByID(t.Context(), u.ID)
		if confirmed.Email != "b@example.com" {
			t.Errorf("Email = %q after confirm, want b@example.com", confirmed.Email)
		}
	})

	t.Run("disabled mailer: same as nil, and nothing is mailed", func(t *testing.T) {
		mailer := &fakeMailer{enabled: false}
		st, svc := newEmailChangeSvc(t, mailer)
		u := seedUser(t, st, "a@example.com", "user")

		link, delivery, expiresAt, err := svc.Request(t.Context(), u, "b@example.com")
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if delivery.Attempted {
			t.Errorf("Delivery = %+v, want not Attempted with a disabled mailer", delivery)
		}
		if link == "" {
			t.Fatal("link is empty, want a confirm link to show on screen")
		}
		if expiresAt == 0 {
			t.Error("expiresAt = 0, want the staged change's actual expiry")
		}
		if n := len(mailer.Sent()); n != 0 {
			t.Errorf("sent %d mails with a disabled mailer, want 0", n)
		}
	})

	t.Run("a repeat request to the same pending address mints nothing new (D12)", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, nil)
		u := seedUser(t, st, "a@example.com", "user")
		if _, _, _, err := svc.Request(t.Context(), u, "b@example.com"); err != nil {
			t.Fatal(err)
		}
		u, _ = st.Users().GetByID(t.Context(), u.ID)

		link, delivery, expiresAt, err := svc.Request(t.Context(), u, "B@example.com")
		if err != nil {
			t.Fatalf("repeat request: %v, want nil", err)
		}
		if link != "" || delivery.Attempted || expiresAt != 0 {
			t.Errorf("link = %q, delivery = %+v, expiresAt = %d; want all empty/zero on a D12 repeat", link, delivery, expiresAt)
		}
	})
}

// TestEmailChange_Request_LinkClearedWhenMailed is the Significant #2 finding
// from the #144 review: a configured mailer that successfully carries the
// confirmation link to the new address must not ALSO hand that same
// single-use, bearer token back to the caller in the return value. The one
// caller today (webui/account.go) already gated correctly on
// link != "" && !delivery.Attempted, so this was not a live leak -- but a
// future caller trusting a non-empty link alone would have leaked a
// confirmation token. Clearing link here makes link != "" alone sufficient.
func TestEmailChange_Request_LinkClearedWhenMailed(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	link, delivery, _, err := svc.Request(t.Context(), u, "new@example.com")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !delivery.Sent() {
		t.Fatalf("delivery = %+v, want Sent() true (mailer is enabled and does not fail)", delivery)
	}
	if link != "" {
		t.Errorf("link = %q, want empty: the mailer already carried it to the new address", link)
	}
}

func TestEmailChange_Request_StagesMailsAndAudits(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	if _, _, _, err := svc.Request(t.Context(), u, "New@Example.com"); err != nil {
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
	if _, _, _, err := svc.Request(t.Context(), u, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ = st.Users().GetByID(t.Context(), u.ID) // now carries the pending change

	if _, _, _, err := svc.Request(t.Context(), u, "NEW@example.com"); err != nil {
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
	if _, _, _, err := svc.Request(t.Context(), u, "first@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ = st.Users().GetByID(t.Context(), u.ID)
	if _, _, _, err := svc.Request(t.Context(), u, "second@example.com"); err != nil {
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

	_, _, _, err := svc.Request(t.Context(), u, "new@example.com")
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

	if _, _, _, err := svc.Request(t.Context(), u, "new@example.com"); err != nil {
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

// requestAndToken runs Request for u and returns the raw confirmation token
// out of the mail that was sent to the new address, plus u re-read with the
// pending change on it.
func requestAndToken(t *testing.T, st *store.Store, svc *EmailChangeService, mailer *fakeMailer, u store.User, newEmail string) (store.User, string) {
	t.Helper()
	if _, _, _, err := svc.Request(t.Context(), u, newEmail); err != nil {
		t.Fatalf("Request: %v", err)
	}
	sent := mailer.Sent()
	token := extractToken(t, extractLinkFromBody(t, sent[len(sent)-2].body))
	fresh, err := st.Users().GetByID(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return fresh, token
}

// seedUnusedGrant stages an unconsumed registration grant for userID.
func seedUnusedGrant(t *testing.T, st *store.Store, hash, userID string) {
	t.Helper()
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: hash, UserID: userID, Reason: "recovery", ExpiresAt: store.NowUnix() + 3600,
	}); err != nil {
		t.Fatal(err)
	}
}

func grantGone(t *testing.T, st *store.Store, hash string) bool {
	t.Helper()
	_, err := st.AccountRecovery().Get(t.Context(), hash)
	return errors.Is(err, store.ErrNotFound)
}

func TestEmailChange_Confirm_AppliesDeletesGrantsAuditsAndNotifies(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")
	seedUnusedGrant(t, st, "grant-old", u.ID)
	pending, token := requestAndToken(t, st, svc, mailer, u, "new@example.com")

	if err := svc.Confirm(t.Context(), pending, token); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	got, _ := st.Users().GetByID(t.Context(), u.ID)
	if got.Email != "new@example.com" || got.PendingEmail != "" {
		t.Errorf("row = (%q, pending %q), want (new@example.com, \"\")", got.Email, got.PendingEmail)
	}
	if !grantGone(t, st, "grant-old") {
		t.Error("outstanding grant survived the change (D8)")
	}
	rows := auditRows(t, st, "user.email_changed")
	if len(rows) != 1 || rows[0].ActorUserID != u.ID || rows[0].DetailsJSON != `{"new":"new@example.com","old":"old@example.com"}` {
		t.Errorf("user.email_changed rows = %+v", rows)
	}
	sent := mailer.Sent()
	last := sent[len(sent)-1]
	wantSubj, _ := emailpkg.ChangedBody("new@example.com")
	if last.to != "old@example.com" || last.subject != wantSubj {
		t.Errorf("last mail = %+v, want the changed notice to old@example.com", last)
	}
	// Single use.
	if err := svc.Confirm(t.Context(), got, token); !errors.Is(err, ErrEmailChangeInvalid) {
		t.Errorf("second confirm: err = %v, want ErrEmailChangeInvalid", err)
	}
}

func TestEmailChange_Confirm_Rejects(t *testing.T) {
	t.Run("wrong token", func(t *testing.T) {
		mailer := &fakeMailer{enabled: true}
		st, svc := newEmailChangeSvc(t, mailer)
		u := seedUser(t, st, "old@example.com", "user")
		pending, _ := requestAndToken(t, st, svc, mailer, u, "new@example.com")
		if err := svc.Confirm(t.Context(), pending, "not-the-token"); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("err = %v, want ErrEmailChangeInvalid", err)
		}
		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got.Email != "old@example.com" || got.PendingEmail != "new@example.com" {
			t.Errorf("row changed on a rejected confirm: %+v", got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "old@example.com", "user")
		if err := st.Users().SetPendingEmail(t.Context(), u.ID, "new@example.com", "irrelevant", store.NowUnix()-1); err != nil {
			t.Fatal(err)
		}
		u, _ = st.Users().GetByID(t.Context(), u.ID)
		if err := svc.Confirm(t.Context(), u, "anything"); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("err = %v, want ErrEmailChangeInvalid", err)
		}
	})
	t.Run("nothing pending", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := seedUser(t, st, "old@example.com", "user")
		if err := svc.Confirm(t.Context(), u, "anything"); !errors.Is(err, ErrEmailChangeInvalid) {
			t.Fatalf("err = %v, want ErrEmailChangeInvalid", err)
		}
	})
	t.Run("oidc-linked meanwhile", func(t *testing.T) {
		mailer := &fakeMailer{enabled: true}
		st, svc := newEmailChangeSvc(t, mailer)
		u := seedUser(t, st, "old@example.com", "user")
		pending, token := requestAndToken(t, st, svc, mailer, u, "new@example.com")
		pending.OIDCProvider, pending.OIDCSubject = "https://idp.example.com", "s1"
		if err := st.Users().Update(t.Context(), pending); err != nil {
			t.Fatal(err)
		}
		if err := svc.Confirm(t.Context(), pending, token); !errors.Is(err, ErrEmailManagedByOIDC) {
			t.Fatalf("err = %v, want ErrEmailManagedByOIDC", err)
		}
	})
	t.Run("address taken between request and confirm", func(t *testing.T) {
		mailer := &fakeMailer{enabled: true}
		st, svc := newEmailChangeSvc(t, mailer)
		u := seedUser(t, st, "old@example.com", "user")
		pending, token := requestAndToken(t, st, svc, mailer, u, "new@example.com")
		seedUser(t, st, "new@example.com", "user")
		if err := svc.Confirm(t.Context(), pending, token); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("err = %v, want store.ErrConflict", err)
		}
		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got.Email != "old@example.com" || got.PendingEmail != "new@example.com" {
			t.Errorf("row after conflict = %+v, want unchanged with pending intact", got)
		}
	})
}

func TestEmailChange_AdminSet(t *testing.T) {
	t.Run("applies immediately, notifies old, deletes grants, audits by admin", func(t *testing.T) {
		mailer := &fakeMailer{enabled: true}
		st, svc := newEmailChangeSvc(t, mailer)
		admin := seedUser(t, st, "admin@example.com", "admin")
		target := seedUser(t, st, "old@example.com", "user")
		seedUnusedGrant(t, st, "grant-old", target.ID)
		if err := st.Users().SetPendingEmail(t.Context(), target.ID, "pending@example.com", "h", store.NowUnix()+3600); err != nil {
			t.Fatal(err)
		}
		target, _ = st.Users().GetByID(t.Context(), target.ID)

		updated, d, err := svc.AdminSet(t.Context(), admin.ID, target, "New@example.com")
		if err != nil {
			t.Fatalf("AdminSet: %v", err)
		}
		if updated.Email != "New@example.com" || updated.PendingEmail != "" || updated.ID != target.ID {
			t.Errorf("returned user = %+v", updated)
		}
		got, _ := st.Users().GetByID(t.Context(), target.ID)
		if got.Email != "New@example.com" || got.PendingEmail != "" {
			t.Errorf("persisted row = (%q, pending %q)", got.Email, got.PendingEmail)
		}
		if got.UpdatedAt != updated.UpdatedAt {
			t.Errorf("UpdatedAt: returned %d, persisted %d", updated.UpdatedAt, got.UpdatedAt)
		}
		if !grantGone(t, st, "grant-old") {
			t.Error("outstanding grant survived the change (D8)")
		}
		rows := auditRows(t, st, "user.email_changed_by_admin")
		if len(rows) != 1 || rows[0].ActorUserID != admin.ID || rows[0].TargetID != target.ID ||
			rows[0].DetailsJSON != `{"new":"New@example.com","old":"old@example.com"}` {
			t.Errorf("audit rows = %+v", rows)
		}
		wantSubj, _ := emailpkg.AdminChangedBody("New@example.com")
		sent := mailer.Sent()
		if !d.Sent() || len(sent) != 1 || sent[0].to != "old@example.com" || sent[0].subject != wantSubj {
			t.Errorf("Delivery = %+v, sent = %+v; want one admin changed notice to old@example.com", d, sent)
		}
	})
	t.Run("guards", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		admin := seedUser(t, st, "admin@example.com", "admin")
		target := seedUser(t, st, "old@example.com", "user")
		seedUser(t, st, "taken@example.com", "user")
		for _, tc := range []struct {
			in   string
			want error
		}{
			{"nope", ErrInvalidEmail},
			{"OLD@example.com", ErrEmailUnchanged},
			{"Taken@example.com", store.ErrConflict},
		} {
			if _, _, err := svc.AdminSet(t.Context(), admin.ID, target, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("%q: err = %v, want %v", tc.in, err, tc.want)
			}
		}
	})
	t.Run("a case variant of the target's own pending address is allowed", func(t *testing.T) {
		// exceptID exempts the target's own row: its pending address is not
		// "held by another account". Pins the argument at this site.
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		admin := seedUser(t, st, "admin@example.com", "admin")
		target := seedUser(t, st, "old@example.com", "user")
		if err := st.Users().SetPendingEmail(t.Context(), target.ID, "pending@example.com", "h", store.NowUnix()+3600); err != nil {
			t.Fatal(err)
		}
		target, _ = st.Users().GetByID(t.Context(), target.ID)
		if _, _, err := svc.AdminSet(t.Context(), admin.ID, target, "PENDING@example.com"); err != nil {
			t.Fatalf("AdminSet to the target's own pending address: %v, want nil", err)
		}
	})
	t.Run("self target is allowed and immediate (D21)", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		admin := seedUser(t, st, "admin@example.com", "admin")
		if _, _, err := svc.AdminSet(t.Context(), admin.ID, admin, "admin2@example.com"); err != nil {
			t.Fatalf("AdminSet on self: %v", err)
		}
		got, _ := st.Users().GetByID(t.Context(), admin.ID)
		if got.Email != "admin2@example.com" {
			t.Errorf("Email = %q", got.Email)
		}
	})
	t.Run("disabled target is still notified", func(t *testing.T) {
		mailer := &fakeMailer{enabled: true}
		st, svc := newEmailChangeSvc(t, mailer)
		admin := seedUser(t, st, "admin@example.com", "admin")
		target, _ := st.Users().Create(t.Context(), store.User{Email: "old@example.com", Role: "user", Disabled: true})
		if _, d, err := svc.AdminSet(t.Context(), admin.ID, target, "new@example.com"); err != nil || !d.Sent() {
			t.Fatalf("err = %v, Delivery = %+v; want nil and Sent", err, d)
		}
	})
	t.Run("without a mailer the change still applies", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, nil)
		admin := seedUser(t, st, "admin@example.com", "admin")
		target := seedUser(t, st, "old@example.com", "user")
		if _, d, err := svc.AdminSet(t.Context(), admin.ID, target, "new@example.com"); err != nil || d.Attempted {
			t.Fatalf("err = %v, Delivery = %+v; want nil and not Attempted", err, d)
		}
	})
}

func TestEmailChange_SyncFromIDP(t *testing.T) {
	const iss = "https://idp.example.com"
	linked := func(t *testing.T, st *store.Store, addr string) store.User {
		t.Helper()
		u, err := st.Users().Create(t.Context(), store.User{Email: addr, Role: "user", OIDCProvider: iss, OIDCSubject: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	noWrite := func(t *testing.T, st *store.Store, u store.User) {
		t.Helper()
		got, _ := st.Users().GetByID(t.Context(), u.ID)
		if got != u {
			t.Errorf("row changed:\n before %+v\n after  %+v", u, got)
		}
		if n := len(auditRows(t, st, "user.email_changed_by_oidc")); n != 0 {
			t.Errorf("audit rows = %d, want 0", n)
		}
	}

	t.Run("empty claim keeps the stored address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := linked(t, st, "a@example.com")
		if got := svc.SyncFromIDP(t.Context(), u, ""); got != u {
			t.Errorf("returned %+v, want the input row", got)
		}
		noWrite(t, st, u)
	})
	t.Run("unusable claim keeps the stored address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := linked(t, st, "a@example.com")
		for _, bad := range []string{"not-an-email", "josé@example.com"} {
			if got := svc.SyncFromIDP(t.Context(), u, bad); got != u {
				t.Errorf("%q: returned %+v, want the input row", bad, got)
			}
		}
		noWrite(t, st, u)
	})
	t.Run("same address, any case, is a silent no-op", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := linked(t, st, "a@example.com")
		if got := svc.SyncFromIDP(t.Context(), u, "A@Example.COM"); got != u {
			t.Errorf("returned %+v, want the input row", got)
		}
		noWrite(t, st, u)
	})
	t.Run("address held by another account keeps the stored address", func(t *testing.T) {
		st, svc := newEmailChangeSvc(t, &fakeMailer{enabled: true})
		u := linked(t, st, "a@example.com")
		seedUser(t, st, "b@example.com", "user")
		if got := svc.SyncFromIDP(t.Context(), u, "B@example.com"); got != u {
			t.Errorf("returned %+v, want the input row", got)
		}
		noWrite(t, st, u)
	})
	t.Run("own stale pending change to the claimed address does not block the sync", func(t *testing.T) {
		// Pins exceptID actually being threaded through to addressHeld on this
		// path: if SyncFromIDP passed "" instead of u.ID, addressHeld would see
		// THIS row's own stale self-service pending change -- staged, say, by
		// starting a self-service change and then signing in via OIDC before
		// confirming it -- as another account already holding the address, and
		// permanently refuse to sync (and thus log in) a user whose IdP claim
		// matches their own stale pending address.
		mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 1)}
		st, svc := newEmailChangeSvc(t, mailer)
		u := linked(t, st, "a@example.com")
		if err := st.Users().SetPendingEmail(t.Context(), u.ID, "b@example.com", "hash", store.NowUnix()+3600); err != nil {
			t.Fatal(err)
		}
		got := svc.SyncFromIDP(t.Context(), u, "b@example.com")
		if got.Email != "b@example.com" || got.ID != u.ID {
			t.Fatalf("returned %+v, want the row synced to b@example.com", got)
		}
		persisted, _ := st.Users().GetByID(t.Context(), u.ID)
		if persisted.Email != "b@example.com" {
			t.Errorf("persisted Email = %q, want b@example.com", persisted.Email)
		}
		// Drain the detached off-path notice so it cannot outlive the test.
		waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
	})
	t.Run("a changed claim overwrites, deletes grants, audits and notifies off-path", func(t *testing.T) {
		// release gates fakeMailer.Send via onSend, which fires as Send's FIRST
		// statement (grants_test.go:79); reachedSend closes at that same
		// instant. Racing resultCh against reachedSend -- never against a
		// wall-clock timer -- is what makes this deterministic: the race only
		// starts once SyncFromIDP reaches its `go sendAdvisory` statement, so
		// the DB writes that precede it (List, SetEmail, DeleteUnusedByUser,
		// the audit Log) can take however long they take under load without
		// ever entering the race. (An earlier version of this test raced
		// resultCh against time.After(100ms) instead; under this host's
		// current load that flaked -- FAIL 1 run in 5 -- because a slow DB
		// write alone could exceed 100ms even on the correct async path. That
		// is exactly the Task-4-history failure mode this fix is required to
		// avoid, so it was replaced rather than given a bigger margin.) A
		// synchronous sendAdvisory call cannot close reachedSend without also
		// blocking SyncFromIDP's own return on release, so the two channels
		// are mutually exclusive by construction, not by speed.
		// selfServiceRecoveryWaitTimeout below is a backstop against an actual
		// hang (neither channel ever firing), not a margin either real branch
		// is expected to graze.
		release := make(chan struct{})
		closeRelease := sync.OnceFunc(func() { close(release) })
		t.Cleanup(closeRelease)
		reachedSend := make(chan struct{})
		mailer := &fakeMailer{
			enabled: true,
			sendCh:  make(chan sentEmail, 1),
			onSend:  func() { close(reachedSend); <-release },
		}
		st, svc := newEmailChangeSvc(t, mailer)
		u := linked(t, st, "a@example.com")
		seedUnusedGrant(t, st, "grant-a", u.ID)

		resultCh := make(chan store.User, 1)
		go func() { resultCh <- svc.SyncFromIDP(t.Context(), u, "b@example.com") }()

		var got store.User
		select {
		case got = <-resultCh:
			// Returned while the notice's Send is still parked on release:
			// the send cannot have been on this call's path.
		case <-reachedSend:
			t.Fatal("SyncFromIDP blocked on its notice send before returning -- the notice is on the caller's path (design §5.6/B5 regression)")
		case <-time.After(selfServiceRecoveryWaitTimeout):
			t.Fatal("neither SyncFromIDP nor its notice send progressed -- test hung")
		}
		closeRelease()

		if got.Email != "b@example.com" || got.ID != u.ID {
			t.Fatalf("returned %+v, want the row with b@example.com", got)
		}
		persisted, _ := st.Users().GetByID(t.Context(), u.ID)
		if persisted.Email != "b@example.com" {
			t.Errorf("persisted Email = %q", persisted.Email)
		}
		if !grantGone(t, st, "grant-a") {
			t.Error("outstanding grant survived the change (D8)")
		}
		rows := auditRows(t, st, "user.email_changed_by_oidc")
		if len(rows) != 1 || rows[0].ActorUserID != u.ID || rows[0].DetailsJSON != `{"new":"b@example.com","old":"a@example.com"}` {
			t.Errorf("audit rows = %+v", rows)
		}
		e := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
		wantSubj, _ := emailpkg.ChangedBody("b@example.com")
		if e.to != "a@example.com" || e.subject != wantSubj {
			t.Errorf("notice = %+v, want the changed notice to a@example.com", e)
		}
	})
}

// TestEmailChange_Request_RollbackSurvivesCanceledRequestContext pins the same
// hazard grants.go's recordSendFailure and sendAdvisory already dodge
// (grants.go:120-134): sendAdvisory detaches the SEND itself from
// cancellation (context.WithoutCancel) specifically so a slow SMTP peer can
// outlive a client disconnect, which means a send that FAILS can do so after
// the caller's own request context is already canceled. If Request's rollback
// (ClearPendingEmail) reused that same canceled context, database/sql would
// reject the write before it reached the driver, leaving a dangling pending
// change with a confirmation link nobody will ever get -- and the
// no-resend short-circuit (D12) would then report success on retry while
// sending nothing, for up to emailChangeTTL.
//
// onSend, not a fixed sleep racing sendDelay: cancel fires as the first
// statement inside Send, the one point provably after every pre-send DB
// write (List, SetPendingEmail, the requested audit row) and before Send
// returns, so the test never races a real clock. A fixed sleep here would be
// flaky in exactly the direction that hides a regression -- too short and the
// pre-send writes haven't landed (false failure), too long under load and
// cancellation lands after the rollback already ran (false green on the
// buggy code) -- which is the same reasoning pollForAuditRows below already
// documents for the self-service flow.
func TestEmailChange_Request_RollbackSurvivesCanceledRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("smtp exploded"), onSend: cancel}
	st, svc := newEmailChangeSvc(t, mailer)
	u := seedUser(t, st, "old@example.com", "user")

	_, _, _, err := svc.Request(ctx, u, "new@example.com")
	if !errors.Is(err, ErrConfirmationNotSent) {
		t.Fatalf("err = %v, want ErrConfirmationNotSent", err)
	}

	got, getErr := st.Users().GetByID(t.Context(), u.ID)
	if getErr != nil {
		t.Fatalf("GetByID: %v", getErr)
	}
	if got.PendingEmail != "" || got.PendingEmailExpiresAt != 0 {
		t.Errorf("pending not rolled back on a canceled request context: (%q, %d)", got.PendingEmail, got.PendingEmailExpiresAt)
	}
}
