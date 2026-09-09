package service

import (
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestOIDCLoginOrLink(t *testing.T) {
	newSvc := func(t *testing.T, st *store.Store, cfg config.OIDCCfg) *OIDCService {
		t.Helper()
		sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
		return NewOIDCService(st, sm, cfg, NewAuditWriter(st), discardLogger())
	}
	baseCfg := config.OIDCCfg{AutoLinkByEmail: true, AllowOIDCSignup: true}
	const iss = "https://idp.example.com"

	t.Run("existing subject logs in", func(t *testing.T) {
		st := openTestStore(t)
		u, _ := st.Users().Create(t.Context(), store.User{Email: "a@x.com", Role: "user", OIDCProvider: iss, OIDCSubject: "s1"})
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s1", "a@x.com", true)
		if err != nil || got.ID != u.ID {
			t.Fatalf("want login of %s, got %+v err=%v", u.ID, got, err)
		}
	})

	t.Run("verified email links existing local user", func(t *testing.T) {
		st := openTestStore(t)
		u, _ := st.Users().Create(t.Context(), store.User{Email: "b@x.com", Role: "user"})
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s2", "b@x.com", true)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if got.OIDCProvider != iss || got.OIDCSubject != "s2" || got.ID != u.ID {
			t.Fatalf("expected link onto %s, got %+v", u.ID, got)
		}
	})

	t.Run("admin is never auto-linked", func(t *testing.T) {
		st := openTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "admin@x.com", Role: "admin"})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s3", "admin@x.com", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for admin email, got %v", err)
		}
	})

	t.Run("unverified email with existing account is rejected, not duplicated", func(t *testing.T) {
		st := openTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "c@x.com", Role: "user"})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s4", "c@x.com", false); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
	})

	t.Run("empty email is rejected", func(t *testing.T) {
		st := openTestStore(t)
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s5", "", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for empty email, got %v", err)
		}
	})

	t.Run("new verified user is created as role=user", func(t *testing.T) {
		st := openTestStore(t)
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s6", "new@x.com", true)
		if err != nil || got.Role != "user" || got.OIDCSubject != "s6" {
			t.Fatalf("signup: %+v err=%v", got, err)
		}
	})

	t.Run("signup disabled rejects unknown user", func(t *testing.T) {
		st := openTestStore(t)
		cfg := baseCfg
		cfg.AllowOIDCSignup = false
		if _, err := newSvc(t, st, cfg).LoginOrLink(t.Context(), iss, "s7", "nope@x.com", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
	})

	t.Run("disabled linked user is rejected", func(t *testing.T) {
		st := openTestStore(t)
		_, _ = st.Users().Create(t.Context(), store.User{Email: "d@x.com", Role: "user", OIDCProvider: iss, OIDCSubject: "s8", Disabled: true})
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s8", "d@x.com", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected for disabled user, got %v", err)
		}
	})

	// Path 1 must be untouched. An already-linked user whose IdP emits a
	// non-ASCII claim must still log in: that path never reads the email
	// argument, and rejecting there would be a lockout manufactured by an
	// address-formatting rule.
	t.Run("existing linked user with a non-ascii stored email still logs in", func(t *testing.T) {
		st := openTestStore(t)
		u, err := st.Users().Create(t.Context(), store.User{
			Email: "josé@example.test", Role: "user", OIDCProvider: iss, OIDCSubject: "s-nonascii",
		})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-nonascii", "josé@example.test", true)
		if err != nil {
			t.Fatalf("path-1 login must not be broken by the new guard: %v", err)
		}
		if got.ID != u.ID {
			t.Fatalf("logged in as %s, want %s", got.ID, u.ID)
		}
	})

	// DELIBERATE, maintainer-decided consequence of the guard above (design
	// §5.7 said "do not reject login for such a user"; the maintainer chose to
	// accept this narrower regression instead of adding a raw-claim lookup
	// fallback). A user whose STORED row is non-ASCII (created before the
	// boundary validations existed) and who has NOT YET linked an OIDC
	// identity can no longer auto-link via path 2: normalizeClaim rejects the
	// matching non-ASCII claim before GetByEmail ever runs. Before this guard
	// existed, this exact case auto-linked and the user could sign in; now it
	// is ErrOIDCRejected, and there is no admin-facing way to fix the stored
	// address (applyRole only writes role) — not self-service recoverable.
	// If this test ever starts failing, that is a scope decision (adding the
	// lookup fallback, or a migration), not a bug fix.
	t.Run("existing UNLINKED user with a non-ascii stored email is rejected, not auto-linked", func(t *testing.T) {
		st := openTestStore(t)
		_, err := st.Users().Create(t.Context(), store.User{Email: "josé@example.test", Role: "user"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-nonascii-unlinked", "josé@example.test", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected (deliberate — see comment above), got %v", err)
		}
	})

	t.Run("non-ascii claim is rejected at signup", func(t *testing.T) {
		st := openTestStore(t)
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-new", "josé@example.test", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
		users, err := st.Users().List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(users) != 0 {
			t.Errorf("users = %d, want 0 — a rejected signup must create nothing", len(users))
		}
	})

	// The lockout the fix itself would cause if the lookup were not normalized
	// alongside the create: a display-name-form claim must find its own row via
	// GetByEmail and LINK, not fall through to signup and hit ErrConflict.
	t.Run("display-name form claim links the existing normalized row", func(t *testing.T) {
		st := openTestStore(t)
		u, err := st.Users().Create(t.Context(), store.User{Email: "bob@example.test", Role: "user"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-display", "Bob <bob@example.test>", true)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if got.ID != u.ID || got.OIDCSubject != "s-display" {
			t.Fatalf("expected a link onto %s, got %+v", u.ID, got)
		}
	})

	// #93: the mirror of the case above. A legacy row stored in display-name
	// form (created before #87's boundary validations existed) plus the same
	// display-name-form claim must resolve to that ORIGINAL row. Before the
	// fix the claim was canonicalized, GetByEmail missed the raw row, signup
	// succeeded, and the user landed in a second empty account while the row
	// holding their devices and history was orphaned.
	t.Run("legacy display-name row is linked, not duplicated", func(t *testing.T) {
		st := openTestStore(t)
		legacy, err := st.Users().Create(t.Context(), store.User{Email: "Bob <bob@example.test>", Role: "user"})
		if err != nil {
			t.Fatalf("create legacy user: %v", err)
		}
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-legacy", "Bob <bob@example.test>", true)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("logged in as %s, want the original row %s", got.ID, legacy.ID)
		}
		users, err := st.Users().List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("users = %d, want 1 - the login must not create a second account", len(users))
		}
	})

	// The half of #93 the issue does not name. The claim form is irrelevant:
	// what is stale is the ROW, so an ordinary canonical claim misses the
	// legacy row exactly as the display-name one does. A fallback that simply
	// retried the raw claim as a second lookup key would pass the test above
	// and still fail this one.
	t.Run("legacy display-name row is found by an ordinary canonical claim", func(t *testing.T) {
		st := openTestStore(t)
		legacy, err := st.Users().Create(t.Context(), store.User{Email: "Bob <bob@example.test>", Role: "user"})
		if err != nil {
			t.Fatalf("create legacy user: %v", err)
		}
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-legacy-canon", "bob@example.test", true)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("logged in as %s, want the original row %s", got.ID, legacy.ID)
		}
		users, err := st.Users().List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("users = %d, want 1 - the login must not create a second account", len(users))
		}
	})

	// Linking repairs the stored address. Until it is canonical the row is
	// rejected by email.checkSendable, so the user receives no invite and no
	// recovery mail. Asserted against the STORE, not the returned struct.
	t.Run("linking a legacy row canonicalizes its stored address", func(t *testing.T) {
		st := openTestStore(t)
		legacy, err := st.Users().Create(t.Context(), store.User{Email: "Bob <bob@example.test>", Role: "user"})
		if err != nil {
			t.Fatalf("create legacy user: %v", err)
		}
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-legacy-repair", "Bob <bob@example.test>", true); err != nil {
			t.Fatalf("link: %v", err)
		}
		reloaded, err := st.Users().GetByID(t.Context(), legacy.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if reloaded.Email != "bob@example.test" {
			t.Errorf("stored email = %q, want %q", reloaded.Email, "bob@example.test")
		}
	})

	// A legacy row that CANNOT be linked must still not fall through to
	// signup. Both reasons a link is refused get their own case, because they
	// are separate branches and each one used to end in a duplicate account.
	t.Run("legacy display-name row with an unverified claim is rejected, not duplicated", func(t *testing.T) {
		st := openTestStore(t)
		if _, err := st.Users().Create(t.Context(), store.User{Email: "Bob <bob@example.test>", Role: "user"}); err != nil {
			t.Fatalf("create legacy user: %v", err)
		}
		if _, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-legacy-unverified", "Bob <bob@example.test>", false); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
		users, err := st.Users().List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("users = %d, want 1 - a rejected login must create nothing", len(users))
		}
	})

	t.Run("legacy display-name row with auto-link off is rejected, not duplicated", func(t *testing.T) {
		st := openTestStore(t)
		if _, err := st.Users().Create(t.Context(), store.User{Email: "Bob <bob@example.test>", Role: "user"}); err != nil {
			t.Fatalf("create legacy user: %v", err)
		}
		cfg := baseCfg
		cfg.AutoLinkByEmail = false
		if _, err := newSvc(t, st, cfg).LoginOrLink(t.Context(), iss, "s-legacy-nolink", "Bob <bob@example.test>", true); !errors.Is(err, ErrOIDCRejected) {
			t.Fatalf("want ErrOIDCRejected, got %v", err)
		}
		users, err := st.Users().List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("users = %d, want 1 - a rejected login must create nothing", len(users))
		}
	})

	t.Run("signup stores the normalized address", func(t *testing.T) {
		st := openTestStore(t)
		got, err := newSvc(t, st, baseCfg).LoginOrLink(t.Context(), iss, "s-norm", "Carol <carol@example.test>", true)
		if err != nil {
			t.Fatalf("signup: %v", err)
		}
		if got.Email != "carol@example.test" {
			t.Errorf("stored email = %q, want %q", got.Email, "carol@example.test")
		}
	})
}

func TestOIDCBrowserLogin_CreatesSession(t *testing.T) {
	st := openTestStore(t)
	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	svc := NewOIDCService(st, sm, config.OIDCCfg{AutoLinkByEmail: true, AllowOIDCSignup: true}, NewAuditWriter(st), discardLogger())
	sess, err := svc.BrowserLogin(t.Context(), "https://idp.example.com", "s9", "e@x.com", true, "1.2.3.4", "ua")
	if err != nil || sess.ID == "" || sess.CSRFToken == "" {
		t.Fatalf("BrowserLogin: sess=%+v err=%v", sess, err)
	}
}
