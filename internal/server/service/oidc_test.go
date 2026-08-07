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
