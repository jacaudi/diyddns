package webui

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/logtest"
	"github.com/jacaudi/diyddns/internal/store"
)

// /register renders from GrantService.ClassifyRegistration: a live grant names
// its flow and account (no Email field, the token in a hidden input), first-run
// shows the claim form, and anything else is a dead end with no form (#188).
// Every render is a 200.

const (
	headingInvite   = "Finish setting up your account"
	headingRecovery = "Recover your passkey"
	headingFirstRun = "Set up the first admin"
	headingDead     = "This link can't be used"
	headingNoLink   = "You need a registration link"

	adviceAskAdmin   = "Ask an administrator for a new link."
	adviceSelfServe  = "If you requested this link yourself from the sign-in page, you can request another one there."
	noteRecoveryWipe = "removes the passkeys already on"
)

// getRegister serves GET target through the real mux.
func getRegister(t *testing.T, deps Deps, target string) *httptest.ResponseRecorder {
	t.Helper()
	h, _ := New(deps)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// seedLiveGrant gives a new user a live grant and returns the raw token that
// hashes to it.
func seedLiveGrant(t *testing.T, st *store.Store, email, reason string) string {
	t.Helper()
	usr := seedUser(t, st, email, "user")
	token, err := auth.RandToken(32)
	if err != nil {
		t.Fatalf("RandToken: %v", err)
	}
	seedGrant(t, st, usr.ID, auth.HashToken(token), reason, store.NowUnix()+3600)
	return token
}

func TestHandleRegister_Renders(t *testing.T) {
	tests := []struct {
		name string
		// setup seeds the store and returns the request target.
		setup   func(t *testing.T, st *store.Store) string
		want    []string
		notWant []string
	}{
		{
			name: "live invite grant",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				token := seedLiveGrant(t, st, "invitee@example.com", "invite")
				return "/register?token=" + token
			},
			want:    []string{headingInvite, "invitee@example.com", `id="register-name"`},
			notWant: []string{noteRecoveryWipe, headingRecovery, `id="register-email"`, adviceAskAdmin},
		},
		{
			name: "live recovery grant",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				token := seedLiveGrant(t, st, "locked-out@example.com", "recovery")
				return "/register?token=" + token
			},
			want:    []string{headingRecovery, "locked-out@example.com", noteRecoveryWipe, `id="register-name"`},
			notWant: []string{headingInvite, `id="register-email"`, adviceAskAdmin},
		},
		{
			name:    "first run, token from the query",
			setup:   func(*testing.T, *store.Store) string { return "/register?token=bootstrap-abc" },
			want:    []string{headingFirstRun, `id="register-token"`, `value="bootstrap-abc"`, `id="register-email"`, `id="register-name"`},
			notWant: []string{noteRecoveryWipe, adviceAskAdmin},
		},
		{
			name: "dead link: expired grant",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				usr := seedUser(t, st, "late@example.com", "user")
				token := "expired-token"
				seedGrant(t, st, usr.ID, auth.HashToken(token), "invite", store.NowUnix()-10)
				return "/register?token=" + token
			},
			want:    []string{headingDead, adviceAskAdmin, `href="/login"`},
			notWant: []string{"<form", `id="register-token"`, `id="register-email"`, headingNoLink, "late@example.com"},
		},
		{
			name: "dead link: unknown token",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				return "/register?token=no-such-token"
			},
			want:    []string{headingDead, adviceAskAdmin, `href="/login"`},
			notWant: []string{"<form", `id="register-token"`, headingNoLink},
		},
		{
			name: "dead, no token at all",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				return "/register"
			},
			want:    []string{headingNoLink, `href="/login"`},
			notWant: []string{"<form", headingDead, adviceAskAdmin},
		},
		{
			name: "dead, empty token parameter",
			setup: func(t *testing.T, st *store.Store) string {
				seedUser(t, st, "admin@example.com", "admin")
				return "/register?token="
			},
			want:    []string{headingNoLink, `href="/login"`},
			notWant: []string{"<form", headingDead, adviceAskAdmin},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, st := testDeps(t)
			target := tt.setup(t, st)

			rec := getRegister(t, deps, target)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q:\n%s", want, body)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(body, notWant) {
					t.Errorf("body contains %q, want it absent:\n%s", notWant, body)
				}
			}
		})
	}
}

// firstInputOfForm returns the first <input> tag inside the register form.
func firstInputOfForm(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<form id="register-form"[^>]*>\s*(<input[^>]*>)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no <input> directly inside the register form:\n%s", body)
	}
	return m[1]
}

// TestHandleRegister_GrantFormCarriesTheTokenInAHiddenFirstInput: a grant
// render has no Email field; the token rides in a hidden input that is the
// form's FIRST child, so the passkey-name field is still the element directly
// before the button (the .field:has(+ .btn) spacing rule).
func TestHandleRegister_GrantFormCarriesTheTokenInAHiddenFirstInput(t *testing.T) {
	for _, reason := range []string{"invite", "recovery"} {
		t.Run(reason, func(t *testing.T) {
			deps, st := testDeps(t)
			token := seedLiveGrant(t, st, "user@example.com", reason)

			body := getRegister(t, deps, "/register?token="+token).Body.String()

			first := firstInputOfForm(t, body)
			for _, want := range []string{`type="hidden"`, `id="register-token"`, `name="token"`, `value="` + token + `"`} {
				if !strings.Contains(first, want) {
					t.Errorf("first form input %s missing %s", first, want)
				}
			}
			if strings.Contains(body, `id="register-email"`) || strings.Contains(body, `name="email"`) {
				t.Errorf("a grant render must have no Email field:\n%s", body)
			}
			// Exactly one visible input remains: the passkey name.
			if n := strings.Count(body, "<input"); n != 2 {
				t.Errorf("inputs = %d, want 2 (hidden token + passkey name)", n)
			}
		})
	}
}

// TestHandleRegister_FirstRunFormRequiresTheEmail: the first-run form keeps its
// three ids, and the email is now required (it is the admin account's address).
func TestHandleRegister_FirstRunFormRequiresTheEmail(t *testing.T) {
	deps, _ := testDeps(t)

	body := getRegister(t, deps, "/register").Body.String()

	email := regexp.MustCompile(`<input[^>]*id="register-email"[^>]*>`).FindString(body)
	if email == "" {
		t.Fatalf("first-run form has no #register-email:\n%s", body)
	}
	// Drop the quoted values first: the placeholder text may say "required".
	attrs := regexp.MustCompile(`"[^"]*"`).ReplaceAllString(email, `""`)
	if !regexp.MustCompile(`\srequired[\s>]`).MatchString(attrs) {
		t.Errorf("#register-email has no required attribute: %s", email)
	}
	for _, id := range []string{"register-token", "register-name"} {
		if !strings.Contains(body, `id="`+id+`"`) {
			t.Errorf("first-run form missing #%s", id)
		}
	}
}

// TestHandleRegister_DeadPageOffersSelfServiceOnlyWhenMailIsEnabled: the
// self-service line sends the reader to the sign-in page's "Lost your passkey?"
// form, which exists only under email.enabled. The administrator advice leads
// either way.
func TestHandleRegister_DeadPageOffersSelfServiceOnlyWhenMailIsEnabled(t *testing.T) {
	for _, mail := range []bool{false, true} {
		name := "mail disabled"
		if mail {
			name = "mail enabled"
		}
		t.Run(name, func(t *testing.T) {
			deps, st := testDeps(t)
			deps.Cfg.Email.Enabled = mail
			seedUser(t, st, "admin@example.com", "admin")

			body := getRegister(t, deps, "/register?token=no-such-token").Body.String()

			if !strings.Contains(body, adviceAskAdmin) {
				t.Errorf("body missing %q", adviceAskAdmin)
			}
			if got := strings.Contains(body, adviceSelfServe); got != mail {
				t.Errorf("self-service line present = %v, want %v", got, mail)
			}
			if mail && strings.Index(body, adviceAskAdmin) > strings.Index(body, adviceSelfServe) {
				t.Errorf("the administrator advice must come before the self-service line")
			}
		})
	}
}

// TestHandleRegister_EscapesTheReflectedToken: ?token= is echoed into a form
// value on the first-run render. It must be HTML-escaped, never injected.
func TestHandleRegister_EscapesTheReflectedToken(t *testing.T) {
	deps, _ := testDeps(t)
	token := `"><script>alert(1)</script>`

	body := getRegister(t, deps, "/register?token="+url.QueryEscape(token)).Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("the token was reflected unescaped:\n%s", body)
	}
	m := regexp.MustCompile(`<input[^>]*id="register-token"[^>]*value="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no #register-token value in:\n%s", body)
	}
	if got := html.UnescapeString(m[1]); got != token {
		t.Errorf("#register-token value unescapes to %q, want %q", got, token)
	}
}

// TestHandleRegister_StoreFailureIsAnErrorPage: a failing store behind the
// classifier is a 500 with the shared error page and one Error line, not a
// misleading "link invalid" or "first-run" page.
func TestHandleRegister_StoreFailureIsAnErrorPage(t *testing.T) {
	_, buf, st, deps := loggingHandler(t)
	h, _ := New(deps)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/register?token=abc", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Something went wrong") {
		t.Errorf("body is not the shared error page:\n%s", rec.Body.String())
	}
	if n := strings.Count(buf.String(), `"level":"ERROR"`); n != 1 {
		t.Errorf("Error lines = %d, want 1:\n%s", n, buf)
	}
}

// TestHandleRegister_CancelledRequest: a request whose context is already done
// answers 499 with no body, one Info line ("webui: register cancelled") and no
// Error line, and the line never carries the token from the query string. It
// must write a status: a client that half-closes is still reading, and
// returning silently would hand it an empty 200. The handler is called
// directly, so the cancellation is deterministic.
func TestHandleRegister_CancelledRequest(t *testing.T) {
	const longToken = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJ" // 47 chars: long enough that a match means a leak
	for _, target := range []string{"/register?token=" + longToken, "/register"} {
		t.Run(target, func(t *testing.T) {
			h, buf, _, _ := loggingHandler(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			rec := httptest.NewRecorder()

			h.handleRegister(rec, httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx))

			if rec.Code != 499 {
				t.Errorf("status = %d, want 499", rec.Code)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("body = %q, want empty", rec.Body.String())
			}
			if n := strings.Count(buf.String(), "\n"); n != 1 {
				t.Fatalf("log lines = %d, want 1:\n%s", n, buf)
			}
			if line := logtest.Find(t, buf.String(), "webui: register cancelled"); line["level"] != "INFO" {
				t.Errorf("level = %v, want INFO", line["level"])
			}
			if strings.Contains(buf.String(), longToken) {
				t.Errorf("the log contains the token from the query string:\n%s", buf)
			}
		})
	}
}
