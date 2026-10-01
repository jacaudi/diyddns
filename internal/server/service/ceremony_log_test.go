package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// Issue #91: every passkey-ceremony rejection returns the uniform
// ErrPasskeyVerification and writes nothing a caller can read, so an operator
// could not tell a replayed challenge from a truncated cookie from a failed
// assertion. These tests pin the cause each rejection now logs (Info, with the
// request context), and that the returned error and the secrets stay out of it.

const (
	msgCookieNotOpened  = "passkey challenge cookie could not be opened"
	msgCookieNotDecoded = "passkey challenge cookie could not be decoded"
	msgChallengeReplay  = "passkey challenge replayed"
	msgLoginFailed      = "passkey login verification failed"
	msgLoginDisabled    = "passkey login rejected: account disabled"
	msgLoginClone       = "passkey login rejected: sign-count anomaly"
)

// beginLoginFor runs BeginLogin and has authr sign the challenge, returning the
// sealed cookie and the assertion body a browser would post.
func beginLoginFor(t *testing.T, svc *PasskeyService, authr virtualwebauthn.Authenticator, cred virtualwebauthn.Credential) (sealed, body string) {
	t.Helper()
	optsJSON, sealed, err := svc.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	return sealed, virtualwebauthn.CreateAssertionResponse(testRP(), authr, cred, *assertOpts)
}

// unregisteredAuthenticator is a virtual authenticator whose credential the
// server has never stored, so its user handle resolves to no account.
func unregisteredAuthenticator() (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte("unregistered-handle")})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	return authr, cred
}

// challengeOf returns the WebAuthn challenge sealed inside cookie, or "" when
// it cannot be opened. It opens the cookie itself rather than through
// openSession, which would log.
func challengeOf(cookie string) string {
	raw, err := auth.OpenWithAAD(testKey32(), cookie, webauthnAAD)
	if err != nil {
		return ""
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(raw, &sess); err != nil {
		return ""
	}
	return sess.Challenge
}

// newLoggedPasskeys builds a PasskeyService whose logger is captured.
func newLoggedPasskeys(t *testing.T, st *store.Store) (*PasskeyService, *lockedBuffer) {
	t.Helper()
	log, buf := captureLog()
	return newTestPasskeyServiceWithLog(t, st, discardAudit{}, log), buf
}

func TestOpenSession_LogsWhyTheCookieCouldNotBeOpened(t *testing.T) {
	wrongAAD, err := auth.SealWithAAD(testKey32(), []byte("{}"), bootstrapClaimAAD)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	tests := []struct {
		name   string
		cookie string
	}{
		{"no cookie", ""},
		{"truncated cookie", wrongAAD[:10]},
		{"cookie sealed for another purpose", wrongAAD},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, buf := newLoggedPasskeys(t, openTestStore(t))

			_, err := svc.openSession(t.Context(), tt.cookie)

			if !errors.Is(err, ErrPasskeyVerification) {
				t.Errorf("err = %v, want ErrPasskeyVerification", err)
			}
			rec := onlyRecord(t, buf, "INFO", msgCookieNotOpened)
			if got, _ := rec["error"].(string); got == "" {
				t.Errorf("error attribute = %v, want the cause", rec["error"])
			}
			if got := rec["sealed_len"]; got != float64(len(tt.cookie)) {
				t.Errorf("sealed_len = %v, want %d", got, len(tt.cookie))
			}
		})
	}
}

func TestOpenSession_LogsWhyTheCookieCouldNotBeDecoded(t *testing.T) {
	svc, buf := newLoggedPasskeys(t, openTestStore(t))
	notJSON, err := auth.SealWithAAD(testKey32(), []byte("not json"), webauthnAAD)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}

	_, err = svc.openSession(t.Context(), notJSON)

	if !errors.Is(err, ErrPasskeyVerification) {
		t.Errorf("err = %v, want ErrPasskeyVerification", err)
	}
	rec := onlyRecord(t, buf, "INFO", msgCookieNotDecoded)
	if got, _ := rec["error"].(string); got == "" {
		t.Errorf("error attribute = %v, want the cause", rec["error"])
	}
	if _, ok := rec["sealed_len"]; ok {
		t.Errorf("a decode failure carries no sealed_len, got %v", rec["sealed_len"])
	}
}

func TestClaimChallenge_LogsAReplayWithoutAttributes(t *testing.T) {
	svc, buf := newLoggedPasskeys(t, openTestStore(t))
	expires := time.Now().Add(time.Minute)

	if !svc.claimChallenge(t.Context(), "c1", expires) {
		t.Fatal("first claim of a challenge was refused")
	}
	if recs := logRecords(t, buf); len(recs) != 0 {
		t.Fatalf("a first claim logged: %s", buf.String())
	}
	if svc.claimChallenge(t.Context(), "c1", expires) {
		t.Fatal("a replayed challenge was accepted")
	}

	rec := onlyRecord(t, buf, "INFO", msgChallengeReplay)
	if len(rec) != 3 { // time, level, msg: no attributes
		t.Errorf("replay line has attributes: %v", rec)
	}
}

// lockProbe is a slog.Handler that records, for every record it handles,
// whether the used-challenge mutex was free at that moment. mu is set after the
// service is built (the service owns the mutex and needs the logger first).
type lockProbe struct {
	mu   *sync.Mutex
	free []bool
}

func (p *lockProbe) Enabled(context.Context, slog.Level) bool { return true }

func (p *lockProbe) Handle(context.Context, slog.Record) error {
	got := p.mu.TryLock()
	if got {
		p.mu.Unlock()
	}
	p.free = append(p.free, got)
	return nil
}

func (p *lockProbe) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p *lockProbe) WithGroup(string) slog.Handler      { return p }

// TestClaimChallenge_LogsAReplayAfterUnlocking pins the design's rule that
// claimChallenge decides under its mutex and logs after releasing it, so a slow
// log handler never holds up other ceremonies. The probe handler tries to take
// the mutex while it is handling the replay line: it succeeds only if the
// mutex was already released.
func TestClaimChallenge_LogsAReplayAfterUnlocking(t *testing.T) {
	probe := &lockProbe{}
	svc := newTestPasskeyServiceWithLog(t, openTestStore(t), discardAudit{}, slog.New(probe))
	probe.mu = &svc.usedMu
	expires := time.Now().Add(time.Minute)

	if !svc.claimChallenge(t.Context(), "c1", expires) {
		t.Fatal("first claim of a challenge was refused")
	}
	if svc.claimChallenge(t.Context(), "c1", expires) {
		t.Fatal("a replayed challenge was accepted")
	}

	if len(probe.free) != 1 {
		t.Fatalf("log records handled = %d, want exactly 1 (the replay)", len(probe.free))
	}
	if !probe.free[0] {
		t.Error("the replay line was handled while claimChallenge still held its mutex")
	}
}

func TestFinishLogin_ReplayIsLogged(t *testing.T) {
	st := openTestStore(t)
	svc, buf := newLoggedPasskeys(t, st)
	u := seedUser(t, st, "alice@example.com", "user")
	_, authr, cred := registerPasskey(t, svc, u.ID, "My Key", testRP())
	sealed, body := beginLoginFor(t, svc, authr, cred)
	if _, err := svc.FinishLogin(t.Context(), sealed, jsonRequest(body), "1.2.3.4", "ua"); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	buf.reset()

	_, err := svc.FinishLogin(t.Context(), sealed, jsonRequest(body), "1.2.3.4", "ua")

	if !errors.Is(err, ErrPasskeyVerification) {
		t.Errorf("err = %v, want ErrPasskeyVerification", err)
	}
	onlyRecord(t, buf, "INFO", msgChallengeReplay)
}

func TestFinishLogin_LogsAFailedVerification(t *testing.T) {
	tests := []struct {
		name string
		// body builds the request body; the sealed cookie is always valid.
		body func(t *testing.T, svc *PasskeyService) (sealed, body string)
		// wantInError is text the logged cause must contain.
		wantInError string
	}{
		{"assertion that does not parse", func(t *testing.T, svc *PasskeyService) (string, string) {
			_, sealed, err := svc.BeginLogin(t.Context())
			if err != nil {
				t.Fatalf("BeginLogin: %v", err)
			}
			return sealed, "{}"
		}, ""},
		{"user handle that resolves to no account", func(t *testing.T, svc *PasskeyService) (string, string) {
			authr, cred := unregisteredAuthenticator()
			return beginLoginFor(t, svc, authr, cred)
		}, "resolve user by webauthn handle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, buf := newLoggedPasskeys(t, openTestStore(t))
			sealed, body := tt.body(t, svc)
			buf.reset()

			_, err := svc.FinishLogin(t.Context(), sealed, jsonRequest(body), "1.2.3.4", "ua")

			if !errors.Is(err, ErrPasskeyVerification) {
				t.Errorf("err = %v, want ErrPasskeyVerification", err)
			}
			rec := onlyRecord(t, buf, "INFO", msgLoginFailed)
			got, _ := rec["error"].(string)
			if got == "" || !strings.Contains(got, tt.wantInError) {
				t.Errorf("error attribute = %q, want it to contain %q", got, tt.wantInError)
			}
		})
	}
}

func TestFinishLogin_LogsADisabledAccount(t *testing.T) {
	st := openTestStore(t)
	svc, buf := newLoggedPasskeys(t, st)
	u := seedUser(t, st, "alice@example.com", "user")
	_, authr, cred := registerPasskey(t, svc, u.ID, "My Key", testRP())
	if err := st.Users().SetDisabled(t.Context(), u.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	buf.reset()

	_, err := loginPasskey(t, svc, testRP(), authr, cred, "1.2.3.4", "ua")

	if !errors.Is(err, ErrPasskeyVerification) {
		t.Errorf("err = %v, want ErrPasskeyVerification", err)
	}
	rec := onlyRecord(t, buf, "INFO", msgLoginDisabled)
	if rec["user_id"] != u.ID {
		t.Errorf("user_id = %v, want %s", rec["user_id"], u.ID)
	}
}

func TestFinishLogin_LogsASignCountAnomaly(t *testing.T) {
	st := openTestStore(t)
	svc, buf := newLoggedPasskeys(t, st)
	u := seedUser(t, st, "alice@example.com", "user")
	stored, authr, cred := registerPasskey(t, svc, u.ID, "My Key", testRP())
	rewindSignCount(t, st, stored)
	buf.reset()

	_, err := loginPasskey(t, svc, testRP(), authr, cred, "1.2.3.4", "ua")

	if !errors.Is(err, ErrPasskeyVerification) {
		t.Errorf("err = %v, want ErrPasskeyVerification", err)
	}
	rec := onlyRecord(t, buf, "INFO", msgLoginClone)
	if rec["user_id"] != u.ID {
		t.Errorf("user_id = %v, want %s", rec["user_id"], u.ID)
	}
}

// TestCeremonyCallSites_LogTheirCause covers the call sites outside
// FinishLogin: each used to call the helpers without a context, and now logs
// through them.
func TestCeremonyCallSites_LogTheirCause(t *testing.T) {
	t.Run("FinishRegister with no cookie", func(t *testing.T) {
		st := openTestStore(t)
		svc, buf := newLoggedPasskeys(t, st)
		u := seedUser(t, st, "alice@example.com", "user")

		_, err := svc.FinishRegister(t.Context(), u.ID, "", "key", jsonRequest("{}"))

		if !errors.Is(err, ErrPasskeyVerification) {
			t.Errorf("err = %v, want ErrPasskeyVerification", err)
		}
		rec := onlyRecord(t, buf, "INFO", msgCookieNotOpened)
		if rec["sealed_len"] != float64(0) {
			t.Errorf("sealed_len = %v, want 0", rec["sealed_len"])
		}
	})

	t.Run("RedeemFinish with no cookie", func(t *testing.T) {
		st := openTestStore(t)
		svc, buf := newLoggedPasskeys(t, st)
		grants := newTestGrantService(t, st, svc, &fakeMailer{}, NewAuditWriter(st))
		u := seedUser(t, st, "alice@example.com", "user")
		token := seedGrant(t, st, u.ID, "invite", store.NowUnix()+3600, 0)

		_, err := grants.RedeemFinish(t.Context(), token, "", jsonRequest("{}"), "key")

		if !errors.Is(err, ErrPasskeyVerification) {
			t.Errorf("err = %v, want ErrPasskeyVerification", err)
		}
		rec := onlyRecord(t, buf, "INFO", msgCookieNotOpened)
		if rec["sealed_len"] != float64(0) {
			t.Errorf("sealed_len = %v, want 0", rec["sealed_len"])
		}
	})

	t.Run("RedeemFinish replaying a challenge", func(t *testing.T) {
		st := openTestStore(t)
		svc, buf := newLoggedPasskeys(t, st)
		grants := newTestGrantService(t, st, svc, &fakeMailer{}, NewAuditWriter(st))
		u := seedUser(t, st, "alice@example.com", "user")
		token := seedGrant(t, st, u.ID, "invite", store.NowUnix()+3600, 0)
		sealed, _ := beginRedeem(t, grants, token)
		// A body that cannot verify: the first call claims the challenge and then
		// fails verification, leaving the grant live for the replay.
		if _, err := grants.RedeemFinish(t.Context(), token, sealed, jsonRequest("{}"), "key"); !errors.Is(err, ErrPasskeyVerification) {
			t.Fatalf("first RedeemFinish: err = %v, want ErrPasskeyVerification", err)
		}
		buf.reset()

		_, err := grants.RedeemFinish(t.Context(), token, sealed, jsonRequest("{}"), "key")

		if !errors.Is(err, ErrPasskeyVerification) {
			t.Errorf("err = %v, want ErrPasskeyVerification", err)
		}
		onlyRecord(t, buf, "INFO", msgChallengeReplay)
	})

	t.Run("FinishClaim replaying a challenge", func(t *testing.T) {
		st := openTestStore(t)
		svc, buf := newLoggedPasskeys(t, st)
		var token string
		bootstrap := NewBootstrapService(st, discardLogger(), discardAudit{}, func(tok string) { token = tok }, svc, testKey32())
		if err := bootstrap.Startup(t.Context()); err != nil {
			t.Fatalf("Startup: %v", err)
		}
		sealed, _, err := bootstrap.BeginClaim(t.Context(), token, "admin@example.com")
		if err != nil {
			t.Fatalf("BeginClaim: %v", err)
		}
		if _, err := bootstrap.FinishClaim(t.Context(), sealed, jsonRequest("{}"), "key"); !errors.Is(err, ErrPasskeyVerification) {
			t.Fatalf("first FinishClaim: err = %v, want ErrPasskeyVerification", err)
		}
		buf.reset()

		_, err = bootstrap.FinishClaim(t.Context(), sealed, jsonRequest("{}"), "key")

		if !errors.Is(err, ErrPasskeyVerification) {
			t.Errorf("err = %v, want ErrPasskeyVerification", err)
		}
		onlyRecord(t, buf, "INFO", msgChallengeReplay)
	})
}

// TestCeremonyLogs_NeverContainTheChallengeOrTheCookie runs the rejections
// above and checks that no captured line carries the challenge, the sealed
// cookie, or any other value a caller could replay.
func TestCeremonyLogs_NeverContainTheChallengeOrTheCookie(t *testing.T) {
	st := openTestStore(t)
	svc, buf := newLoggedPasskeys(t, st)
	u := seedUser(t, st, "alice@example.com", "user")
	_, authr, cred := registerPasskey(t, svc, u.ID, "My Key", testRP())
	buf.reset()

	var secrets []string
	attempt := func(sealed, body string) {
		t.Helper()
		secrets = append(secrets, sealed, challengeOf(sealed))
		_, _ = svc.FinishLogin(t.Context(), sealed, jsonRequest(body), "1.2.3.4", "ua")
	}

	// A failed assertion, then the replay of the same cookie.
	sealed, _ := beginLoginFor(t, svc, authr, cred)
	attempt(sealed, "{}")
	attempt(sealed, "{}")
	// A truncated cookie, a cookie that is not JSON, and an unknown account.
	attempt(sealed[:12], "{}")
	notJSON, err := auth.SealWithAAD(testKey32(), []byte("not json"), webauthnAAD)
	if err != nil {
		t.Fatalf("SealWithAAD: %v", err)
	}
	attempt(notJSON, "{}")
	ghostAuthr, ghostCred := unregisteredAuthenticator()
	ghostSealed, ghostBody := beginLoginFor(t, svc, ghostAuthr, ghostCred)
	attempt(ghostSealed, ghostBody)

	logged := buf.String()
	if got := len(logRecords(t, buf)); got != 5 {
		t.Fatalf("log lines = %d, want 5 (one per attempt):\n%s", got, logged)
	}
	for _, secret := range secrets {
		if len(secret) < 8 {
			continue
		}
		if strings.Contains(logged, secret) {
			t.Errorf("a log line contains %q:\n%s", secret, logged)
		}
	}
}
