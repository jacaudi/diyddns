package service

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// A rejected registration grant or enrollment code answers a uniform error and,
// until now, logged nothing, so an operator could not tell an expired link from
// a used one from a mistyped one. Both services now log why from ONE
// vocabulary (rejectReason), at Info, with the request context, and never the
// token, its hash or the code. The returned errors do not change.

const (
	msgGrantRejected = "registration grant rejected"
	msgCodeRejected  = "enrollment code rejected"
)

// newLoggedGrants builds a GrantService (with passkeys, so RedeemBegin gets past
// its availability check) whose logger is captured.
func newLoggedGrants(t *testing.T) (*store.Store, *GrantService, *lockedBuffer) {
	t.Helper()
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	log, buf := captureLog()
	return st, NewGrantService(st, passkeys, &fakeMailer{}, "https://ddns.example.com", NewAuditWriter(st), log, testLinkTTL), buf
}

// assertNoSecrets fails if any captured line contains one of secrets.
func assertNoSecrets(t *testing.T, buf *lockedBuffer, secrets ...string) {
	t.Helper()
	logged := buf.String()
	for _, secret := range secrets {
		if len(secret) >= 8 && strings.Contains(logged, secret) {
			t.Errorf("a log line contains %q:\n%s", secret, logged)
		}
	}
}

// wantRejection checks the single rejection line in buf: message, Info, the
// reason, and user_id only when the row was known.
func wantRejection(t *testing.T, buf *lockedBuffer, msg string, reason rejectReason, userID string) {
	t.Helper()
	rec := onlyRecord(t, buf, "INFO", msg)
	if rec["reason"] != string(reason) {
		t.Errorf("reason = %v, want %q", rec["reason"], reason)
	}
	got, has := rec["user_id"]
	switch {
	case userID == "" && has:
		t.Errorf("user_id = %v, want none (the row is unknown)", got)
	case userID != "" && got != userID:
		t.Errorf("user_id = %v, want %s", got, userID)
	}
}

func TestGrantService_ValidGrant_LogsWhyAGrantWasRejected(t *testing.T) {
	now := store.NowUnix()
	tests := []struct {
		name string
		// grant plants the grant, if any, for user and returns the token to redeem.
		grant      func(t *testing.T, st *store.Store, user store.User) string
		wantReason rejectReason
		wantUser   bool
	}{
		{"no token", func(*testing.T, *store.Store, store.User) string { return "" }, rejectMissing, false},
		{"unknown token", func(*testing.T, *store.Store, store.User) string { return "no-such-token" }, rejectUnknown, false},
		{"expired", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "invite", now-10, 0)
		}, rejectExpired, true},
		{"already used", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "invite", now+3600, now-5)
		}, rejectUsed, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, grants, buf := newLoggedGrants(t)
			user := seedUser(t, st, "alice@example.com", "user")
			token := tt.grant(t, st, user)

			_, _, _, err := grants.RedeemBegin(t.Context(), token)

			if !errors.Is(err, ErrGrantInvalid) {
				t.Fatalf("err = %v, want ErrGrantInvalid", err)
			}
			wantUser := ""
			if tt.wantUser {
				wantUser = user.ID
			}
			wantRejection(t, buf, msgGrantRejected, tt.wantReason, wantUser)
			assertNoSecrets(t, buf, token, auth.HashToken(token))
		})
	}
}

// hookBody is a request body that runs hook on its first Read. go-webauthn
// reads the body after validGrant and before Consume, so a hook that consumes
// the grant there makes Consume match no row: a lost race, made deterministic.
type hookBody struct {
	r    io.Reader
	hook func()
	done bool
}

func (b *hookBody) Read(p []byte) (int, error) {
	if !b.done {
		b.done = true
		b.hook()
	}
	return b.r.Read(p)
}

func (*hookBody) Close() error { return nil }

func TestGrantService_RedeemFinish_LogsALostRace(t *testing.T) {
	st, grants, buf := newLoggedGrants(t)
	user := seedUser(t, st, "alice@example.com", "user")
	token := seedGrant(t, st, user.ID, "invite", store.NowUnix()+3600, 0)
	sealed, attResp := beginRedeem(t, grants, token)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	var hookErr error
	req.Body = &hookBody{r: strings.NewReader(attResp), hook: func() {
		_, hookErr = st.AccountRecovery().Consume(t.Context(), auth.HashToken(token), store.NowUnix())
	}}
	buf.reset()

	_, err = grants.RedeemFinish(t.Context(), token, sealed, req, "key")

	if hookErr != nil {
		t.Fatalf("the racing consume failed: %v", hookErr)
	}
	if !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("err = %v, want ErrGrantInvalid", err)
	}
	wantRejection(t, buf, msgGrantRejected, rejectLostRace, user.ID)
	assertNoSecrets(t, buf, token, auth.HashToken(token))
	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("credentials = %d, want 0: the loser must not register a passkey", len(creds))
	}
}

// newLoggedEnrollment builds an EnrollmentService whose logger is captured.
func newLoggedEnrollment(t *testing.T) (*store.Store, *EnrollmentService, *lockedBuffer) {
	t.Helper()
	st := openTestStore(t)
	log, buf := captureLog()
	return st, NewEnrollmentService(st, testKey32(), 15*time.Minute, discardAudit{}, log), buf
}

// TestEnrollmentService_ConsumeCode_LogsALostRace: an AFTER INSERT trigger on
// devices marks the code used between the pre-check and Consume, so Consume
// matches no row. The compensating delete must still remove the device.
func TestEnrollmentService_ConsumeCode_LogsALostRace(t *testing.T) {
	st, svc, buf := newLoggedEnrollment(t)
	user := seedUser(t, st, "bob@example.com", "user")
	code, _, err := svc.CreateCode(t.Context(), user.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`CREATE TRIGGER mark_code_used AFTER INSERT ON devices
		 BEGIN UPDATE enrollment_codes SET used_at = 1 WHERE used_at IS NULL; END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	buf.reset()

	_, err = svc.ConsumeCode(t.Context(), code, ClientMeta{})

	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap store.ErrNotFound", err)
	}
	wantRejection(t, buf, msgCodeRejected, rejectLostRace, user.ID)
	assertNoSecrets(t, buf, code)
	devices, err := st.Devices().ListByUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Devices.ListByUser: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("devices = %d, want 0: the compensating delete must remove the device", len(devices))
	}
}
