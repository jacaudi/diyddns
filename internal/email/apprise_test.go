package email_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apprise "github.com/unraid/apprise-go"
	"go.uber.org/goleak"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
)

// stubSend is a sendFunc double: every call blocks until release is closed
// (when release is non-nil), then returns err, or panics with panicWith when
// that is set. calls counts invocations.
type stubSend struct {
	release   chan struct{}
	err       error
	panicWith any
	calls     atomic.Int32
}

func (s *stubSend) send(string, string, string) error {
	s.calls.Add(1)
	if s.release != nil {
		<-s.release
	}
	if s.panicWith != nil {
		panic(s.panicWith)
	}
	return s.err
}

var testCfg = config.EmailSection{
	Enabled: true, Host: "smtp.example.test", Port: 587, From: "noreply@example.test", TLS: "starttls",
}

// verifyNoLeak registers goleak LAST-to-run: t.Cleanup is LIFO, so registering
// it first means every later cleanup (closing a fake listener, releasing a
// stub) has already run and the send goroutine has had its chance to end.
// A stranded goroutine is a failing test (go-standards: goroutine leaks).
func verifyNoLeak(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
}

// TestMailer_Send_SaturationFailsFast: the in-flight cap is a hard bound. With
// a cap of one and a send that never returns, the second Send is refused
// without calling the transport at all, and the cap turns over once the
// first conversation ends.
func TestMailer_Send_SaturationFailsFast(t *testing.T) {
	verifyNoLeak(t)
	stub := &stubSend{release: make(chan struct{})}
	m := email.NewMailerForTest(testCfg, debugLogger(), 1, stub.send)

	var wg sync.WaitGroup
	var firstErr error
	wg.Go(func() { firstErr = m.Send(t.Context(), "user@example.test", "s", "b") })
	waitForCalls(t, &stub.calls, 1)

	err := m.Send(t.Context(), "other@example.test", "s", "b")
	if !errors.Is(err, email.ErrTransportSaturated) {
		t.Fatalf("second Send err = %v, want ErrTransportSaturated", err)
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("transport called %d times, want 1 — a refused send must not touch the network", got)
	}

	close(stub.release)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first Send: %v, want nil", firstErr)
	}
	if err := m.Send(t.Context(), "third@example.test", "s", "b"); err != nil {
		t.Fatalf("third Send after the slot freed: %v, want nil", err)
	}
}

// TestMailer_Send_AbandonedAtDeadlineKeepsItsSlot is what distinguishes the
// semaphore from a counter of abandoned sends: the caller leaves at its
// deadline, the conversation is still open, and it still counts.
func TestMailer_Send_AbandonedAtDeadlineKeepsItsSlot(t *testing.T) {
	verifyNoLeak(t)
	stub := &stubSend{release: make(chan struct{})}
	t.Cleanup(func() { close(stub.release) })
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := email.NewMailerForTest(testCfg, log, 1, stub.send)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.Send(ctx, "user@example.test", "s", "b")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Send took %v, want it bounded by the 50ms deadline", elapsed)
	}
	if !strings.Contains(buf.String(), "abandoned at deadline") {
		t.Errorf("expected an abandoned-at-deadline log line, got:\n%s", buf.String())
	}

	// The abandoned conversation still holds the only slot.
	if err := m.Send(t.Context(), "other@example.test", "s", "b"); !errors.Is(err, email.ErrTransportSaturated) {
		t.Fatalf("Send while the abandoned conversation is open: err = %v, want ErrTransportSaturated", err)
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("transport called %d times, want 1", got)
	}
}

// TestMailer_Send_LateCompletionIsLogged: a conversation the caller gave up
// on may still finish -- and deliver -- later. The only record of that is
// the warning the goroutine writes when it finally returns, which is also
// the operator's drain signal.
func TestMailer_Send_LateCompletionIsLogged(t *testing.T) {
	verifyNoLeak(t)
	stub := &stubSend{release: make(chan struct{})}
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := email.NewMailerForTest(testCfg, log, 1, stub.send)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := m.Send(ctx, "user@example.test", "s", "b"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	close(stub.release) // the peer answers, late; the stub returns nil = delivered

	waitForLog(t, &buf, "completed after its caller gave up")
	if got := buf.String(); !strings.Contains(got, "delivered=true") {
		t.Errorf("late-completion line must report the real outcome, got:\n%s", got)
	}
	// And the slot is free again.
	if err := m.Send(t.Context(), "other@example.test", "s", "b"); err != nil {
		t.Fatalf("Send after the late completion: %v, want nil", err)
	}
}

// TestMailer_Send_AbandonedFailureIsSanitizedInTheWarnLog pins the one log
// line written from inside the send goroutine, not the caller: the
// late-completion WARN. TestMailer_Send_SanitizesLibraryErrors never reaches
// it -- its stub has release == nil, so the send returns while the caller is
// still listening and abandoned never becomes true. This test forces the
// abandon-then-fail path so the WARN itself is exercised.
func TestMailer_Send_AbandonedFailureIsSanitizedInTheWarnLog(t *testing.T) {
	verifyNoLeak(t)
	const password = "PASS-do-not-leak-in-the-warn"
	stub := &stubSend{release: make(chan struct{}), err: errors.Join(&apprise.TargetError{
		URL: "mailto://svc:" + password + "@smtp.example.test:587?from=a@b.c", Err: errors.New("boom"),
	})}
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := testCfg
	cfg.Username, cfg.Password = "svc", password
	m := email.NewMailerForTest(cfg, log, 1, stub.send)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := m.Send(ctx, "user@example.test", "s", "b"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	close(stub.release) // the peer answers, late, with a failure

	waitForLog(t, &buf, "completed after its caller gave up")
	got := buf.String()
	if !strings.Contains(got, "delivered=false") {
		t.Errorf("late-completion line must report the real (failed) outcome, got:\n%s", got)
	}
	if strings.Contains(got, password) {
		t.Errorf("late-completion WARN carries the SMTP password:\n%s", got)
	}
}

// TestMailer_Send_AbandonedRaceNeverLosesTheOutcome is a regression test for
// the ordering of Store(&abandoned, true) relative to the non-blocking
// re-check of done in Send's ctx.Done branch. With the buggy ordering
// (re-check, THEN Store), a done <- err landing strictly between the two
// loses both signals: the caller returns DeadlineExceeded for a send that
// may have succeeded, AND the goroutine's own abandoned.Load() still reads
// false, so the late-completion WARN -- normally the only remaining record
// -- never fires either. Reproducing that interleaving needs many rounds:
// racing a very short deadline against the stub's release, over enough
// iterations, used to lose the WARN on the buggy ordering.
//
// This pins AT LEAST ONCE, not exactly once: the fixed ordering makes a rare
// duplicate report reachable (the caller's own result AND the WARN both
// fire for the same send), which is expected and harmless -- see the Store
// comment in apprise.go. This test does not fail on a duplicate; it only
// fails if an abandoned send's outcome is reported zero times.
func TestMailer_Send_AbandonedRaceNeverLosesTheOutcome(t *testing.T) {
	verifyNoLeak(t)
	const iterations = 400
	for i := range iterations {
		var buf syncBuffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		stub := &stubSend{release: make(chan struct{})}
		m := email.NewMailerForTest(testCfg, log, 1, stub.send)

		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		var releaseWG sync.WaitGroup
		releaseWG.Go(func() {
			time.Sleep(time.Millisecond) // race this against the same-length deadline
			close(stub.release)
		})

		err := m.Send(ctx, "user@example.test", "s", "b")
		cancel()
		releaseWG.Wait()

		if err == nil {
			// The stub answered before (or exactly at) the deadline: the
			// caller already holds the real, non-abandoned result.
			continue
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("iteration %d: Send err = %v, want nil or context.DeadlineExceeded", i, err)
		}
		// Abandoned: the WARN is the only remaining record of the outcome,
		// and the fix guarantees it is never silently dropped.
		waitForLog(t, &buf, "completed after its caller gave up")
	}
}

// syncBuffer is a bytes.Buffer safe for a logger written from the send
// goroutine and read by the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLog blocks until buf contains want or five seconds pass.
func waitForLog(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q within 5s; got:\n%s", want, buf.String())
		}
		time.Sleep(time.Millisecond)
	}
}

// TestMailer_Send_TransportPanicIsAFailedSend: a panic inside the library is
// reported as a delivery failure and releases the slot; it never takes the
// process down.
func TestMailer_Send_TransportPanicIsAFailedSend(t *testing.T) {
	verifyNoLeak(t)
	stub := &stubSend{panicWith: "library exploded"}
	m := email.NewMailerForTest(testCfg, debugLogger(), 1, stub.send)

	err := m.Send(t.Context(), "user@example.test", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "transport panic") {
		t.Fatalf("Send err = %v, want a transport panic error", err)
	}
	stub.panicWith = nil
	if err := m.Send(t.Context(), "user@example.test", "s", "b"); err != nil {
		t.Fatalf("Send after a recovered panic: %v, want nil — the slot must have been released", err)
	}
}

// TestMailer_Send_SanitizesLibraryErrors: the library renders its target URL,
// password included, into *TargetError and a parse failure into *url.Error.
// Neither the returned error nor the log may carry it.
func TestMailer_Send_SanitizesLibraryErrors(t *testing.T) {
	verifyNoLeak(t)
	const password = "PASS-do-not-leak"
	tests := []struct {
		name string
		err  error
	}{
		{name: "TargetError", err: errors.Join(&apprise.TargetError{
			URL: "mailto://svc:" + password + "@smtp.example.test:587?from=a@b.c", Err: errors.New("boom"),
		})},
		{name: "url.Error", err: &url.Error{
			Op: "parse", URL: "mailto://svc:" + password + "@smtp.example.test:587", Err: errors.New("boom"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			cfg := testCfg
			cfg.Username, cfg.Password = "svc", password
			stub := &stubSend{err: tt.err}
			m := email.NewMailerForTest(cfg, log, 1, stub.send)

			err := m.Send(t.Context(), "user@example.test", "s", "b")
			if err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("Send err = %v, want it to carry the inner error", err)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("returned error carries the SMTP password: %v", err)
			}
			if strings.Contains(buf.String(), password) {
				t.Errorf("log output carries the SMTP password:\n%s", buf.String())
			}
		})
	}
}

// TestMailer_TargetURL pins the URL shape the facade renders: mode, format,
// from and to are explicit; the password survives url.UserPassword and
// url.Parse for every reserved character it might contain. This test calls
// neither apprise.New nor .Add -- it only proves the string round-trips
// through Go's own net/url, nothing about whether the real apprise-go
// library would parse or accept it. This task does not wire appriseMailer
// into email.New (Task 4 does), so the wire tests in email_test.go today
// exercise smtpMailer only; that library-acceptance question stays
// unverified until Task 4 switches New over and those wire tests actually
// exercise appriseMailer end-to-end -- Task 4 must confirm it then.
func TestMailer_TargetURL(t *testing.T) {
	const password = "p@ss:w/rd%25#&=+"
	tests := []struct {
		name     string
		tlsMode  string
		wantMode string
		username string
	}{
		{name: "starttls, no auth", tlsMode: "starttls", wantMode: "starttls"},
		{name: "implicit, no auth", tlsMode: "implicit", wantMode: "ssl"},
		{name: "none, no auth", tlsMode: "none", wantMode: "insecure"},
		{name: "starttls with auth", tlsMode: "starttls", wantMode: "starttls", username: "svc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.EmailSection{
				Enabled: true, Host: "smtp.example.test", Port: 2525, From: "noreply@example.test",
				TLS: tt.tlsMode, Username: tt.username, Password: password,
			}
			raw := email.TargetURLForTest(cfg, "user+tag@example.test")
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", raw, err)
			}
			if u.Scheme != "mailto" || u.Host != "smtp.example.test:2525" {
				t.Errorf("scheme/host = %q/%q, want mailto/smtp.example.test:2525", u.Scheme, u.Host)
			}
			q := u.Query()
			for key, want := range map[string]string{
				"mode": tt.wantMode, "format": "text", "from": "noreply@example.test", "to": "user+tag@example.test",
			} {
				if got := q.Get(key); got != want {
					t.Errorf("query %s = %q, want %q", key, got, want)
				}
			}
			if tt.username == "" {
				if u.User != nil {
					t.Errorf("userinfo = %q, want none without a username", u.User.String())
				}
				return
			}
			gotPass, _ := u.User.Password()
			if u.User.Username() != tt.username || gotPass != password {
				t.Errorf("userinfo = %q/%q, want %q/%q", u.User.Username(), gotPass, tt.username, password)
			}
		})
	}
}

// waitForCalls blocks until the counter reaches want or the test times out.
func waitForCalls(t *testing.T, calls *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("transport was called %d times, want %d within 5s", calls.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}
