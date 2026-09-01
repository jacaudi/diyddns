package webui

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// loggingHandler builds a handler wired to a JSON logger writing into the
// returned buffer, so a test can assert on the records the four auth guards
// emit. It also returns the store and Deps: the CSRF and ParseForm tests sit
// behind requireSession and need a seeded session cookie, which requires
// both.
func loggingHandler(t *testing.T) (*handler, *bytes.Buffer, *store.Store, Deps) {
	t.Helper()
	deps, st := testDeps(t)
	var buf bytes.Buffer
	deps.Log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return newTestHandler(t, deps), &buf, st, deps
}

// findRecord returns the first JSON record in buf whose msg matches, or fails.
func findRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %v (%s)", err, line)
		}
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no record with msg %q in:\n%s", msg, buf.String())
	return nil
}

func TestRequireSession_LogsRejection(t *testing.T) {
	h, buf, _, _ := loggingHandler(t)
	rec := httptest.NewRecorder()
	h.requireSession(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
		t.Fatal("handler ran without a session")
	})(rec, httptest.NewRequest(http.MethodGet, "/devices/dev_01J8W", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
	line := findRecord(t, buf, "session auth rejected")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["reason"] != "no_cookie" {
		t.Errorf("reason = %v, want no_cookie", line["reason"])
	}
}

// The recorded exclusion. GET /{$} is the anonymous homepage; logging it would
// emit a record per crawler hit. If this test ever fails because someone
// "fixed" the inconsistency, read design 8.6 before changing it.
func TestHandleRoot_DoesNotLogRejection(t *testing.T) {
	h, buf, _, _ := loggingHandler(t)
	rec := httptest.NewRecorder()
	h.handleRoot(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if buf.Len() != 0 {
		t.Fatalf("handleRoot logged a rejection; it is excluded on volume: %s", buf.String())
	}
}

// TestAdminOnly_LogsRejection is the admin door. adminOnly returns a
// sessionHandler, not an http.HandlerFunc, and never authenticates itself --
// so the test passes a non-admin user directly rather than seeding a cookie.
func TestAdminOnly_LogsRejection(t *testing.T) {
	h, buf, _, _ := loggingHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	usr := store.User{ID: "usr_test123", Role: "user"}

	h.adminOnly(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
		t.Fatal("handler ran for a non-admin user")
	})(rec, req, usr, store.Session{})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	line := findRecord(t, buf, "admin role required")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["user_id"] != "usr_test123" {
		t.Errorf("user_id = %v, want usr_test123", line["user_id"])
	}
	if line["role"] != "user" {
		t.Errorf("role = %v, want user", line["role"])
	}
}

// TestRequirePost_LogsCSRFRejection is the CSRF door. requirePost wraps
// requireSession, so without a valid session cookie the request 303s at the
// session door and never reaches the CSRF check -- hence the seeded cookie.
func TestRequirePost_LogsCSRFRejection(t *testing.T) {
	h, buf, st, deps := loggingHandler(t)
	cookie, sess := seedSessionCookie(t, st, deps.Sessions, "csrf@example.com")

	req := httptest.NewRequest(http.MethodPost, "/devices/dev_01J8W/label", strings.NewReader("csrf=wrong-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	h.requirePost(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
		t.Fatal("handler ran with an invalid csrf token")
	})(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	line := findRecord(t, buf, "csrf rejected")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["user_id"] != sess.UserID {
		t.Errorf("user_id = %v, want %s", line["user_id"], sess.UserID)
	}
}

// TestRequirePost_LogsMalformedForm is the ParseForm door, same requireSession
// wrapping as the CSRF door above.
func TestRequirePost_LogsMalformedForm(t *testing.T) {
	h, buf, st, deps := loggingHandler(t)
	cookie, sess := seedSessionCookie(t, st, deps.Sessions, "malformed@example.com")

	req := httptest.NewRequest(http.MethodPost, "/devices/dev_01J8W/label", strings.NewReader("csrf=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	h.requirePost(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
		t.Fatal("handler ran with a malformed form body")
	})(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	line := findRecord(t, buf, "malformed form")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["user_id"] != sess.UserID {
		t.Errorf("user_id = %v, want %s", line["user_id"], sess.UserID)
	}
}
