package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// authTestCookieName mirrors the default cookie name from config's
// keyDefaults, kept as a local literal so this file doesn't depend on
// config's internal default map.
const authTestCookieName = "diyddns_session"

// doJSON sends method to url with an optional JSON body, cookie, and CSRF
// header. It reads and closes the response body itself — the same
// self-contained shape as agent_test.go's postJSON — and returns the status
// code, response header (for Set-Cookie inspection via findCookie), and raw
// body bytes, so callers never hold a live response.Body to leak.
func doJSON(t *testing.T, method, url string, body any, cookie *http.Cookie, csrf string) (status int, header http.Header, respBody []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, resp.Header, respBody
}

// findCookie returns the named cookie parsed from header's Set-Cookie
// entries, or nil if absent.
func findCookie(header http.Header, name string) *http.Cookie {
	resp := &http.Response{Header: header}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestMe_WithSessionCookieReturnsUserAndCSRF(t *testing.T) {
	h := newFullHarness(t)
	usr := seedUser(t, h.st, "me@example.com", "user")
	cookie, _ := sessionFor(t, h, "me@example.com")

	status, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("me status = %d, want 200, body=%s", status, meBody)
	}

	var got struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(meBody, &got); err != nil {
		t.Fatalf("decode me response: %v, body=%s", err, meBody)
	}
	if got.User.ID != usr.ID || got.User.Email != usr.Email || got.User.Role != usr.Role {
		t.Fatalf("me user = %+v, want id=%q email=%q role=%q", got.User, usr.ID, usr.Email, usr.Role)
	}
	if got.CSRF == "" {
		t.Fatal("me returned empty csrf token")
	}
}

func TestLogout_ClearsSessionSoSubsequentMeReturns401(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "logout@example.com", "user")
	cookie, _ := sessionFor(t, h, "logout@example.com")

	logoutStatus, _, logoutBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/logout", nil, cookie, "")
	if logoutStatus != http.StatusOK {
		t.Fatalf("logout status = %d, want 200, body=%s", logoutStatus, logoutBody)
	}

	meStatus, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	if meStatus != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d, want 401, body=%s", meStatus, meBody)
	}
}
