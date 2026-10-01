package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// TestPasskeyLoginFinish_FailureBodyStaysUniform: #91 started logging why a
// ceremony was rejected, but the response must not say. Every failure is the
// same 401 with exactly the fixed detail, whichever check failed.
func TestPasskeyLoginFinish_FailureBodyStaysUniform(t *testing.T) {
	const loginFinish = "/api/v1/auth/passkey/login/finish"
	tests := []struct {
		name string
		// fail drives one failing finish through the real server and returns its
		// status and body.
		fail func(t *testing.T, h fullHarness) (int, []byte)
	}{
		{"no challenge cookie", func(t *testing.T, h fullHarness) (int, []byte) {
			status, _, body := jarPost(t, jarClient(t), h.srv.URL+loginFinish, json.RawMessage("{}"), "")
			return status, body
		}},
		{"unreadable challenge cookie", func(t *testing.T, h fullHarness) (int, []byte) {
			client := jarClient(t)
			setChallengeCookie(t, client, h, "junk")
			status, _, body := jarPost(t, client, h.srv.URL+loginFinish, json.RawMessage("{}"), "")
			return status, body
		}},
		{"replayed challenge", func(t *testing.T, h fullHarness) (int, []byte) {
			user := seedUser(t, h.st, "alice@example.com", "user")
			setup := jarClient(t)
			authr, cred, _ := registerPasskeyHTTP(t, setup, h, jarSeedSession(t, setup, h, user.Email), "Key")

			client := jarClient(t)
			status, header, beginBody := jarPost(t, client, h.srv.URL+"/api/v1/auth/passkey/login/begin", nil, "")
			if status != http.StatusOK {
				t.Fatalf("login begin: status = %d, body=%s", status, beginBody)
			}
			cookie := findCookie(header, webauthnChallengeCookieName).Value
			assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(beginBody))
			if err != nil {
				t.Fatalf("ParseAssertionOptions: %v", err)
			}
			finish := json.RawMessage(virtualwebauthn.CreateAssertionResponse(apiTestRP(), authr, cred, *assertOpts))
			if status, _, body := jarPost(t, client, h.srv.URL+loginFinish, finish, ""); status != http.StatusOK {
				t.Fatalf("first login finish: status = %d, body=%s", status, body)
			}
			setChallengeCookie(t, client, h, cookie)
			status, _, body := jarPost(t, client, h.srv.URL+loginFinish, finish, "")
			return status, body
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFullHarness(t)

			status, body := tt.fail(t, h)

			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body=%s", status, body)
			}
			var problem struct {
				Title  string `json:"title"`
				Detail string `json:"detail"`
				Errors []any  `json:"errors"`
			}
			if err := json.Unmarshal(body, &problem); err != nil {
				t.Fatalf("decode error body: %v, body=%s", err, body)
			}
			if problem.Detail != errPasskeyVerificationDetail || problem.Title != "Unauthorized" || len(problem.Errors) != 0 {
				t.Errorf("error body = %+v, want only %q under title Unauthorized", problem, errPasskeyVerificationDetail)
			}
		})
	}
}
