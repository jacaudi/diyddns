package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// The challenges a 401 must carry (RFC 9110 §15.5.2), written out here rather
// than taken from internal/shared, so a changed constant fails this test.
const (
	challengeHMAC         = `DIYDDNS-HMAC realm="diyddns"`
	challengeDIYDDNS      = `DIYDDNS realm="diyddns"`
	challengeSessionOrKey = `Bearer realm="diyddns", DIYDDNS realm="diyddns"`
)

// requestChallenge sends one request with no credential beyond header and
// returns the status and the WWW-Authenticate header.
func requestChallenge(t *testing.T, method, url string, body any, header map[string]string) (int, string) {
	t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

// TestUnauthorized_CarriesTheChallengeForItsCredential: every place the API
// answers 401 names the credential the route takes (#191). None is Basic, so
// no browser shows its own credentials prompt.
func TestUnauthorized_CarriesTheChallengeForItsCredential(t *testing.T) {
	fresh := newFullHarness(t) // no admin yet: register/begin is a first-run claim
	claimed := newFullHarness(t)
	seedUser(t, claimed.st, "admin@example.com", "admin") // register/begin redeems a link

	for _, tt := range []struct {
		name, method, url string
		body              any
		header            map[string]string
		want              string
	}{
		{"agent route without a signature", http.MethodPost, fresh.srv.URL + "/agent/v1/checkin", map[string]string{}, nil, challengeHMAC},
		{"session-only route without a cookie", http.MethodGet, fresh.srv.URL + "/api/v1/account/keys", nil, nil, challengeDIYDDNS},
		{"session-or-key route without a credential", http.MethodGet, fresh.srv.URL + "/api/v1/devices", nil, nil, challengeSessionOrKey},
		{"session-or-key route with a bad key", http.MethodGet, fresh.srv.URL + "/api/v1/devices", nil,
			map[string]string{"Authorization": "Bearer not-a-key"}, challengeSessionOrKey},
		{"passkey login without a ceremony", http.MethodPost, fresh.srv.URL + "/api/v1/auth/passkey/login/finish", map[string]string{}, nil, challengeDIYDDNS},
		{"first-run claim with a wrong token", http.MethodPost, fresh.srv.URL + registerBeginPath,
			map[string]string{"token": "wrong", "email": "admin@example.com"}, nil, challengeDIYDDNS},
		{"register link that is not valid", http.MethodPost, claimed.srv.URL + registerBeginPath,
			map[string]string{"token": "never-issued"}, nil, challengeDIYDDNS},
		{"register finish without a ceremony", http.MethodPost, fresh.srv.URL + registerFinishPath, map[string]string{}, nil, challengeDIYDDNS},
		{"enrollment code never issued", http.MethodPost, fresh.srv.URL + "/agent/v1/enroll/code",
			map[string]string{"code": "never-issued"}, nil, challengeDIYDDNS},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, got := requestChallenge(t, tt.method, tt.url, tt.body, tt.header)
			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", status)
			}
			if got != tt.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
		})
	}
}
