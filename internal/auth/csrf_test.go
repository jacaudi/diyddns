package auth

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func TestValidCSRF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		sess  store.Session
		token string
		want  bool
	}{
		{"matching token", store.Session{CSRFToken: "abc123"}, "abc123", true},
		{"mismatched token", store.Session{CSRFToken: "abc123"}, "xyz789", false},
		{"empty submitted token", store.Session{CSRFToken: "abc123"}, "", false},
		{"empty session token never validates", store.Session{CSRFToken: ""}, "", false},
		{"empty session token rejects any input", store.Session{CSRFToken: ""}, "abc123", false},
		{"prefix is not a match", store.Session{CSRFToken: "abc123"}, "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidCSRF(tt.sess, tt.token); got != tt.want {
				t.Errorf("ValidCSRF(%q, %q) = %v, want %v", tt.sess.CSRFToken, tt.token, got, tt.want)
			}
		})
	}
}
