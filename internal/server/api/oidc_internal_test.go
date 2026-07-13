package api

import "testing"

// TestSafeNext is a white-box test (package api) because safeNext is
// unexported: it's the open-redirect defense for the OIDC callback's `next`
// query param and has no reason to be part of the package's public surface.
func TestSafeNext(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"scheme-relative double slash rejected", "//evil.com", "/"},
		{"backslash-escape rejected", "/\\evil", "/"},
		{"absolute URL rejected", "https://evil", "/"},
		{"local path allowed", "/devices", "/devices"},
		{"empty defaults to root", "", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeNext(tt.in); got != tt.want {
				t.Errorf("safeNext(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
