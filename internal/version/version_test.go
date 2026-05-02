package version

import (
	"strings"
	"testing"
)

func TestStringFormat(t *testing.T) {
	cases := []struct {
		name string
		v    Info
		want string
	}{
		{"all-set", Info{Version: "1.2.3", Commit: "abcdef0", Date: "2026-05-01"}, "1.2.3 (abcdef0, 2026-05-01)"},
		{"only-version", Info{Version: "v0.0.0-dev"}, "v0.0.0-dev"},
		{"empty", Info{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			got := tc.v.String()
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCurrentReturnsNonEmpty(t *testing.T) {
	got := Current().String()
	if strings.TrimSpace(got) == "" {
		t.Fatal("Current().String() should never be empty")
	}
}
