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
		{"version-and-commit", Info{Version: "1.0.0", Commit: "abc1234"}, "1.0.0 (abc1234)"},
		{"version-and-date", Info{Version: "1.0.0", Date: "2026-05-01"}, "1.0.0 (2026-05-01)"},
		{"empty", Info{}, "unknown"},
		{"only-commit", Info{Commit: "abc1234"}, "unknown"},
		{"only-date", Info{Date: "2026-05-01"}, "unknown"},
		{"commit-and-date-no-version", Info{Commit: "abc1234", Date: "2026-05-01"}, "unknown"},
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
