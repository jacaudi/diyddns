package main

import (
	"errors"
	"strings"
	"testing"
)

func TestResolvePassword(t *testing.T) {
	neverTTY := func() bool { return false }
	yesTTY := func() bool { return true }
	failHidden := func() (string, error) { return "", errors.New("no terminal") }

	tests := []struct {
		name       string
		env        string
		stdin      string
		isTTY      func() bool
		readHidden func() (string, error)
		want       string
		wantErr    bool
	}{
		{"env wins", "envpw", "ignored\n", yesTTY, func() (string, error) { return "hiddenpw", nil }, "envpw", false},
		{"piped stdin when not a tty", "", "pipedpw\n", neverTTY, failHidden, "pipedpw", false},
		{"piped strips CRLF", "", "pw\r\n", neverTTY, failHidden, "pw", false},
		{"hidden prompt on a tty", "", "", yesTTY, func() (string, error) { return "hiddenpw", nil }, "hiddenpw", false},
		{"empty resolved password errors", "", "\n", neverTTY, failHidden, "", true},
		{"hidden read error propagates", "", "", yesTTY, failHidden, "", true},
		{"empty hidden read errors", "", "", yesTTY, func() (string, error) { return "", nil }, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePassword(tt.env, strings.NewReader(tt.stdin), &strings.Builder{}, tt.isTTY, tt.readHidden)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (got %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePassword: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
