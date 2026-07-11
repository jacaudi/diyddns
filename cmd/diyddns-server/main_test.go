package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "diyddns-server") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestServe_RequiresDatabasePath(t *testing.T) {
	// No --config, no DIYDDNS_DATABASE_PATH → config.Load must error before
	// the server blocks.
	t.Setenv("DIYDDNS_DATABASE_PATH", "")
	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "database.path") {
		t.Fatalf("want database.path error, got %v", err)
	}
}
