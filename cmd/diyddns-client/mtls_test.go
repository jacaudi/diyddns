package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/client/mtls"
)

func TestMTLSReset_DeletesStateFile(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	statePath := mtls.PathFor(credPath)
	for _, p := range []string{credPath, statePath} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	reset := func() string {
		t.Helper()
		var out bytes.Buffer
		cmd := newMTLSCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"reset", "--credentials-file", credPath})
		if err := cmd.ExecuteContext(t.Context()); err != nil {
			t.Fatalf("mtls reset: %v", err)
		}
		return out.String()
	}

	if got, want := reset(), `ask an admin to click "Reset certificate"`; !strings.Contains(got, want) {
		t.Errorf("first run stdout %q lacks %q", got, want)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("mtls.json still present (stat err = %v)", err)
	}
	if _, err := os.Stat(credPath); err != nil {
		t.Errorf("credentials.json must be kept: %v", err)
	}
	if got, want := reset(), "nothing to delete"; !strings.Contains(got, want) {
		t.Errorf("second run stdout %q lacks %q", got, want)
	}
}
