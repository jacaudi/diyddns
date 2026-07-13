package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClientExcludesServerOnlyDeps asserts the client binary's transitive
// imports include none of the server-only dependencies: the huma API
// framework, and the OIDC stack (oauth2/go-oidc/go-jose), which is confined to
// internal/oidc and never imported by the client (design §2). cobra/viper are
// shared and intentionally not checked.
func TestClientExcludesServerOnlyDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	for _, forbidden := range []string{
		"github.com/danielgtaylor/huma",
		"golang.org/x/oauth2",
		"github.com/coreos/go-oidc",
		"github.com/go-jose/go-jose",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Errorf("client binary imports server-only dependency %q", forbidden)
		}
	}
}
