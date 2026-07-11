package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestClientExcludesHuma asserts the client binary's transitive imports do not
// include the huma API framework (a server-only dependency per the design).
// cobra/viper are shared and intentionally not checked.
func TestClientExcludesHuma(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	const forbidden = "github.com/danielgtaylor/huma"
	if strings.Contains(string(out), forbidden) {
		t.Errorf("client binary imports server-only dependency %q", forbidden)
	}
}
