package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHasVersionSubcommand(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "version" {
			found = true
		}
	}
	if !found {
		t.Fatal("version subcommand not registered")
	}
}

func TestVersionSubcommandPrints(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "diyddns-client") {
		t.Errorf("output = %q", out.String())
	}
}

func TestVersionSubcommandJSON(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), `"Version"`) {
		t.Errorf("json output = %q", out.String())
	}
}
