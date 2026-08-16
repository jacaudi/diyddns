package webui

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/version"
)

func TestClientImage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  string
		wantRef  string
		wantNote bool
	}{
		{"release", "v0.1.0", "ghcr.io/jacaudi/diyddns/client:v0.1.0", false},
		{"double digits", "v10.20.30", "ghcr.io/jacaudi/diyddns/client:v10.20.30", false},
		{"dev build", "v0.0.0-dev", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"empty", "", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"test fixture", "test", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"operator ldflags", "mybuild", "ghcr.io/jacaudi/diyddns/client:latest", true},
		// Build metadata is legal semver but an ILLEGAL Docker tag: docker
		// rejects it outright with "invalid reference format".
		{"build metadata", "v1.2.3+build7", "ghcr.io/jacaudi/diyddns/client:latest", true},
		// Prereleases are excluded deliberately — see TestReleasePleaseHasNoPrerelease.
		{"prerelease", "v1.2.3-rc.1", "ghcr.io/jacaudi/diyddns/client:latest", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, note := clientImage(version.Info{Version: tc.version})
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
			if got := note != ""; got != tc.wantNote {
				t.Errorf("note present = %v, want %v (note=%q)", got, tc.wantNote, note)
			}
		})
	}
}

// TestReleasePleaseHasNoPrerelease makes clientImage's prerelease exclusion
// mechanical rather than aspirational. releaseTagRe deliberately rejects
// vX.Y.Z-rc.N and falls back to :latest, which is correct ONLY while
// release-please cannot emit a prerelease tag. docker/metadata-action DOES
// publish an image for a prerelease, so if this config ever grows a prerelease
// key, clientImage would point RC operators away from an image that exists —
// and at a :latest that tracks main, i.e. ahead of their own server.
//
// The walk only descends into objects, not arrays; a prerelease key nested
// inside a plugins array would be missed. Adequate as a canary.
func TestReleasePleaseHasNoPrerelease(t *testing.T) {
	raw, err := os.ReadFile("../../../release-please-config.json")
	if err != nil {
		t.Fatalf("read release-please-config.json: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse release-please-config.json: %v", err)
	}
	var found []string
	var walk func(string, map[string]any)
	walk = func(path string, m map[string]any) {
		for k, v := range m {
			if strings.Contains(strings.ToLower(k), "prerelease") {
				found = append(found, path+"/"+k)
			}
			if nested, ok := v.(map[string]any); ok {
				walk(path+"/"+k, nested)
			}
		}
	}
	walk("", cfg)
	if len(found) > 0 {
		t.Fatalf("release-please-config.json now has prerelease key(s) %v — "+
			"revisit releaseTagRe in devices.go: prerelease images DO get published, "+
			"so falling back to :latest now points operators at the wrong image", found)
	}
}
