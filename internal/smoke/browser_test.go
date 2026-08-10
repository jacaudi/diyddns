//go:build browser

// Browser smoke: the only thing in this repo that executes passkey.js.
//
// Separate build tag from `smoke` because it needs Node and a Chromium
// download, which `task smoke` deliberately does not. Neither tag is in the
// default build, so `go build ./...` and `go test ./...` are unaffected and
// the project still builds with the Go toolchain alone.
//
//	task smoke:browser
//
// Skips (rather than fails) when node/npx is absent, so it degrades to a
// no-op on a machine without the Node toolchain instead of turning an
// optional check into a broken build.
package smoke

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// browserDiscovery opts the browser harness into the check-in step, which makes
// real outbound IP-discovery calls. Off by default so the harness is useful
// offline and in CI without network egress — the same reason smoke_test.go has
// -skip-discovery, with the polarity inverted so the default needs no flag.
var browserDiscovery = flag.Bool("browser-discovery", false,
	"run the client check-in step, which performs real outbound IP discovery")

// discoveryArg renders the flag as the argv token smoke.mjs checks for.
func discoveryArg() string {
	if *browserDiscovery {
		return "discover"
	}
	return "skip-discovery"
}

func TestBrowserSmoke(t *testing.T) {
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not found; skipping the browser check (see internal/smoke/browser/smoke.mjs)")
	}

	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build the server")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")

	step(t, "build the client")
	clientBin := build(t, repoRoot, binDir, "diyddns-client")

	credsPath := filepath.Join(t.TempDir(), "credentials.json")

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)
	srv := startServer(t, repoRoot, serverBin, addr)

	step(t, "wait for GET /healthz")
	waitHealthy(t, baseURL)

	step(t, "scrape BOOTSTRAP_TOKEN")
	token := scrapeToken(t, srv)

	step(t, "provision playwright into a scratch directory")
	// The script is copied next to a node_modules rather than run in place:
	// ESM resolves a bare "playwright" import by walking up from the
	// IMPORTING FILE's directory, and ignores NODE_PATH — so `npx -p` does
	// not work here even though it looks like it should. Installing into a
	// temp dir also keeps node_modules out of the repo entirely.
	work := t.TempDir()
	if out, err := runIn(work, "npm", "install", "playwright@1.62.1", "--no-audit", "--no-fund"); err != nil {
		t.Skipf("could not provision playwright (offline?): %v\n%s", err, out)
	}

	src := filepath.Join(repoRoot, "internal", "smoke", "browser", "smoke.mjs")
	script, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dst := filepath.Join(work, "smoke.mjs")
	if err := os.WriteFile(dst, script, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}

	step(t, "drive the real pages through Chromium")
	out, err := runIn(work, "node", dst, baseURL, token, clientBin, credsPath, discoveryArg())
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("browser smoke failed: %v", err)
	}
	if !strings.Contains(out, "BROWSER SMOKE OK") {
		t.Fatalf("browser smoke did not report success:\n%s", out)
	}
}

// runIn runs name with args in dir and returns combined output.
func runIn(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
