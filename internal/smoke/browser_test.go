//go:build browser

// Browser smoke: the only thing in this repo that executes passkey.js.
//
// Separate build tag from `smoke` because it needs Node and a Chromium
// download, which `task smoke` deliberately does not. Neither tag is in the
// default build, so `go build ./...` and `go test ./...` are unaffected and
// the project still builds with the Go toolchain alone.
//
//	task test:e2e:browser
//
// Skips (rather than fails) when node/npx is absent, so it degrades to a
// no-op on a machine without the Node toolchain instead of turning an
// optional check into a broken build. CI passes -browser-required, which
// turns that skip into a failure, so the gate cannot pass without running.
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

// browserRequired makes a missing Node toolchain or a failed Playwright
// download fail the test instead of skipping it. go:ci sets it: a skip there
// would leave a gate that is green without having run (#95).
var browserRequired = flag.Bool("browser-required", false,
	"fail, rather than skip, when the browser toolchain cannot be provisioned")

// discoveryArg renders the flag as the argv token smoke.mjs checks for.
func discoveryArg() string {
	if *browserDiscovery {
		return "discover"
	}
	return "skip-discovery"
}

func TestBrowserSmoke(t *testing.T) {
	// Provisioned first so a machine without Node skips before paying for two
	// Go builds and a server boot.
	step(t, "provision playwright into a scratch directory")
	work, ok := provisionPlaywright(t)
	if !ok {
		return // provisionPlaywright already skipped
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

	script := copyScript(t, repoRoot, work, "smoke.mjs")

	step(t, "drive the real pages through Chromium")
	out, err := runIn(work, "node", script, baseURL, token, clientBin, credsPath, discoveryArg())
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("browser smoke failed: %v", err)
	}
	if !strings.Contains(out, "BROWSER SMOKE OK") {
		t.Fatalf("browser smoke did not report success:\n%s", out)
	}
}

// provisionPlaywright installs playwright into a scratch directory and returns
// it, so a script copied there can resolve a bare "playwright" import: ESM
// resolves it by walking up from the IMPORTING FILE's directory and ignores
// NODE_PATH, so `npx -p` does not work here even though it looks like it
// should. A temp dir also keeps node_modules out of the repo entirely.
//
// It also installs the Chromium build that playwright version expects, which
// is a no-op where it is already cached and the download on a fresh CI runner.
//
// Returns ok=false after skipping the test when the Node toolchain or the
// download is unavailable, so the check degrades to a no-op rather than
// turning an optional harness into a broken build. With -browser-required it
// fails instead.
func provisionPlaywright(t *testing.T) (string, bool) {
	t.Helper()
	unavailable := t.Skipf
	if *browserRequired {
		unavailable = t.Fatalf
	}
	if _, err := exec.LookPath("npx"); err != nil {
		unavailable("npx not found; cannot run the browser check (see internal/smoke/browser/)")
		return "", false
	}
	work := t.TempDir()
	if out, err := runIn(work, "npm", "install", "playwright@1.62.1", "--no-audit", "--no-fund"); err != nil {
		unavailable("could not provision playwright (offline?): %v\n%s", err, out)
		return "", false
	}
	if out, err := runIn(work, "npx", "playwright", "install", "chromium"); err != nil {
		unavailable("could not install chromium for playwright (offline?): %v\n%s", err, out)
		return "", false
	}
	return work, true
}

// copyScript copies internal/smoke/browser/<name> next to work's node_modules
// and returns the destination path. See provisionPlaywright for why in place
// does not work.
func copyScript(t *testing.T, repoRoot, work, name string) string {
	t.Helper()
	src := filepath.Join(repoRoot, "internal", "smoke", "browser", name)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dst := filepath.Join(work, name)
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	return dst
}

// runIn runs name with args in dir and returns combined output.
func runIn(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
