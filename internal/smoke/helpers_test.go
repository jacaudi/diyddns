//go:build smoke

package smoke

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// step prints a progress line, matching the shape the shell harness used so
// a failing run reads the same way.
func step(t *testing.T, msg string) {
	t.Helper()
	t.Logf("==> %s", msg)
}

// repoRoot walks up from the package directory until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repoRoot: no go.mod found above the package directory")
		}
		dir = parent
	}
}

func build(t *testing.T, repoRoot, outDir, cmdName string) string {
	t.Helper()
	out := filepath.Join(outDir, cmdName)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/"+cmdName)
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", cmdName, err, b)
	}
	return out
}

// freeAddr asks the kernel for an unused loopback port and returns it as
// host:port. Loopback is not incidental: WebAuthn requires a secure context,
// and 127.0.0.1 is the only one available without TLS.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

func host(t *testing.T, addr string) string {
	t.Helper()
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return h
}

// server wraps the running subprocess and its captured log.
type server struct {
	cmd *exec.Cmd
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *server) log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *server) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// startServer runs the real binary against the shipped config.example.yaml
// with DIYDDNS_* overrides, so every smoke run also proves the committed
// example still boots. Teardown is registered with t.Cleanup, so a failure
// anywhere still stops the process.
func startServer(t *testing.T, repoRoot, bin, addr string) *server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "smoke.db")
	baseURL := "http://" + addr

	s := &server{}
	cmd := exec.Command(bin, "serve", "--config", filepath.Join(repoRoot, "config.example.yaml"))
	cmd.Env = append(os.Environ(),
		"DIYDDNS_SERVER_LISTEN="+addr,
		"DIYDDNS_SERVER_BASE_URL="+baseURL,
		"DIYDDNS_DATABASE_PATH="+dbPath,
		"DIYDDNS_AUTH_HMAC_SECRET_KEY="+randomKeyB64(t),
	)
	cmd.Stdout = s
	cmd.Stderr = s
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	s.cmd = cmd

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			t.Logf("--- server log ---\n%s", s.log())
		}
	})
	return s
}

// waitHealthy polls until /healthz answers, rather than sleeping a fixed
// amount. It gives up if the process dies first, so a boot failure surfaces
// as a boot failure instead of a timeout.
func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "ok" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server did not become healthy within 30s")
}

// bootstrapTokenRe matches the greppable prefix. The token is base64url
// (auth.RandToken uses RawURLEncoding): no padding, and `-`/`_` rather than
// `+`/`/`. A pattern written for standard base64 would truncate it.
var bootstrapTokenRe = regexp.MustCompile(`BOOTSTRAP_TOKEN=([A-Za-z0-9_-]+)`)

func scrapeToken(t *testing.T, s *server) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := bootstrapTokenRe.FindStringSubmatch(s.log()); m != nil {
			return m[1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no BOOTSTRAP_TOKEN in server log:\n%s", s.log())
	return ""
}

// randomKeyB64 mints the AES-256 master key the server seals device secrets
// with. It is standard base64 (not base64url) because that is what the
// config loader decodes.
func randomKeyB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func runClient(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credentials: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("credentials mode = %o, want 600", perm)
	}
}

func credsField(t *testing.T, path, key string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	var m map[string]string
	mustJSON(t, b, &m)
	v := m[key]
	if v == "" {
		t.Fatalf("credentials has no %q: %s", key, b)
	}
	return v
}

func field(t *testing.T, s, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("no match for %q in:\n%s", pattern, s)
	}
	return m[1]
}

// --- HTTP -----------------------------------------------------------------

func postJSON(t *testing.T, c *http.Client, url string, body any, csrf string) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	return postRaw(t, c, url, string(raw), csrf)
}

func postRaw(t *testing.T, c *http.Client, url, body, csrf string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, out
}

func get(t *testing.T, c *http.Client, url string) (int, []byte) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, out
}

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal %T: %v (body=%s)", v, err, b)
	}
}

// mergeField splits obj's JSON so an extra top-level key can be added
// without re-marshalling the ceremony response, whose exact byte content the
// server re-verifies.
func mergeField(t *testing.T, obj, key, val string) string {
	t.Helper()
	trimmed := strings.TrimSpace(obj)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Fatalf("mergeField: not a JSON object: %s", obj)
	}
	kv, err := json.Marshal(map[string]string{key: val})
	if err != nil {
		t.Fatalf("marshal %s: %v", key, err)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(string(kv), "{"), "}")
	return fmt.Sprintf("%s,%s}", strings.TrimSuffix(trimmed, "}"), inner)
}
