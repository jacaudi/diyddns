//go:build smoke

package smoke

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

// mtlsState is the part of the client's mtls.json this test reads.
type mtlsState struct {
	CertPEM   string `json:"cert_pem"`
	Committed bool   `json:"committed"`
}

// TestAgentMTLSSmoke proves the agent-mTLS feature end to end with the real
// binaries: first-boot CA generation, provisioning at enroll, probation then
// commit, enforcement of require_mtls on the main port, an admin certificate
// reset recovered in-cycle, and the client-side reset.
//
// It makes no outbound calls: the IP providers are local httptest servers, so
// it runs the same with or without -skip-discovery.
func TestAgentMTLSSmoke(t *testing.T) {
	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build diyddns-server and diyddns-client")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")
	clientBin := build(t, repoRoot, binDir, "diyddns-client")

	addr := freeAddr(t)
	agentAddr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)
	_, agentPort, err := net.SplitHostPort(agentAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", agentAddr, err)
	}

	step(t, "start the server with the agent listener and require_mtls")
	tlsDir := filepath.Join(t.TempDir(), "tls")
	yaml := fmt.Sprintf(`agent:
  listen: %q
  public_url: "https://localhost:%s"
  require_mtls: true
  tls:
    dir: %q
`, agentAddr, agentPort, tlsDir)
	// The server refuses an agent.tls.dir under os.TempDir(), and t.TempDir()
	// lives there. Pointing the server process's TMPDIR somewhere else keeps
	// the guard intact; this is process configuration, not a test seam.
	srv := startServerWithYAML(t, serverBin, addr, yaml, "TMPDIR="+t.TempDir())
	waitHealthy(t, baseURL)

	step(t, "first boot generated the CA, warned about the backup key, wrote 0600 files")
	assertBackupWarning(t, srv.log())
	for _, name := range []string{"ca.key", "ca-backup.key", "agent.crt", "agent.key"} {
		assertMode0600(t, filepath.Join(tlsDir, name))
	}

	step(t, "claim the first admin, sign in, mint an enrollment code")
	token := scrapeToken(t, srv)
	client := &http.Client{Jar: newJar(t), Timeout: 30 * time.Second}
	rp := virtualwebauthn.RelyingParty{Name: "DIYDDNS", ID: rpIDFor(t, addr), Origin: baseURL}
	attOpts := beginClaim(t, client, baseURL, token)
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	finishClaim(t, client, baseURL, virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts))
	passkeyLogin(t, client, baseURL, rp, authr, cred)
	csrf := fetchCSRF(t, client, baseURL)
	code := mintCode(t, client, baseURL, csrf)

	step(t, "start two local IP providers and write the client config")
	const reportedIP = "203.0.113.7"
	provider := func() *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(reportedIP))
		}))
		t.Cleanup(s.Close)
		return s
	}
	p1, p2 := provider(), provider()
	// Quoted: an unquoted http://host:port breaks YAML flow parsing.
	clientYAML := fmt.Sprintf("run:\n  address_families: [ipv4]\n  quorum: 2\n  providers_v4: [%q, %q]\n", p1.URL, p2.URL)
	clientDir := t.TempDir()
	configPath := filepath.Join(clientDir, "client.yaml")
	if err := os.WriteFile(configPath, []byte(clientYAML), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	credsPath := filepath.Join(clientDir, "credentials.json")
	statePath := filepath.Join(clientDir, "mtls.json")
	runOnce := func() string {
		t.Helper()
		return runClient(t, clientBin, "run", "--once", "--credentials-file", credsPath,
			"--config", configPath, "--insecure-provision")
	}

	step(t, "enroll provisions a certificate (probation: committed=false)")
	out := runClient(t, clientBin, "enroll", "--code", code, "--server", baseURL,
		"--credentials-file", credsPath, "--config", configPath, "--insecure-provision")
	if !strings.Contains(out, "enrolled") {
		t.Fatalf("enroll output lacks %q:\n%s", "enrolled", out)
	}
	deviceID := credsField(t, credsPath, "device_id")
	assertMode0600(t, statePath)
	if st := readMTLSState(t, statePath); st.Committed {
		t.Fatalf("mtls.json committed right after enroll, want probation")
	}

	// require_mtls closes the HMAC-only check-in on the main port, so a
	// successful check-in here can only have gone over mTLS.
	step(t, "run --once commits the certificate and checks in over mTLS")
	runOnce()
	if st := readMTLSState(t, statePath); !st.Committed {
		t.Fatalf("mtls.json not committed after the first run")
	}
	assertDeviceCurrent(t, client, baseURL, deviceID, reportedIP)

	step(t, "a second run takes the committed path")
	runOnce()

	step(t, "a signed check-in on the main port is refused with mtls_required")
	secret, err := base64.StdEncoding.DecodeString(credsField(t, credsPath, "secret"))
	if err != nil {
		t.Fatalf("decode device secret: %v", err)
	}
	req := signedAgentRequest(t, baseURL, deviceID, secret, time.Now().Unix(), "smoke-mtls-main")
	status, body := doRequest(t, &http.Client{Timeout: 10 * time.Second}, req)
	if status != http.StatusForbidden || !strings.Contains(body, `"code":"mtls_required"`) {
		t.Fatalf("main-port check-in: status %d body %s, want 403 mtls_required", status, body)
	}

	step(t, "an admin resets the certificate; the next run re-provisions in the same cycle")
	before := readMTLSState(t, statePath)
	clearURL := fmt.Sprintf("%s/admin/devices/%s/cert/clear", baseURL, deviceID)
	if got, want := postFormExpect(t, client, clearURL, csrf, nil, http.StatusOK), "/admin/devices/"+deviceID; got != want {
		t.Fatalf("after cert/clear the final path = %q, want %q", got, want)
	}
	runOnce()
	after := readMTLSState(t, statePath)
	if after.CertPEM == before.CertPEM {
		t.Fatalf("mtls.json still holds the old certificate after the admin reset")
	}
	if !after.Committed {
		t.Fatalf("mtls.json not committed after re-provisioning")
	}

	step(t, "mtls reset deletes the local state")
	runClient(t, clientBin, "mtls", "reset", "--credentials-file", credsPath)
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("mtls.json still present after mtls reset (stat err = %v)", err)
	}

	t.Log("AGENT MTLS SMOKE OK")
}

// assertBackupWarning checks the first-boot log carries the one WARN record
// that tells the operator to move ca-backup.key offline.
func assertBackupWarning(t *testing.T, log string) {
	t.Helper()
	for line := range strings.SplitSeq(log, "\n") {
		if strings.Contains(line, "agent CA generated") && strings.Contains(line, "WARN") &&
			strings.Contains(line, "ca-backup.key") && strings.Contains(line, "offline") {
			return
		}
	}
	t.Fatalf("no WARN record naming ca-backup.key and offline after %q in the server log:\n%s", "agent CA generated", log)
}

func readMTLSState(t *testing.T, path string) mtlsState {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mtls.json: %v", err)
	}
	var st mtlsState
	mustJSON(t, b, &st)
	return st
}

// doRequest sends req and returns the status and body.
func doRequest(t *testing.T, c *http.Client, req *http.Request) (int, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}
