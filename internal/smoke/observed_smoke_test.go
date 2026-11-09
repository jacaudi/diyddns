//go:build smoke

package smoke

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/pires/go-proxyproto"
)

// TestObservedIPSmoke proves server-observed IPs end to end with the real
// binaries, one device per path the server can learn an address from:
//
//   - A: a forwarding proxy the server trusts sets X-Forwarded-For.
//   - B: the mTLS agent port with agent.proxy_protocol, behind a PROXY v2 sender.
//   - C: the server observes nothing public (loopback peer), so the client in
//     auto mode falls back to a lookup against a local service.
//
// Every client runs address_families: [ipv4] and every lookup service is
// local, so it makes no outbound calls and runs the same with or without
// -skip-discovery.
func TestObservedIPSmoke(t *testing.T) {
	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build diyddns-server and diyddns-client")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")
	clientBin := build(t, repoRoot, binDir, "diyddns-client")

	// The agent port comes first: the forwarder's address is the server's
	// agent.public_url, so it must exist before the server starts.
	addr := freeAddr(t)
	agentAddr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)
	fwdPort := startProxyV2Forwarder(t, agentAddr, "9.9.9.9:1234")

	step(t, "start the server: trusted_proxies, agent proxy_protocol, agent public_url on the forwarder")
	yaml := fmt.Sprintf(`server:
  trusted_proxies: [127.0.0.1/32]
agent:
  listen: %q
  proxy_protocol: true
  public_url: "https://localhost:%s"
  tls:
    dir: %q
`, agentAddr, fwdPort, filepath.Join(t.TempDir(), "tls"))
	srv := startServerWithYAML(t, serverBin, addr, yaml)
	waitHealthy(t, baseURL)

	step(t, "claim the first admin and sign in")
	token := scrapeToken(t, srv)
	admin := &http.Client{Jar: newJar(t), Timeout: 30 * time.Second}
	rp := virtualwebauthn.RelyingParty{Name: "DIYDDNS", ID: rpIDFor(t, addr), Origin: baseURL}
	attOpts := beginClaim(t, admin, baseURL, token)
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	finishClaim(t, admin, baseURL, virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts))
	passkeyLogin(t, admin, baseURL, rp, authr, cred)
	csrf := fetchCSRF(t, admin, baseURL)

	const autoV4 = "run:\n  ip_discovery: auto\n  address_families: [ipv4]\n"

	step(t, "device A: a trusted proxy's X-Forwarded-For is the observed address")
	proxyURL := startForwardingProxy(t, baseURL, "1.1.1.1")
	a := newSmokeDevice(t, clientBin, autoV4)
	a.enroll(t, mintLabeledCode(t, admin, baseURL, csrf, "device-a"), proxyURL)
	// The proxy URL is http://, so provisioning is refused (no
	// --insecure-provision) and the check-in stays on the main port.
	out := a.runOnce(t)
	assertDeviceCurrent(t, admin, baseURL, a.deviceID(t), "1.1.1.1")
	if !strings.Contains(out, "ipv4_source=observed") {
		t.Fatalf("client log lacks ipv4_source=observed:\n%s", out)
	}

	step(t, "device B: the agent port takes its address from the PROXY v2 header")
	b := newSmokeDevice(t, clientBin, autoV4)
	b.enroll(t, mintLabeledCode(t, admin, baseURL, csrf, "device-b"), baseURL, "--insecure-provision")
	b.runOnce(t, "--insecure-provision") // probation: provisioning check-in
	b.runOnce(t, "--insecure-provision") // commit
	assertDeviceCurrent(t, admin, baseURL, b.deviceID(t), "9.9.9.9")

	step(t, "device C: nothing public observed, so auto mode looks the address up")
	const lookedUp = "8.8.4.4"
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(lookedUp))
	}))
	t.Cleanup(lookup.Close)
	// Quoted: an unquoted http://host:port breaks YAML flow parsing.
	c := newSmokeDevice(t, clientBin, fmt.Sprintf(
		"%s  quorum: 1\n  providers_v4: [%q]\n", autoV4, lookup.URL))
	c.enroll(t, mintLabeledCode(t, admin, baseURL, csrf, "device-c"), baseURL)
	clientLog := c.runDaemon(t, "--interval", "2s")
	waitCurrentIPv4(t, admin, baseURL, c.deviceID(t), lookedUp)
	assertDeviceCurrent(t, admin, baseURL, c.deviceID(t), lookedUp)
	const fallback = "server did not observe a public address; looking it up for this family"
	if !strings.Contains(clientLog.log(), fallback) {
		t.Fatalf("client log lacks %q:\n%s", fallback, clientLog.log())
	}

	t.Log("OBSERVED IP SMOKE OK")
}

// smokeDevice is one client install: its own credentials file and config.
type smokeDevice struct {
	bin, creds, config string
}

func newSmokeDevice(t *testing.T, bin, configYAML string) *smokeDevice {
	t.Helper()
	dir := t.TempDir()
	d := &smokeDevice{bin: bin, creds: filepath.Join(dir, "credentials.json"), config: filepath.Join(dir, "client.yaml")}
	if err := os.WriteFile(d.config, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	return d
}

func (d *smokeDevice) enroll(t *testing.T, code, serverURL string, extra ...string) {
	t.Helper()
	args := append([]string{"enroll", "--code", code, "--server", serverURL,
		"--credentials-file", d.creds, "--config", d.config}, extra...)
	runClient(t, d.bin, args...)
}

func (d *smokeDevice) runOnce(t *testing.T, extra ...string) string {
	t.Helper()
	args := append([]string{"run", "--once", "--credentials-file", d.creds, "--config", d.config}, extra...)
	return runClient(t, d.bin, args...)
}

func (d *smokeDevice) deviceID(t *testing.T) string {
	t.Helper()
	return credsField(t, d.creds, "device_id")
}

// runDaemon starts `run` in the background and returns its captured log. The
// process dies with the test: t.Context is cancelled before cleanups run.
func (d *smokeDevice) runDaemon(t *testing.T, extra ...string) *server {
	t.Helper()
	args := append([]string{"run", "--credentials-file", d.creds, "--config", d.config}, extra...)
	cmd := exec.CommandContext(t.Context(), d.bin, args...)
	// server is only the mutex-guarded log buffer here; its cmd field stays nil.
	logBuf := &server{}
	cmd.Stdout = logBuf
	cmd.Stderr = logBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("--- client log ---\n%s", logBuf.log())
		}
	})
	return logBuf
}

// startForwardingProxy runs an in-process reverse proxy to target that sets
// X-Forwarded-For to xff, the way a real proxy in front of the server would.
// Both sit on loopback, so the server's trusted_proxies covers the proxy.
func startForwardingProxy(t *testing.T, target, xff string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse proxy target %q: %v", target, err)
	}
	p := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.Out.Header.Set("X-Forwarded-For", xff)
	}}
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return s.URL
}

// startProxyV2Forwarder listens on loopback and relays each connection to
// agentAddr after writing a PROXY v2 header naming src as the client, the way
// a TCP load balancer does. It returns the forwarder's port.
func startProxyV2Forwarder(t *testing.T, agentAddr, src string) string {
	t.Helper()
	srcAddr, err := net.ResolveTCPAddr("tcp", src)
	if err != nil {
		t.Fatalf("resolve %q: %v", src, err)
	}
	dstAddr, err := net.ResolveTCPAddr("tcp", agentAddr)
	if err != nil {
		t.Fatalf("resolve %q: %v", agentAddr, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen forwarder: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go relayProxyV2(conn, agentAddr, proxyproto.HeaderProxyFromAddrs(2, srcAddr, dstAddr))
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr(), err)
	}
	return port
}

// relayProxyV2 sends hdr to the agent, then pipes bytes both ways until either
// side closes. Errors only end this one connection.
func relayProxyV2(client net.Conn, agentAddr string, hdr *proxyproto.Header) {
	defer func() { _ = client.Close() }()
	agent, err := net.Dial("tcp", agentAddr)
	if err != nil {
		return
	}
	defer func() { _ = agent.Close() }()
	if _, err := hdr.WriteTo(agent); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(agent, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, agent); done <- struct{}{} }()
	<-done
}

// waitCurrentIPv4 polls until the device's current_ipv4 is want, for the
// background client that has no "finished" moment to wait on.
func waitCurrentIPv4(t *testing.T, c *http.Client, baseURL, deviceID, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		status, body := get(t, c, baseURL+"/api/v1/devices/"+deviceID)
		if status != http.StatusOK {
			t.Fatalf("device: status = %d, body = %s", status, body)
		}
		var out struct {
			CurrentIPv4 string `json:"current_ipv4"`
		}
		mustJSON(t, body, &out)
		if got = out.CurrentIPv4; got == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("current_ipv4 = %q after 30s, want %q", got, want)
}
