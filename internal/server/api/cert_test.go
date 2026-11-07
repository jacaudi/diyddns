package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
)

const testAgentURL = "https://ddns.example.com:8443"

// withAgentMTLS returns a newAgentHarnessWith mutator that turns the agent
// listener's API surface on: a real CA (written to *ca) over the harness's
// :memory: store, a CertService on it, and the agent URL. requireMTLS sets
// agent.require_mtls.
func withAgentMTLS(t *testing.T, requireMTLS bool, ca **agenttls.CA) func(*api.ServerDeps) {
	t.Helper()
	return func(deps *api.ServerDeps) {
		c, err := agenttls.LoadOrInit(t.Context(), deps.Store, t.TempDir(), time.Now(), slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("agenttls.LoadOrInit: %v", err)
		}
		*ca = c
		deps.Cert = service.NewCertService(deps.Store, c, testAgentURL, service.NewAuditWriter(deps.Store))
		deps.AgentURL = testAgentURL
		deps.RequireMTLS = requireMTLS
	}
}

// testCSR returns a PEM CSR over a fresh ECDSA P-256 key.
func testCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// nonceSeq makes each signed request in a test carry a distinct nonce.
var nonceSeq int

// doSigned sends an HMAC-signed request and returns status and body. body (nil
// for none) is marshaled to JSON.
func doSigned(t *testing.T, h agentHarness, method, path, deviceID string, secret []byte, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	nonceSeq++
	req := signedRequest(t, method, h.srv.URL, path, deviceID, secret, raw, "cert-nonce-"+strconv.Itoa(nonceSeq))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, out
}

// problemCode extracts the stable `code` field from a problem JSON body.
func problemCode(t *testing.T, body []byte) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	decodeJSON(t, body, &p)
	return p.Code
}

func TestCert_MainIssuesOnce(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, false, &ca))
	id, secret := enrollViaHTTP(t, h, "cert-once@example.com", "laptop")

	status, body := doSigned(t, h, http.MethodPost, "/agent/v1/cert", id, secret, map[string]string{"csr": testCSR(t)})
	if status != http.StatusOK {
		t.Fatalf("first status = %d, want 200, body=%s", status, body)
	}
	var keys map[string]string
	decodeJSON(t, body, &keys)
	for _, k := range []string{"certificate", "ca_bundle", "agent_url"} {
		if keys[k] == "" {
			t.Errorf("response key %q empty or missing: %s", k, body)
		}
	}
	if keys["agent_url"] != testAgentURL {
		t.Errorf("agent_url = %q, want %q", keys["agent_url"], testAgentURL)
	}

	status, body = doSigned(t, h, http.MethodPost, "/agent/v1/cert", id, secret, map[string]string{"csr": testCSR(t)})
	if status != http.StatusConflict {
		t.Fatalf("second status = %d, want 409, body=%s", status, body)
	}
	if got := problemCode(t, body); got != shared.CodeCertAlreadyIssued {
		t.Errorf("code = %q, want %q", got, shared.CodeCertAlreadyIssued)
	}
}

func TestCert_BadCSRIs400(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, false, &ca))
	id, secret := enrollViaHTTP(t, h, "cert-bad@example.com", "laptop")

	status, body := doSigned(t, h, http.MethodPost, "/agent/v1/cert", id, secret, map[string]string{"csr": "nope"})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", status, body)
	}
}

func TestCert_UnsignedIs401(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, false, &ca))

	status, body := postJSON(t, h.srv.URL+"/agent/v1/cert", map[string]string{"csr": testCSR(t)})
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestCert_DisabledIs404(t *testing.T) {
	h := newAgentHarness(t)

	status, body := postJSON(t, h.srv.URL+"/agent/v1/cert", map[string]string{"csr": testCSR(t)})
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", status, body)
	}
}

func TestRequireMTLS_MainCheckinAndSelf403(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, true, &ca))
	id, secret := enrollViaHTTP(t, h, "require@example.com", "laptop")

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/agent/v1/checkin"},
		{http.MethodGet, "/agent/v1/self"},
	} {
		var body any
		if tc.method == http.MethodPost {
			body = map[string]string{"ipv4": "1.2.3.4"}
		}
		status, out := doSigned(t, h, tc.method, tc.path, id, secret, body)
		if status != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403, body=%s", tc.method, tc.path, status, out)
			continue
		}
		if got := problemCode(t, out); got != shared.CodeMTLSRequired {
			t.Errorf("%s %s code = %q, want %q", tc.method, tc.path, got, shared.CodeMTLSRequired)
		}
	}

	resp, err := http.Get(h.srv.URL + "/agent/v1/capabilities")
	if err != nil {
		t.Fatalf("get capabilities: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("capabilities status = %d, want 200", resp.StatusCode)
	}

	status, out := postJSON(t, h.srv.URL+"/agent/v1/enroll/code", map[string]string{"code": "never-issued"})
	if status == http.StatusForbidden {
		t.Errorf("enroll/code status = 403, want it left open, body=%s", out)
	}

	status, out = doSigned(t, h, http.MethodPost, "/agent/v1/cert", id, secret, map[string]string{"csr": testCSR(t)})
	if status != http.StatusOK {
		t.Errorf("cert status = %d, want 200, body=%s", status, out)
	}
}

func TestRequireMTLS_OffUnchanged(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, false, &ca))
	id, secret := enrollViaHTTP(t, h, "norequire@example.com", "laptop")

	status, out := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, map[string]string{"ipv4": "1.2.3.4"})
	if status != http.StatusOK {
		t.Fatalf("checkin status = %d, want 200, body=%s", status, out)
	}
}
