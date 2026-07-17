package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/shared"
)

// A full round-trip: --once against a fake server that verifies the HMAC and
// returns a check-in response. The fake providers are supplied via config
// pointing at httptest endpoints, so no real network is used.
func TestRunCmd_Once_EndToEnd(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	// Fake IP provider (returns a v4 address as plain text).
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7"))
	}))
	defer ipSrv.Close()

	// Fake diyddns server: verify signature, return checkin response.
	var gotDevice string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDevice = r.Header.Get(shared.HeaderDevice)
		body, _ := io.ReadAll(r.Body)
		// Reconstruct and verify the client's signature exactly as the real
		// server would, proving run's signing path is wired end-to-end.
		canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
			r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
		if got, want := r.Header.Get(shared.HeaderSignature), shared.Sign(key, canonical); got != want {
			t.Errorf("signature mismatch: got %s want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": gotDevice, "current_ipv4": "203.0.113.7", "current_ipv6": "", "stored": true,
		})
	}))
	defer apiSrv.Close()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	writeJSON(t, credPath, map[string]string{
		"server_url": apiSrv.URL, "device_id": "dev-xyz",
		"secret": base64.StdEncoding.EncodeToString(key),
	})
	cfgPath := filepath.Join(dir, "config.yaml")
	// quorum 1 so a single provider suffices; only ipv4 enabled, pointing at the
	// fake. Quote the URL — an unquoted http://host:port breaks YAML flow parsing.
	cfgYAML := fmt.Sprintf("run:\n  quorum: 1\n  address_families: [ipv4]\n  providers_v4: [%q]\n", ipSrv.URL)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRunCmd()
	cmd.SetArgs([]string{"--once", "--credentials-file", credPath, "--config", cfgPath})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("run --once: %v", err)
	}
	if gotDevice != "dev-xyz" {
		t.Errorf("server saw device %q, want dev-xyz", gotDevice)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
