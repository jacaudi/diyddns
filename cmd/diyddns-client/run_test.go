package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
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
		if r.URL.Path == "/agent/v1/capabilities" { // unsigned; no agent_mtls, so the device stays on the main port
			_, _ = w.Write([]byte(`{"server_version":"test"}`))
			return
		}
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
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("run --once: %v", err)
	}
	if gotDevice != "dev-xyz" {
		t.Errorf("server saw device %q, want dev-xyz", gotDevice)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestNewClientLogger_InvalidLevelWarns(t *testing.T) {
	var logger *slog.Logger
	out := captureStderr(t, func() {
		logger = newClientLogger(config.LoggingSection{Level: "bogus"})
	})
	if logger == nil {
		t.Fatal("newClientLogger returned nil")
	}
	if !strings.Contains(out, "bogus") {
		t.Errorf("stderr = %q, want it to mention the invalid level %q", out, "bogus")
	}
}

func TestNewClientLogger_EmptyLevelNoWarn(t *testing.T) {
	var logger *slog.Logger
	out := captureStderr(t, func() {
		logger = newClientLogger(config.LoggingSection{})
	})
	if logger == nil {
		t.Fatal("newClientLogger returned nil")
	}
	if out != "" {
		t.Errorf("stderr = %q, want no warning when Level is unset", out)
	}
}

func TestNewClientLogger_ValidLevelNoWarn(t *testing.T) {
	var logger *slog.Logger
	out := captureStderr(t, func() {
		logger = newClientLogger(config.LoggingSection{Level: "debug"})
	})
	if logger == nil {
		t.Fatal("newClientLogger returned nil")
	}
	if out != "" {
		t.Errorf("stderr = %q, want no warning for a valid level", out)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// #102: once the poller gives up on a rejected credential, the operator must
// read the cause AND the remedy from the container log, not a bare
// "unauthorized". Any other error passes through untouched.
func TestExplainRunError_RejectedCredentialNamesTheRemedy(t *testing.T) {
	err := explainRunError(fmt.Errorf("wrapped: %w", checkin.ErrUnauthorized), "https://ddns.example.com")
	if !errors.Is(err, checkin.ErrUnauthorized) {
		t.Fatalf("explained error must still match checkin.ErrUnauthorized, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"rotated", "disabled", "https://ddns.example.com/devices/new", "enroll --server https://ddns.example.com", "--force"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

func TestExplainRunError_MTLSRequired(t *testing.T) {
	in := fmt.Errorf("poller: %w", fmt.Errorf("%w: upgrade this client", checkin.ErrMTLSRequired))
	out := explainRunError(in, "https://ddns.example.com")
	if !errors.Is(out, checkin.ErrMTLSRequired) {
		t.Fatalf("explained error must still match checkin.ErrMTLSRequired, got %v", out)
	}
	msg := out.Error()
	if n := strings.Count(msg, "server requires mTLS"); n != 1 {
		t.Errorf("message %q has %d occurrences of %q, want 1", msg, n, "server requires mTLS")
	}
	for _, want := range []string{"upgrade diyddns-client", "https://ddns.example.com"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

func TestRunFlags_InsecureProvisionBound(t *testing.T) {
	cmd := newRunCmd()
	if err := cmd.Flags().Set("insecure-provision", "true"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRunConfig(cmd, "")
	if err != nil {
		t.Fatalf("loadRunConfig: %v", err)
	}
	if !cfg.Run.InsecureProvision {
		t.Error("InsecureProvision = false with --insecure-provision set, want true")
	}

	cfg, err = loadRunConfig(newRunCmd(), "")
	if err != nil {
		t.Fatalf("loadRunConfig (no flag): %v", err)
	}
	if cfg.Run.InsecureProvision {
		t.Error("InsecureProvision = true without the flag, want false")
	}
}

func TestExplainRunError_OtherErrorsPassThrough(t *testing.T) {
	in := errors.New("dial tcp: connection refused")
	got := explainRunError(in, "https://ddns.example.com")
	if !errors.Is(got, in) || got.Error() != in.Error() {
		t.Errorf("explainRunError(other) = %v, want the same error back, unwrapped and unchanged", got)
	}
	if got := explainRunError(nil, "https://ddns.example.com"); got != nil {
		t.Errorf("explainRunError(nil) = %v, want nil", got)
	}
}

func TestBuildDiscovererNeverSkipsQuorum(t *testing.T) {
	rc := config.ClientRunSection{
		IPDiscovery:     config.IPDiscoveryNever,
		Quorum:          5,
		AddressFamilies: []string{"ipv4"},
		ProvidersV4:     []string{"http://127.0.0.1:1/ip"},
	}
	d, err := buildDiscoverer(rc)
	if err != nil || d != nil {
		t.Fatalf("buildDiscoverer(never) = %v, %v; want nil, nil", d, err)
	}
}

func TestBuildDiscovererAutoValidatesQuorum(t *testing.T) {
	rc := config.ClientRunSection{
		IPDiscovery:     config.IPDiscoveryAuto,
		Quorum:          5,
		AddressFamilies: []string{"ipv4"},
		ProvidersV4:     []string{"http://127.0.0.1:1/ip"},
	}
	if _, err := buildDiscoverer(rc); err == nil {
		t.Fatal("buildDiscoverer(auto, quorum 5, one provider) = nil error, want a quorum error")
	}
}

func TestBuildDiscovererAlwaysBuilds(t *testing.T) {
	rc := config.ClientRunSection{
		IPDiscovery:     config.IPDiscoveryAlways,
		Quorum:          1,
		AddressFamilies: []string{"ipv4"},
		ProvidersV4:     []string{"http://127.0.0.1:1/ip"},
	}
	d, err := buildDiscoverer(rc)
	if err != nil || d == nil {
		t.Fatalf("buildDiscoverer(always) = %v, %v; want a Discoverer", d, err)
	}
}

func TestEnabledFamilies(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []ipdiscovery.Family
		err  bool
	}{
		{name: "order is v4 then v6", in: []string{"ipv6", "ipv4"}, want: []ipdiscovery.Family{ipdiscovery.FamilyV4, ipdiscovery.FamilyV6}},
		{name: "v6 only", in: []string{"ipv6"}, want: []ipdiscovery.Family{ipdiscovery.FamilyV6}},
		{name: "duplicates collapse", in: []string{"ipv4", "ipv4"}, want: []ipdiscovery.Family{ipdiscovery.FamilyV4}},
		{name: "unknown family", in: []string{"ipv5"}, err: true},
		{name: "none enabled", in: nil, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enabledFamilies(config.ClientRunSection{AddressFamilies: tt.in})
			if (err != nil) != tt.err {
				t.Fatalf("enabledFamilies(%v) error = %v, want error %t", tt.in, err, tt.err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("enabledFamilies(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// runOnceMode drives `run --once` in one ip_discovery mode against a fake
// server that advertises observed_ip and a fake lookup provider. It returns
// the ipv4 each check-in body carried, how many times the provider was asked,
// and what the client wrote to stderr.
func runOnceMode(t *testing.T, mode string, providers bool) (sent []string, lookups int, stderr string) {
	t.Helper()
	const lookupAddr = "203.0.113.7"

	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		lookups++
		_, _ = w.Write([]byte(lookupAddr))
	}))
	t.Cleanup(ipSrv.Close)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/v1/capabilities" {
			_, _ = w.Write([]byte(`{"server_version":"test","observed_ip":true}`))
			return
		}
		var body struct {
			IPv4 string `json:"ipv4"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = append(sent, body.IPv4)
		src := "observed"
		if body.IPv4 != "" {
			src = "reported"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": "dev-xyz", "current_ipv4": lookupAddr, "stored": true,
			"ip_source": map[string]string{"ipv4": src},
		})
	}))
	t.Cleanup(apiSrv.Close)

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	writeJSON(t, credPath, map[string]string{
		"server_url": apiSrv.URL, "device_id": "dev-xyz",
		"secret": base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	})
	cfgYAML := fmt.Sprintf("run:\n  ip_discovery: %s\n  address_families: [ipv4]\n", mode)
	if providers {
		cfgYAML += fmt.Sprintf("  quorum: 1\n  providers_v4: [%q]\n", ipSrv.URL)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRunCmd()
	cmd.SetArgs([]string{"--once", "--credentials-file", credPath, "--config", cfgPath})
	stderr = captureStderr(t, func() {
		if err := cmd.ExecuteContext(t.Context()); err != nil {
			t.Errorf("run --once (%s): %v", mode, err)
		}
	})
	return sent, lookups, stderr
}

// never leaves the address to the server: no provider is built or asked (a
// typed-nil Discoverer in the poller would panic here), and the quorum default
// of 2 against no providers is not an error.
func TestRunCmd_Once_NeverSendsNoAddress(t *testing.T) {
	sent, lookups, _ := runOnceMode(t, config.IPDiscoveryNever, false)
	if !slices.Equal(sent, []string{""}) || lookups != 0 {
		t.Errorf("never: bodies ipv4 = %q, lookups = %d; want [\"\"], 0", sent, lookups)
	}
}

// auto reports nothing while the server observes the address.
func TestRunCmd_Once_AutoLetsServerObserve(t *testing.T) {
	sent, lookups, _ := runOnceMode(t, config.IPDiscoveryAuto, true)
	if !slices.Equal(sent, []string{""}) || lookups != 0 {
		t.Errorf("auto: bodies ipv4 = %q, lookups = %d; want [\"\"], 0", sent, lookups)
	}
}

// always is today's behaviour: look up and report, one request.
func TestRunCmd_Once_AlwaysReportsLookup(t *testing.T) {
	sent, lookups, _ := runOnceMode(t, config.IPDiscoveryAlways, true)
	if !slices.Equal(sent, []string{"203.0.113.7"}) || lookups != 1 {
		t.Errorf("always: bodies ipv4 = %q, lookups = %d; want [203.0.113.7], 1", sent, lookups)
	}
}

func TestRunCmd_Once_ProvidersWarning(t *testing.T) {
	for mode, wantWarn := range map[string]bool{
		config.IPDiscoveryAuto:   true,
		config.IPDiscoveryAlways: false,
	} {
		t.Run(mode, func(t *testing.T) {
			_, _, stderr := runOnceMode(t, mode, true)
			if got := strings.Contains(stderr, "run.providers_v4"); got != wantWarn {
				t.Errorf("stderr mentions run.providers_v4 = %t, want %t:\n%s", got, wantWarn, stderr)
			}
		})
	}
}
