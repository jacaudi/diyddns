package enroll

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	c, err := NewClient(ts.URL, ClientOptions{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "notaurl"} {
		if _, err := NewClient(u, ClientOptions{}); err == nil {
			t.Errorf("NewClient(%q) err = nil, want error", u)
		}
	}
}

func TestDeviceStartStatusMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   error // nil = success
	}{
		{"ok", 200, `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`, nil},
		{"unsupported", 501, `{}`, ErrDeviceUnsupported},
		{"badgateway", 502, `{}`, ErrBadGateway},
		{"server", 500, `{}`, ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			ds, err := c.OIDCDeviceStart(context.Background())
			if tt.want == nil {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if ds.FlowID != "f" || ds.UserCode != "UC" || ds.ExpiresIn != 300 {
					t.Errorf("bad decode: %+v", ds)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDevicePollStatusMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  error
		wantKind pollKind
	}{
		{"pending", 200, `{"status":"pending"}`, nil, pollPending},
		{"slow_down", 200, `{"status":"slow_down"}`, nil, pollSlowDown},
		{"complete", 200, `{"device_id":"dev","secret":"c2VjcmV0"}`, nil, pollComplete},
		{"empty200", 200, `{}`, ErrProtocol, 0},
		{"bad_secret", 200, `{"device_id":"dev","secret":"!!notb64"}`, ErrProtocol, 0},
		{"malformed_json", 200, `{bad json`, ErrProtocol, 0},
		{"gone", 410, `{}`, ErrFlowGone, 0},
		{"rejected", 401, `{}`, ErrRejected, 0},
		{"idp", 502, `{}`, ErrBadGateway, 0},
		{"server", 500, `{}`, ErrServer, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/agent/v1/enroll/oidc/poll" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			res, err := c.OIDCDevicePoll(context.Background(), "flow123")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if res.Kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", res.Kind, tt.wantKind)
			}
			if tt.wantKind == pollComplete && (res.DeviceID != "dev" || res.Secret != "c2VjcmV0") {
				t.Errorf("complete payload wrong: %+v", res)
			}
		})
	}
}

func TestCapabilitiesDecode(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"server_version":"1.0","oidc_enabled":true,"oidc_device_enabled":true}`))
	})
	caps, err := c.Capabilities(context.Background())
	if err != nil || !caps.OIDCDeviceEnabled {
		t.Fatalf("caps = %+v err = %v", caps, err)
	}
}

func TestNewClientCACertTrustsTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"oidc_device_enabled":true}`))
	}))
	t.Cleanup(ts.Close)

	// Without the CA, the self-signed cert is rejected.
	plain, _ := NewClient(ts.URL, ClientOptions{})
	if _, err := plain.Capabilities(context.Background()); err == nil {
		t.Fatal("expected TLS verification failure without CA")
	}

	// Write the server's cert to a PEM file and trust it via --ca-cert.
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	trusting, err := NewClient(ts.URL, ClientOptions{CACertPath: caPath})
	if err != nil {
		t.Fatalf("NewClient(ca): %v", err)
	}
	if _, err := trusting.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities with CA: %v", err)
	}
}
