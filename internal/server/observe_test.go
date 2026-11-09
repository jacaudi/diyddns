package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
)

// The observation middleware must hand the request on without r.WithContext or
// r.Clone: AccessLog reads r.Pattern off the request it passed down, and the mux
// annotates a copy otherwise, leaving route silently empty. With
// server.trusted_proxies set, the check-in route runs the observation
// middleware first (it is prepended to the HMAC chain, so an unsigned request
// reaches it before the 401), and its access-log record must still carry the
// route.
func TestMainCheckinAccessLogKeepsRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.json")
	log, err := server.NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: path})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg := testConfig(t, validSecretKey())
	cfg.Server.TrustedProxies = []string{"127.0.0.1"}
	h, _, err := server.Handler(cfg, memStore(t), log, server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/agent/v1/checkin", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST checkin: %v", err)
	}
	_ = resp.Body.Close()

	// AccessLog writes after the handler returns, which can be after the client
	// has the response, so poll for the record.
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read log: %v", err)
		}
		for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "request" {
				continue
			}
			if rec["route"] != "POST /agent/v1/checkin" {
				t.Errorf("route = %v, want %q", rec["route"], "POST /agent/v1/checkin")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access-log record after 10s:\n%s", raw)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
