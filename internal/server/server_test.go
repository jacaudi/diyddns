package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/store"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestServer_AllEndpoints(t *testing.T) {
	srv := httptest.NewServer(server.Handler(discard(), memStore(t)))
	t.Cleanup(srv.Close)

	cases := []struct {
		path       string
		wantStatus int
		contains   string
	}{
		{"/healthz", 200, "ok"},
		{"/readyz", 200, "ready"},
		{"/agent/v1/capabilities", 200, "server_version"},
		{"/agent/openapi.json", 200, "openapi"},
		{"/api/openapi.json", 200, "openapi"},
		{"/agent/docs", 200, "scalar"},
		{"/api/docs", 200, "scalar"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + c.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.wantStatus)
			}
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(strings.ToLower(string(b)), c.contains) {
				t.Errorf("body missing %q", c.contains)
			}
			if resp.Header.Get("X-Request-Id") == "" {
				t.Error("missing X-Request-Id (middleware chain not applied)")
			}
		})
	}
}

func TestServer_RunShutsDownOnCancel(t *testing.T) {
	s := server.New(config.Server{Server: config.ServerSection{Listen: "127.0.0.1:0"}}, memStore(t), discard())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down within 5s")
	}
}
