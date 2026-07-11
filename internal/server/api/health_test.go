package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/store"
)

func openMemStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestHealthz_OK(t *testing.T) {
	mux := http.NewServeMux()
	api.RegisterHealth(mux, discardLogger(), openMemStore(t))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if body := getBody(t, srv.URL+"/healthz"); body != "ok" {
		t.Errorf("/healthz body = %q, want ok", body)
	}
}

func TestReadyz_ReadyThen503AfterClose(t *testing.T) {
	st := openMemStore(t)
	mux := http.NewServeMux()
	api.RegisterHealth(mux, discardLogger(), st)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if body := getBody(t, srv.URL+"/readyz"); body != "ready" {
		t.Errorf("/readyz body = %q, want ready", body)
	}

	_ = st.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/readyz after close = %d, want 503", resp.StatusCode)
	}
}
