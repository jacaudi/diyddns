package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// newAPIServer assembles the api package onto a mux (no middleware) for
// black-box HTTP assertions, backed by a real in-memory store so a future
// test routing /readyz through it (RegisterHealth calls st.DB()) does not
// nil-panic. ServerDeps carries only Store/Log/Info here — Verifier and the
// service layer are wired in Task 15; the register* op functions are empty
// stubs until Tasks 12-14 land, so no operation depends on them yet.
func newAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		Log:   discardLogger(),
		Store: memStore(t),
		Info:  version.Info{Version: "v1.2.3"},
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestCapabilities_Response(t *testing.T) {
	srv := newAPIServer(t)
	resp, err := http.Get(srv.URL + "/agent/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got api.Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ServerVersion != "v1.2.3" {
		t.Errorf("ServerVersion = %q", got.ServerVersion)
	}
	if got.SkewWindowSeconds != 120 {
		t.Errorf("SkewWindowSeconds = %d, want 120", got.SkewWindowSeconds)
	}
	if len(got.AddressFamilies) != 2 {
		t.Errorf("AddressFamilies = %v", got.AddressFamilies)
	}
	if got.OIDCEnabled {
		t.Error("OIDCEnabled should be false in the skeleton")
	}
}

func TestOpenAPIDocs_TwoSeparateDocuments(t *testing.T) {
	srv := newAPIServer(t)
	agentDoc := getBody(t, srv.URL+"/agent/openapi.json")
	apiDoc := getBody(t, srv.URL+"/api/openapi.json")

	// Structural check: both documents decode as JSON objects with the
	// required OpenAPI 3.1 top-level fields, using only encoding/json (no new
	// dependency). A full schema-validated OpenAPI 3.1 parse would need
	// either a third-party validator library (no present consumer to justify
	// the dependency) or unmarshaling into huma's internal *huma.OpenAPI
	// struct, which has no json tags/UnmarshalJSON and would silently rely on
	// Go's case-insensitive field-name fallback — not a real validated parse.
	// Deferred to Task 15 if still wanted then.
	assertOpenAPIShape(t, "agent", agentDoc)
	assertOpenAPIShape(t, "api", apiDoc)

	if !strings.Contains(agentDoc, "/agent/v1/capabilities") {
		t.Error("capabilities should be in the AGENT document")
	}
	if strings.Contains(apiDoc, "/agent/v1/capabilities") {
		t.Error("capabilities must NOT be in the API document")
	}
}

// assertOpenAPIShape checks the two REQUIRED OpenAPI 3.1 top-level fields
// (openapi, info). "paths" is intentionally not asserted here: it is OPTIONAL
// per the OpenAPI 3.1 spec and huma omits it entirely when a group has no
// registered operations — true today for the /api group (Tasks 13-14 add its
// first operations). Path presence is verified separately below via the
// existing capabilities substring checks.
func assertOpenAPIShape(t *testing.T, label, doc string) {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("%s doc: not valid JSON: %v", label, err)
	}
	ver, ok := parsed["openapi"].(string)
	if !ok || !strings.HasPrefix(ver, "3.1") {
		t.Errorf("%s doc: openapi field = %v, want a 3.1.x string", label, parsed["openapi"])
	}
	if _, ok := parsed["info"].(map[string]any); !ok {
		t.Errorf("%s doc: info field missing or not an object", label)
	}
}

func TestScalarDocs_BothGroups(t *testing.T) {
	srv := newAPIServer(t)
	for _, path := range []string{"/agent/docs", "/api/docs"} {
		body := getBody(t, srv.URL+path)
		if !strings.Contains(strings.ToLower(body), "scalar") {
			t.Errorf("%s did not render Scalar docs", path)
		}
	}
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
