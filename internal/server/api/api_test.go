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
	"github.com/jacaudi/diyddns/internal/version"
)

// buildTestServer assembles the api package onto a mux (no middleware) for
// black-box HTTP assertions. st is nil here; health (Task 4) tolerates the
// nil-free path because these tests do not hit /readyz.
func newAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	api.Build(mux, discardLogger(), nil, version.Info{Version: "v1.2.3"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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

	if !strings.Contains(agentDoc, "openapi") {
		t.Error("agent doc missing openapi field")
	}
	if !strings.Contains(agentDoc, "/agent/v1/capabilities") {
		t.Error("capabilities should be in the AGENT document")
	}
	if strings.Contains(apiDoc, "/agent/v1/capabilities") {
		t.Error("capabilities must NOT be in the API document")
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
