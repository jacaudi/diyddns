package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/enroll"
)

// oidcMockServer answers capabilities + start + (first-poll) success.
func oidcMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/capabilities":
			_, _ = w.Write([]byte(`{"oidc_enabled":true,"oidc_device_enabled":true}`))
		case "/agent/v1/enroll/oidc/start":
			_, _ = w.Write([]byte(`{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`))
		case "/agent/v1/enroll/oidc/poll":
			_, _ = w.Write([]byte(`{"device_id":"dev_42","secret":"c2VjcmV0"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func runEnroll(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCmd()
	root.SetOut(&nopWriter{})
	root.SetErr(&nopWriter{})
	root.SetArgs(args)
	return root.Execute()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestEnrollOIDCEndToEnd(t *testing.T) {
	ts := oidcMockServer(t)
	credPath := filepath.Join(t.TempDir(), "credentials.json")

	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	got, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DeviceID != "dev_42" || got.Secret != "c2VjcmV0" || got.ServerURL != ts.URL {
		t.Errorf("credentials = %+v", got)
	}
}

func TestEnrollTrimsTrailingSlashInServerURL(t *testing.T) {
	ts := oidcMockServer(t)
	credPath := filepath.Join(t.TempDir(), "credentials.json")

	// Pass the server URL WITH a trailing slash; requests must still succeed
	// (the mock's paths are matched against the trimmed base) and the persisted
	// ServerURL must be normalized without the trailing slash.
	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL+"/", "--credentials-file", credPath)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	got, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ServerURL != ts.URL {
		t.Errorf("ServerURL = %q, want trimmed %q", got.ServerURL, ts.URL)
	}
}

func TestEnrollRefusesExistingCredentials(t *testing.T) {
	// The guard must precede any server contact: point --server at a handler
	// that fails the test on ANY request, so "credentials exist" short-circuits
	// before an IdP device authorization could ever be spent.
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be contacted when credentials exist: %s", r.URL.Path)
	}))
	t.Cleanup(ts.Close)
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credPath, []byte(`{"device_id":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err == nil {
		t.Fatal("expected refusal without --force")
	}
	got, _ := credentials.Load(credPath)
	if got.DeviceID != "old" {
		t.Errorf("existing credentials clobbered: %+v", got)
	}
}

func TestEnrollDeviceDisabledCapability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"oidc_enabled":true,"oidc_device_enabled":false}`))
	}))
	t.Cleanup(ts.Close)
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	err := runEnroll(t, "enroll", "--oidc", "--server", ts.URL, "--credentials-file", credPath)
	if err == nil {
		t.Fatal("expected error when oidc_device_enabled=false")
	}
	if _, statErr := os.Stat(credPath); statErr == nil {
		t.Error("credentials written despite capability gate")
	}
}

func TestEnrollRequiresOIDCFlag(t *testing.T) {
	err := runEnroll(t, "enroll", "--server", "https://x")
	if err == nil {
		t.Fatal("expected error without --oidc")
	}
}

func TestFinishEnroll_GuardsBeforeContact(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	// Pre-existing credentials.
	if err := credentials.Save(credPath, credentials.Credentials{
		ServerURL: "https://old", DeviceID: "old", Secret: "old",
	}, false); err != nil {
		t.Fatal(err)
	}

	called := false
	p := enrollParams{out: &nopWriter{}, server: "https://x", credFile: credPath, force: false}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		called = true
		return enroll.Result{}, nil
	})
	if err == nil {
		t.Fatal("want error when credentials already exist and --force is not set")
	}
	if called {
		t.Error("do() was called — guard must refuse BEFORE contacting the server")
	}
}

func TestFinishEnroll_RequiresServer(t *testing.T) {
	dir := t.TempDir()
	p := enrollParams{out: &nopWriter{}, server: "", credFile: filepath.Join(dir, "credentials.json")}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		return enroll.Result{}, nil
	})
	if err == nil {
		t.Fatal("want error when server URL is empty")
	}
}

func TestFinishEnroll_SavesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	p := enrollParams{out: &nopWriter{}, server: "https://srv/", credFile: credPath}
	err := finishEnroll(context.Background(), p, func(context.Context, *enroll.Client) (enroll.Result, error) {
		return enroll.Result{DeviceID: "dev-1", Secret: "c2VjcmV0"}, nil
	})
	if err != nil {
		t.Fatalf("finishEnroll: %v", err)
	}
	got, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DeviceID != "dev-1" || got.Secret != "c2VjcmV0" {
		t.Errorf("saved creds = %+v", got)
	}
	if got.ServerURL != "https://srv" { // trailing slash normalized off
		t.Errorf("ServerURL = %q, want https://srv", got.ServerURL)
	}
}
