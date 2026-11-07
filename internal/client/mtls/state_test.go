package mtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testCA is a throwaway P-256 CA that can issue server and device leaves.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue signs a leaf for a fresh key and returns the cert and key PEMs.
func (ca testCA) issue(t *testing.T, tmpl *x509.Certificate) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// newTestState returns a valid State for deviceID with a device cert from a
// fresh CA.
func newTestState(t *testing.T, deviceID string) State {
	t.Helper()
	ca := newTestCA(t, "test CA")
	certPEM, keyPEM := ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: deviceID},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return State{
		DeviceID:    deviceID,
		KeyPEM:      keyPEM,
		CertPEM:     certPEM,
		CABundlePEM: ca.pem,
		AgentURL:    "https://ddns.example.com:8443",
		Committed:   true,
	}
}

// newLogger returns a text logger writing into the returned buffer.
func newLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", path, err)
	}
	return false
}

func TestPathFor(t *testing.T) {
	got := PathFor(filepath.Join("etc", "diyddns", "credentials.json"))
	want := filepath.Join("etc", "diyddns", "mtls.json")
	if got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	want := newTestState(t, "dev-a")
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	log, _ := newLogger()
	got, err := Load(path, "dev-a", log)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("round trip: got %+v, want %+v", got, want)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != FileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %v, want only %s", names, FileName)
	}
}

func TestSave_ReplacesExistingAndTightensMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(`{"device_id":"old"}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	want := newTestState(t, "dev-a")
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	log, _ := newLogger()
	got, err := Load(path, "dev-a", log)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("Load after replace: got %+v, want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
	}
}

func TestSave_FailureLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	// A directory squatting on the target name makes the final rename fail
	// after the temp file was written.
	path := filepath.Join(dir, FileName)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := Save(path, newTestState(t, "dev-a")); err == nil {
		t.Fatal("Save onto a non-empty directory: want error")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("dir holds %d entries after failed Save, want 1 (the squatter)", len(entries))
	}
}

func TestLoad_MissingIsNotFound(t *testing.T) {
	log, buf := newLogger()
	_, err := Load(filepath.Join(t.TempDir(), FileName), "dev-a", log)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load missing: err = %v, want ErrNotFound", err)
	}
	if buf.Len() != 0 {
		t.Errorf("absent file logged %q, want silence", buf.String())
	}
}

func TestLoad_DeviceMismatchDeletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	st := newTestState(t, "dev-a")
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	log, buf := newLogger()
	_, err := Load(path, "dev-b", log)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load other device: err = %v, want ErrNotFound", err)
	}
	if fileExists(t, path) {
		t.Errorf("mismatched mtls.json was not deleted")
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("no WARN logged: %q", buf.String())
	}
	if strings.Contains(buf.String(), "PRIVATE KEY") {
		t.Errorf("log leaked key material: %q", buf.String())
	}
}

func TestLoad_CorruptFileIsDeleted(t *testing.T) {
	good := newTestState(t, "dev-a")
	badCert := good
	badCert.CertPEM = "not a certificate"

	tests := []struct {
		name string
		body func(t *testing.T) []byte
	}{
		{"truncated JSON", func(*testing.T) []byte { return []byte(`{"device_id":`) }},
		{"empty file", func(*testing.T) []byte { return nil }},
		{"cert does not parse", func(t *testing.T) []byte {
			p := filepath.Join(t.TempDir(), FileName)
			if err := Save(p, badCert); err != nil {
				t.Fatalf("Save: %v", err)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			return b
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, tt.body(t), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			log, buf := newLogger()
			_, err := Load(path, "dev-a", log)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("Load corrupt: err = %v, want ErrNotFound", err)
			}
			if fileExists(t, path) {
				t.Errorf("corrupt mtls.json was not deleted")
			}
			if !strings.Contains(buf.String(), "level=WARN") {
				t.Errorf("no WARN logged: %q", buf.String())
			}
		})
	}
}

func TestLoad_UnreadableIsError(t *testing.T) {
	// A directory at the path is neither absent nor corrupt: surface it, do
	// not delete it.
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	log, _ := newLogger()
	_, err := Load(path, "dev-a", log)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Load on a directory: err = %v, want a non-ErrNotFound error", err)
	}
	if !fileExists(t, path) {
		t.Errorf("unreadable path was removed")
	}
}

func TestRemove_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Remove(path); err != nil {
		t.Errorf("Remove of absent file: %v", err)
	}
	if err := Save(path, newTestState(t, "dev-a")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := Remove(path); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if fileExists(t, path) {
		t.Errorf("file still present after Remove")
	}
	if err := Remove(path); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func TestLeaf(t *testing.T) {
	st := newTestState(t, "dev-a")
	leaf, err := st.Leaf()
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if got := leaf.Subject.CommonName; got != "dev-a" {
		t.Errorf("leaf CN = %q, want dev-a", got)
	}
	st.CertPEM = ""
	if _, err := st.Leaf(); err == nil {
		t.Errorf("Leaf of empty cert PEM: want error")
	}
}

// serve starts a TLS 1.3 server presenting a cert for 127.0.0.1 issued by ca
// and requiring a client cert chaining to clientCA. The handler echoes the
// peer cert CN.
func serve(t *testing.T, ca testCA, clientCA testCA) *httptest.Server {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("server key pair: %v", err)
	}
	clients := x509.NewCertPool()
	clients.AddCert(clientCA.cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, cfg *tls.Config, url string) (string, error) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	t.Cleanup(c.CloseIdleConnections)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b), nil
}

func TestTLSConfig_PinsBundleOnly(t *testing.T) {
	pinned := newTestCA(t, "diyddns agent CA pinned")
	other := newTestCA(t, "Totally A Public Root CA")

	certPEM, keyPEM := pinned.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "dev-a"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	st := State{DeviceID: "dev-a", KeyPEM: keyPEM, CertPEM: certPEM, CABundlePEM: pinned.pem}

	cfg, err := st.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3 (%#x)", cfg.MinVersion, tls.VersionTLS13)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs nil would fall back to system roots")
	}

	t.Run("server chaining to the bundle succeeds and sees the device cert", func(t *testing.T) {
		srv := serve(t, pinned, pinned)
		body, err := get(t, cfg, srv.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if body != "dev-a" {
			t.Errorf("server saw client CN %q, want dev-a", body)
		}
	})

	t.Run("server chaining to an unpinned root fails", func(t *testing.T) {
		srv := serve(t, other, pinned)
		_, err := get(t, cfg, srv.URL)
		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
			t.Fatalf("GET err = %v, want x509.UnknownAuthorityError", err)
		}
	})
}

func TestTLSConfig_BadMaterial(t *testing.T) {
	good := newTestState(t, "dev-a")
	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"empty CA bundle", func(s *State) { s.CABundlePEM = "" }},
		{"garbage CA bundle", func(s *State) { s.CABundlePEM = "junk" }},
		{"garbage key", func(s *State) { s.KeyPEM = "junk" }},
		{"garbage cert", func(s *State) { s.CertPEM = "junk" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := good
			tt.mutate(&st)
			cfg, err := st.TLSConfig()
			if err == nil {
				t.Fatalf("TLSConfig = %+v, want error", cfg)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Errorf("error leaked key material: %v", err)
			}
		})
	}
}
