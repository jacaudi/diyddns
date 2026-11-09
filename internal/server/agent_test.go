package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/logtest"
	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// syncBuffer is a bytes.Buffer safe to write from server goroutines while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// jsonLog returns a slog logger writing JSON records and the buffer they land in.
func jsonLog() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// freeAddr returns a loopback address nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

// agentTestConfig is routesTestConfig with a file-backed database in a fresh
// directory and both listeners on free loopback ports.
func agentTestConfig(t *testing.T) (config.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := routesTestConfig(t)
	cfg.Database.Path = filepath.Join(dir, "diyddns.db")
	cfg.Server.Listen = freeAddr(t)
	agentAddr := freeAddr(t)
	cfg.Agent = config.AgentSection{
		Listen:    agentAddr,
		PublicURL: "https://" + agentAddr,
		TLS:       config.AgentTLSSection{Dir: dir},
	}
	return cfg, dir
}

func openFileStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newAgentServer builds a Server with the agent listener enabled.
func newAgentServer(t *testing.T, cfg config.Server, st *store.Store, log *slog.Logger) *Server {
	t.Helper()
	s, err := New(cfg, st, log, NopInstruments{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.agent.release)
	return s
}

// runServer starts s.Run and returns its cancel func and result channel. The
// cleanup cancels and waits, so no test leaves a listener behind.
func runServer(t *testing.T, s *Server) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ch := make(chan error, 1)
	go func() {
		ch <- s.Run(ctx)
		close(ch) // a second receive in the cleanup must not block after the test took the result
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-ch:
		case <-time.After(shutdownTimeout):
			t.Error("Run did not return after cleanup cancel")
		}
	})
	return cancel, ch
}

// eventually retries fn until it returns nil, for the window between starting
// Run and its listeners accepting.
func eventually(t *testing.T, what string, fn func() error) {
	t.Helper()
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if err = fn(); err == nil {
			return
		}
	}
	t.Fatalf("%s: %v", what, err)
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	eventually(t, "dial "+addr, func() error {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	})
}

func assertRefused(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = c.Close()
		t.Errorf("%s still accepts connections", addr)
	}
}

func assertLockFree(t *testing.T, dir string) {
	t.Helper()
	l, err := agenttls.AcquireLock(dir)
	if err != nil {
		t.Fatalf("AcquireLock(%s) = %v, want the lock free", dir, err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func awaitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func TestCheckAgentDirs(t *testing.T) {
	tests := []struct {
		name     string
		dbPath   string
		dir      func(t *testing.T) string
		wantErr  string
		wantMode bool
	}{
		{
			name:    "memory database",
			dbPath:  ":memory:",
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "a") },
			wantErr: "database.path",
		},
		{
			name:    "shared-cache memory database",
			dbPath:  "file::memory:?cache=shared",
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "a") },
			wantErr: "database.path",
		},
		{
			// Where agent.tls.dir lives is the operator's call (#6).
			name:     "fresh dir under the temp dir",
			dbPath:   "/data/diyddns.db",
			dir:      func(t *testing.T) string { return filepath.Join(t.TempDir(), "agent") },
			wantMode: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir(t)

			err := checkAgentDirs(tt.dbPath, dir)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkAgentDirs() = %v, want nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkAgentDirs() = %v, want an error naming %s", err, tt.wantErr)
			}
			if tt.wantMode {
				info, err := os.Stat(dir)
				if err != nil {
					t.Fatalf("Stat: %v", err)
				}
				if got := info.Mode().Perm(); got != 0o700 {
					t.Errorf("dir mode = %o, want 700", got)
				}
			}
		})
	}
}

func TestNew_AgentDisabledUnchanged(t *testing.T) {
	cfg := routesTestConfig(t)
	cfg.Agent.TLS.Dir = t.TempDir()

	s, err := New(cfg, openTestStore(t), discardLog(), NopInstruments{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if s.agentServer != nil || s.agent != nil {
		t.Errorf("agentServer = %v, agent = %v, want both nil with agent.listen empty", s.agentServer, s.agent)
	}
	if _, err := os.Stat(filepath.Join(cfg.Agent.TLS.Dir, agenttls.LockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(.lock) = %v, want not-exist: a disabled listener must not touch agent.tls.dir", err)
	}
}

func TestNew_AgentEnabledGuardsMemoryDB(t *testing.T) {
	cfg, _ := agentTestConfig(t)
	cfg.Database.Path = ":memory:"

	_, err := New(cfg, openTestStore(t), discardLog(), NopInstruments{})

	if err == nil || !strings.Contains(err.Error(), "database.path") {
		t.Fatalf("New() = %v, want an error naming database.path", err)
	}
}

func TestNew_AgentEnabledHoldsLock(t *testing.T) {
	cfg, dir := agentTestConfig(t)
	s := newAgentServer(t, cfg, openFileStore(t, cfg.Database.Path), discardLog())

	if _, err := agenttls.AcquireLock(dir); !errors.Is(err, agenttls.ErrLocked) {
		t.Fatalf("AcquireLock while serving = %v, want ErrLocked", err)
	}
	cancel, done := runServer(t, s)
	waitDial(t, cfg.Server.Listen)
	cancel()
	if err := awaitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertLockFree(t, dir)
}

func TestNew_ReleasesLockWhenHandlerFails(t *testing.T) {
	cfg, dir := agentTestConfig(t)
	cfg.Auth.HMAC.SecretKey = "not a key"

	if _, err := New(cfg, openFileStore(t, cfg.Database.Path), discardLog(), NopInstruments{}); err == nil {
		t.Fatal("New() = nil error, want the handler failure")
	}

	assertLockFree(t, dir)
}

// newDeviceCert enrolls a device and issues it a certificate through the main
// path of CertService, returning the device id, its HMAC secret and the pair.
func newDeviceCert(t *testing.T, cfg config.Server, st *store.Store, ca *agenttls.CA) (id string, secret []byte, cert tls.Certificate) {
	t.Helper()
	ctx := t.Context()
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		t.Fatalf("DecodeSecretKey: %v", err)
	}
	u, err := st.Users().Create(ctx, store.User{Email: "agent@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	audit := service.NewAuditWriter(st)
	res, err := service.NewEnrollmentService(st, key, time.Minute, audit, discardLog()).
		EnrollForUser(ctx, u.ID, "device.enroll.oidc", service.ClientMeta{Hostname: "laptop"})
	if err != nil {
		t.Fatalf("EnrollForUser: %v", err)
	}

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, devKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	issued, err := service.NewCertService(st, ca, cfg.Agent.PublicURL, audit).Issue(ctx, res.DeviceID,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	return res.DeviceID, res.Secret, tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: devKey}
}

var checkinNonce int

// signedCheckin builds an HMAC-signed POST /agent/v1/checkin against base.
func signedCheckin(t *testing.T, base, id string, secret []byte) *http.Request {
	t.Helper()
	checkinNonce++
	nonce := "agent-test-nonce-" + strconv.Itoa(checkinNonce)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := []byte(`{"ipv4":"1.2.3.4"}`)
	const path = "/agent/v1/checkin"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(shared.HeaderDevice, id)
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, shared.Sign(secret, shared.CanonicalRequest(http.MethodPost, path, ts, nonce, shared.BodyHashHex(body))))
	return req
}

func TestRun_AgentListenerServesMTLS(t *testing.T) {
	cfg, _ := agentTestConfig(t)
	st := openFileStore(t, cfg.Database.Path)
	s := newAgentServer(t, cfg, st, discardLog())
	id, secret, cert := newDeviceCert(t, cfg, st, s.agent.ca)
	runServer(t, s)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(s.agent.ca.Bundle()) {
		t.Fatal("CA bundle has no certificates")
	}
	client := func(maxVersion uint16) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, MaxVersion: maxVersion, RootCAs: pool, Certificates: []tls.Certificate{cert},
		}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}

	eventually(t, "signed checkin on the agent port", func() error {
		resp, err := client(tls.VersionTLS13).Do(signedCheckin(t, cfg.Agent.PublicURL, id, secret))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("status = %d, body = %s", resp.StatusCode, body)
		}
		return nil
	})

	resp, err := client(tls.VersionTLS12).Do(signedCheckin(t, cfg.Agent.PublicURL, id, secret))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("TLS 1.2 request to the agent port succeeded, want a handshake error")
	}
}

func TestRun_AgentHandshakeErrorsAreSlog(t *testing.T) {
	cfg, _ := agentTestConfig(t)
	log, buf := jsonLog()
	s := newAgentServer(t, cfg, openFileStore(t, cfg.Database.Path), log)
	cancel, done := runServer(t, s)

	eventually(t, "plain HTTP to the agent port", func() error {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+cfg.Agent.Listen+"/", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	})
	cancel()
	if err := awaitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var found bool
	for _, rec := range logtest.Records(t, buf.String()) {
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "TLS handshake error") {
			found = true
		}
	}
	if !found {
		t.Errorf("no JSON record with a TLS handshake error msg in:\n%s", buf.String())
	}
}

func TestRun_GracefulShutdownBoth(t *testing.T) {
	cfg, dir := agentTestConfig(t)
	s := newAgentServer(t, cfg, openFileStore(t, cfg.Database.Path), discardLog())
	cancel, done := runServer(t, s)
	waitDial(t, cfg.Server.Listen)
	waitDial(t, cfg.Agent.Listen)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil on a clean shutdown", err)
		}
	case <-time.After(shutdownTimeout):
		t.Fatal("Run did not return within shutdownTimeout")
	}

	assertRefused(t, cfg.Server.Listen)
	assertRefused(t, cfg.Agent.Listen)
	assertLockFree(t, dir)
}

func TestRun_AgentListenFailureStopsBoth(t *testing.T) {
	cfg, dir := agentTestConfig(t)
	occupied, err := net.Listen("tcp", cfg.Agent.Listen)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	s := newAgentServer(t, cfg, openFileStore(t, cfg.Database.Path), discardLog())

	_, done := runServer(t, s)

	runErr := awaitRun(t, done)
	if runErr == nil || !strings.HasPrefix(runErr.Error(), "server: listen:") {
		t.Fatalf("Run = %v, want an error starting %q without any ctx cancellation", runErr, "server: listen:")
	}
	assertRefused(t, cfg.Server.Listen)
	assertLockFree(t, dir)
}
