package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/store"
)

// agentSetupTimeout bounds setupAgent. New has no ctx parameter, so it supplies
// one; CA generation and the store write finish in well under a second.
const agentSetupTimeout = 30 * time.Second

// agentTempDirAllowed is a test seam: every t.TempDir lives under os.TempDir,
// which checkAgentDirs refuses in production. Only agent_test.go sets it.
var agentTempDirAllowed = false

// checkAgentDirs refuses the two layouts that would lose the agent CA on
// restart: an in-memory database (the recorded CA vanishes with the process
// while ca.key stays on disk, which startup rule 4 then refuses) and a CA
// directory under the OS temp dir (the key vanishes while the database
// survives, rule 2). It creates dir 0700 so the check sees where it really is.
func checkAgentDirs(dbPath, dir string) error {
	if dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:") {
		return fmt.Errorf("server: the agent listener needs a file-backed database.path, got %q", dbPath)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("server: create agent.tls.dir: %w", err)
	}
	if agentTempDirAllowed {
		return nil
	}
	resolved, err := resolvePath(dir)
	if err != nil {
		return err
	}
	tmp, err := resolvePath(os.TempDir())
	if err != nil {
		return err
	}
	// Both are absolute and cleaned, so Rel is "." or "a/b" when dir is the
	// temp dir or inside it, and "../x" otherwise.
	if rel, err := filepath.Rel(tmp, resolved); err == nil && filepath.IsLocal(rel) {
		return fmt.Errorf("server: agent.tls.dir %s is inside the OS temp dir %s; the CA key would not survive a restart", resolved, tmp)
	}
	return nil
}

// resolvePath returns p absolute with every symlink followed, so macOS's
// /tmp -> /private/tmp compares equal on both sides.
func resolvePath(p string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("server: resolve %s: %w", p, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("server: resolve %s: %w", p, err)
	}
	return abs, nil
}

// agentStack is everything the agent listener owns for the process lifetime.
type agentStack struct {
	lock    *agenttls.Lock
	ca      *agenttls.CA
	serving tls.Certificate
}

// setupAgent takes the agent.tls.dir lock, loads or creates the CA and loads or
// issues the serving certificate. It returns nil, nil when the listener is
// disabled. The lock is held until release; any error here releases it first.
func setupAgent(ctx context.Context, cfg config.Server, st *store.Store, log *slog.Logger) (*agentStack, error) {
	if !cfg.Agent.Enabled() {
		return nil, nil
	}
	dir := cfg.Agent.TLS.Dir
	if err := checkAgentDirs(cfg.Database.Path, dir); err != nil {
		return nil, err
	}
	lock, err := agenttls.AcquireLock(dir)
	if errors.Is(err, agenttls.ErrLocked) {
		return nil, fmt.Errorf("agent.tls.dir %s is locked: another diyddns-server or a ca command is running", dir)
	}
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	a := &agentStack{lock: lock}
	now := time.Now()
	if a.ca, err = agenttls.LoadOrInit(ctx, st, dir, now, log); err != nil {
		a.release()
		return nil, fmt.Errorf("server: %w", err)
	}
	if a.serving, err = agenttls.LoadOrIssueServingCert(dir, cfg.Agent.PublicHost(), a.ca, now, log); err != nil {
		a.release()
		return nil, fmt.Errorf("server: %w", err)
	}
	return a, nil
}

// release drops the directory lock. It is nil-safe and idempotent; a failed
// close leaves nothing for the caller to do, so the error is dropped.
func (a *agentStack) release() {
	if a != nil {
		_ = a.lock.Release()
	}
}

// buildAgentServer returns the agent listener's http.Server, or nil when the
// listener is disabled (stack is nil). It requests any client certificate
// without verifying it: the handshake cannot name the active CA alone (ClientCAs
// stays nil), so api.ClientCertMiddleware does the real check per request.
// TLS 1.3 is the floor. Handshake failures, which scanners and plain-HTTP
// clients cause constantly, go to log rather than the std logger's stderr.
func buildAgentServer(cfg config.Server, h http.Handler, stack *agentStack, log *slog.Logger) *http.Server {
	if stack == nil {
		return nil
	}
	log.LogAttrs(context.Background(), slog.LevelInfo, "agent listener enabled",
		slog.String("listen", cfg.Agent.Listen),
		slog.String("public_url", cfg.Agent.PublicURL),
		slog.Bool("require_mtls", cfg.Agent.RequireMTLS))
	return &http.Server{
		Addr:              cfg.Agent.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelInfo),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAnyClientCert,
			Certificates: []tls.Certificate{stack.serving},
		},
	}
}
