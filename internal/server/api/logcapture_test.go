package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/store"
)

// logCapture collects the JSON lines a logger writes. The server logs from its
// own goroutines, so reads and writes share a mutex.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// String returns everything logged so far, raw, for asserting that a value
// appears nowhere in the log.
func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// logger returns a JSON logger at Debug that writes into c.
func (c *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// records returns every line logged so far, decoded.
func (c *logCapture) records(t *testing.T) []map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(c.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v (%s)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// atLevel returns the records logged at level ("INFO", "ERROR", ...).
func atLevel(recs []map[string]any, level string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] == level {
			out = append(out, r)
		}
	}
	return out
}

// withMsg returns the records whose message is msg.
func withMsg(recs []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// serveWith starts the full server over deps, which buildServerDeps built on
// st, with the mux wrapped by wrap (nil for no wrapper).
func serveWith(t *testing.T, st *store.Store, deps api.ServerDeps, wrap func(http.Handler) http.Handler) fullHarness {
	t.Helper()
	mux := http.NewServeMux()
	api.Build(mux, deps)
	var h http.Handler = mux
	if wrap != nil {
		h = wrap(mux)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return fullHarness{srv: srv, st: st}
}

// cancelledRequests wraps h so every request reaches it with a context that is
// already cancelled: the deterministic stand-in for a client that hung up. (A
// raw-TCP hang-up lands only most of the time, so it cannot back an assertion.)
// It is a serveWith wrapper.
func cancelledRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// newLoggedHarness is newFullHarness with deps.Log replaced by a capture
// logger, for tests that assert on what the API layer logs. newFullHarness
// discards its log.
func newLoggedHarness(t *testing.T) (fullHarness, *logCapture) {
	t.Helper()
	st, deps := buildServerDeps(t)
	logs := &logCapture{}
	deps.Log = logs.logger()
	return serveWith(t, st, deps, nil), logs
}
