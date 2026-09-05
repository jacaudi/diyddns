package server_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/server/middleware"
)

// logRecords runs fn with a logger writing JSON to a temp file, then returns
// the decoded records. Output is a file path because NewLogger's only
// non-stderr/stdout sink is a path (logging.go:31).
func logRecords(t *testing.T, fn func(*slog.Logger)) []map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log.json")
	log, err := server.NewLogger(config.LoggingSection{Level: "debug", Format: "json", Output: path})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	fn(log)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var out []map[string]any
	// SplitSeq, not Split -- `modernize` is not excluded for _test.go files.
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// reqCtx returns a context carrying a request id, produced by the real
// middleware rather than by reaching into its unexported context key.
//
// The header name is passed explicitly because RequestID is now configured
// from observability.request_id_header; "X-Request-Id" is that key's default.
func reqCtx(t *testing.T, id string) context.Context {
	t.Helper()
	var got context.Context
	h := middleware.RequestID("X-Request-Id")(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) { got = r.Context() }))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-Id", id)
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestNewLogger_AddsRequestIDFromContext(t *testing.T) {
	ctx := reqCtx(t, "req-abc-123")
	recs := logRecords(t, func(log *slog.Logger) {
		log.LogAttrs(ctx, slog.LevelInfo, "handler thing", slog.String("k", "v"))
	})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if got := recs[0]["request_id"]; got != "req-abc-123" {
		t.Fatalf("request_id = %v, want %q", got, "req-abc-123")
	}
}

// D2: absent, not empty. A background record must carry no request_id KEY at
// all -- an empty string reads as "correlation failed" on every pruner sweep.
func TestNewLogger_OmitsRequestIDKeyWithoutRequestContext(t *testing.T) {
	recs := logRecords(t, func(log *slog.Logger) {
		log.LogAttrs(context.Background(), slog.LevelWarn, "background sweep")
	})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if _, present := recs[0]["request_id"]; present {
		t.Fatalf("request_id key present on a background record: %v", recs[0])
	}
}

// D4: WithAttrs must RE-WRAP. Returning h.inner.WithAttrs(as) directly unwraps
// the handler and silently stops adding ids from that point on. The tree has
// zero Logger.With call sites, so only this test can catch it.
func TestNewLogger_WithAttrsKeepsAddingRequestID(t *testing.T) {
	ctx := reqCtx(t, "req-with")
	recs := logRecords(t, func(log *slog.Logger) {
		log.With("component", "grants").LogAttrs(ctx, slog.LevelInfo, "via With")
	})
	if got := recs[0]["request_id"]; got != "req-with" {
		t.Fatalf("request_id = %v, want %q (WithAttrs unwrapped the handler)", got, "req-with")
	}
}

// D4's documented limitation, pinned deliberately: under WithGroup the id
// lands INSIDE the group. This assertion is correct as written -- if it ever
// fails, do NOT "fix" it by unwrapping the handler.
func TestNewLogger_WithGroupNestsRequestID(t *testing.T) {
	ctx := reqCtx(t, "req-group")
	recs := logRecords(t, func(log *slog.Logger) {
		log.WithGroup("g").LogAttrs(ctx, slog.LevelInfo, "via WithGroup")
	})
	if _, topLevel := recs[0]["request_id"]; topLevel {
		t.Fatal("request_id at top level under WithGroup; expected it nested in g")
	}
	g, ok := recs[0]["g"].(map[string]any)
	if !ok {
		t.Fatalf("no group object in record: %v", recs[0])
	}
	if got := g["request_id"]; got != "req-group" {
		t.Fatalf("g.request_id = %v, want %q", got, "req-group")
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.LoggingSection
		wantErr bool
	}{
		{"json stderr info", config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, false},
		{"text stdout debug", config.LoggingSection{Level: "debug", Format: "text", Output: "stdout"}, false},
		{"bad level", config.LoggingSection{Level: "loud", Format: "json", Output: "stderr"}, true},
		{"bad format", config.LoggingSection{Level: "info", Format: "xml", Output: "stderr"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := server.NewLogger(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			if log == nil {
				t.Fatal("nil logger")
			}
		})
	}
}
