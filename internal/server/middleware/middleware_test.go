package middleware_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/middleware"
)

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var seen string
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" {
		t.Fatal("expected a generated request id in context")
	}
	if got := rec.Header().Get(middleware.RequestIDHeader); got != seen {
		t.Errorf("response header %q, context %q — should match", got, seen)
	}
}

func TestRequestID_HonorsIncoming(t *testing.T) {
	var seen string
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.RequestIDHeader, "incoming-123")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "incoming-123" {
		t.Errorf("request id = %q, want incoming-123", seen)
	}
}

func TestAccessLog_EmitsLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.RequestID(middleware.AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/foo", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log not JSON: %v (%s)", err, buf.String())
	}
	if line["method"] != "GET" || line["path"] != "/foo" {
		t.Errorf("method/path = %v %v", line["method"], line["path"])
	}
	if line["status"].(float64) != 418 {
		t.Errorf("status = %v, want 418", line["status"])
	}
	// request_id is no longer an access-log attr (D3) -- the wrapper adds it.
	// What AccessLog still owes the caller is the echoed response header.
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("response is missing the correlation header")
	}
}

// D3: the wrapper supplies request_id, so AccessLog must not add its own.
// slog's JSON handler does not deduplicate, so both would appear.
func TestAccessLog_NoHandWrittenRequestID(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	if n := strings.Count(buf.String(), `"request_id"`); n != 0 {
		t.Fatalf("AccessLog emitted %d request_id attrs; the wrapper owns that field now: %s", n, buf.String())
	}
}

func TestRecover_ConvertsPanicTo500(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.Recover(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "panic") {
		t.Errorf("panic not logged: %s", buf.String())
	}
}

func TestChain_OrdersOuterToInner(t *testing.T) {
	var order []string
	mk := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { order = append(order, "handler") })
	h := middleware.Chain(final, mk("a"), mk("b"), mk("c"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	want := []string{"a", "b", "c", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}
