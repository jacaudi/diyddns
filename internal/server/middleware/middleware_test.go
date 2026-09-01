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
	h := middleware.RequestID("X-Request-Id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" {
		t.Fatal("expected a generated request id in context")
	}
	if got := rec.Header().Get("X-Request-Id"); got != seen {
		t.Errorf("response header %q, context %q — should match", got, seen)
	}
}

func TestRequestID_HonorsIncoming(t *testing.T) {
	var seen string
	h := middleware.RequestID("X-Request-Id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "incoming-123")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "incoming-123" {
		t.Errorf("request id = %q, want incoming-123", seen)
	}
}

func TestRequestID_HonorsConfiguredHeader(t *testing.T) {
	var seen string
	h := middleware.RequestID("X-Correlation-Id")(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			seen = middleware.RequestIDFromContext(r.Context())
		}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Correlation-Id", "from-proxy-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if seen != "from-proxy-123" {
		t.Errorf("request id = %q, want from-proxy-123", seen)
	}
	if got := rec.Header().Get("X-Correlation-Id"); got != "from-proxy-123" {
		t.Errorf("echoed header = %q, want from-proxy-123", got)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "" {
		t.Errorf("default header %q should not be set when another is configured", got)
	}
}

// D7: an inbound id is REPLACED, never truncated. A truncated id still looks
// like the client's but no longer matches the proxy's logs -- a false
// correlation, which is worse than an honest new one.
func TestRequestID_ReplacesInvalidInbound(t *testing.T) {
	tests := []struct{ name, inbound string }{
		{"too long", strings.Repeat("a", 129)},
		{"newline", "abc\ndef"},
		{"tab", "abc\tdef"},
		{"non-ascii", "abcédef"},
		{"nul", "abc\x00def"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen string
			h := middleware.RequestID("X-Request-Id")(http.HandlerFunc(
				func(_ http.ResponseWriter, r *http.Request) {
					seen = middleware.RequestIDFromContext(r.Context())
				}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Request-Id", tt.inbound)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if seen == tt.inbound {
				t.Fatal("invalid inbound id was honored")
			}
			if seen == "" {
				t.Fatal("no replacement id was minted")
			}
			if strings.HasPrefix(tt.inbound, seen) || strings.HasPrefix(seen, tt.inbound) {
				t.Fatalf("id %q looks like a truncation of the inbound value, not a fresh mint", seen)
			}
			if got := rec.Header().Get("X-Request-Id"); got != seen {
				t.Errorf("echoed header %q != context id %q", got, seen)
			}
		})
	}
}

// A 128-byte value and a W3C traceparent must both be honored: 128 is chosen
// to admit a traceparent (55 bytes), keeping #101's correlation header
// adoptable.
func TestRequestID_HonorsValidInbound(t *testing.T) {
	for _, id := range []string{
		strings.Repeat("a", 128),
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // traceparent
		"0198f0a1-dead-7000-8000-abcdefabcdef",
	} {
		var seen string
		h := middleware.RequestID("X-Request-Id")(http.HandlerFunc(
			func(_ http.ResponseWriter, r *http.Request) {
				seen = middleware.RequestIDFromContext(r.Context())
			}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Request-Id", id)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if seen != id {
			t.Errorf("id %q was replaced; want it honored", id)
		}
	}
}

// D8: route, not path. The device id must not reach the log line.
func TestAccessLog_LogsRouteNotPath(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/devices/{id}", http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	h := middleware.AccessLog(log)(mux)
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/devices/dev_01J8WABCDEF", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log not JSON: %v (%s)", err, buf.String())
	}
	if got := line["route"]; got != "GET /api/v1/devices/{id}" {
		t.Errorf("route = %v, want %q", got, "GET /api/v1/devices/{id}")
	}
	if _, present := line["path"]; present {
		t.Error("path attr still present; it carries device ids")
	}
	if strings.Contains(buf.String(), "dev_01J8WABCDEF") {
		t.Errorf("device id leaked into the access log: %s", buf.String())
	}
}

// Both empty-route cases: 404 (no pattern matched) and 405 (path matched,
// method did not). ServeMux exposes no pattern for either, so status is what
// distinguishes them.
func TestAccessLog_RouteEmptyOn404And405(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("PATCH /api/v1/admin/users/{id}", http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tt := range []struct {
		name, method, target string
		wantStatus           float64
	}{
		{"404 no match", http.MethodGet, "/nope/not/a/route", 404},
		{"405 method mismatch", http.MethodGet, "/api/v1/admin/users/usr_01J8W", 405},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			h := middleware.AccessLog(log)(mux)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tt.method, tt.target, nil))

			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("log not JSON: %v", err)
			}
			if got := line["route"]; got != "" {
				t.Errorf("route = %v, want empty", got)
			}
			if got := line["status"]; got != tt.wantStatus {
				t.Errorf("status = %v, want %v", got, tt.wantStatus)
			}
		})
	}
}

func TestAccessLog_EmitsLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := middleware.RequestID("X-Request-Id")(middleware.AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/foo", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log not JSON: %v (%s)", err, buf.String())
	}
	// route, not path (D8): this handler is not registered on a mux, so its
	// pattern is empty. The two tests below cover route on a real mux.
	if line["method"] != "GET" {
		t.Errorf("method = %v, want GET", line["method"])
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
