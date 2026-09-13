package middleware_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/middleware"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
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

// TestAccessLog_ResponseWriterUnwrapsToHijacker is the regression guard for
// the #106 design's §5.1: AccessLog wraps the ResponseWriter in a
// statusRecorder, and a WebSocket upgrade (github.com/coder/websocket's
// Accept) reaches http.Hijacker only by walking Unwrap(). Without Unwrap
// every upgrade through the real middleware chain answers 501. This drives
// the real chain over a real TCP listener, because httptest.NewRecorder
// cannot be hijacked at all.
func TestAccessLog_ResponseWriterUnwrapsToHijacker(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hijacked := make(chan error, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			hijacked <- err
			http.Error(w, "no hijack", http.StatusNotImplemented)
			return
		}
		_ = conn.Close()
		hijacked <- nil
	})
	srv := httptest.NewServer(middleware.Chain(inner,
		middleware.RequestID("X-Request-Id"),
		middleware.AccessLog(log),
		middleware.Recover(log),
	))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-hijacked; err != nil {
		t.Fatalf("Hijack through the AccessLog wrapper failed: %v (statusRecorder must implement Unwrap)", err)
	}
}

// The span name carries the low-cardinality ROUTE TEMPLATE, read off the
// request passed DOWN to the mux -- not the outer request, whose Pattern the
// mux never annotates.
func TestTrace_SpanNameIsRouteTemplate(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(mux)

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/devices/dev_01J8WABCDEF")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got, want := spans[0].Name, "GET /devices/{id}"; got != want {
		t.Errorf("span name = %q, want %q -- did you read r.Pattern instead of r2.Pattern?", got, want)
	}
}

// An unmatched route yields an empty Pattern. The span must NOT fall back to
// the raw path, which carries device and user ids (design D8, and #100's D8).
func TestTrace_UnmatchedRouteDoesNotLeakPath(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	h := middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(http.NewServeMux())
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/devices/dev_SECRET_ID")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got, want := spans[0].Name, "HTTP GET"; got != want {
		t.Errorf("span name = %q, want %q", got, want)
	}
	// String(), not AsString(): AsString() returns "" for a non-STRING value
	// (e.g. the INT64 status code), so a scan built on it would silently skip
	// every non-string attribute. String() formats every kind, so the scan
	// covers the whole attribute set, not just the string-valued ones.
	for _, kv := range spans[0].Attributes {
		if strings.Contains(kv.Value.String(), "dev_SECRET_ID") {
			t.Errorf("attribute %s leaked the raw path: %q", kv.Key, kv.Value.String())
		}
	}
}

// EXACTLY four attributes, and server.address is the host WITHOUT the port.
// Also pins SpanKind: deleting trace.WithSpanKind(trace.SpanKindServer)
// survived the whole suite in fix round 1's mutation sweep (S4) -- SpanKind is
// what makes these server spans to RED metrics, service graphs, and any
// SpanKind-filtered backend query.
func TestTrace_AttributeSet(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {})
	srv := httptest.NewServer(middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(mux))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got, want := spans[0].SpanKind, trace.SpanKindServer; got != want {
		t.Errorf("span kind = %v, want %v", got, want)
	}

	got := map[string]string{}
	for _, kv := range spans[0].Attributes {
		got[string(kv.Key)] = kv.Value.String()
	}
	for _, want := range []string{"http.request.method", "http.route", "http.response.status_code", "server.address"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing attribute %s (have %v)", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d attributes %v, want exactly 4", len(got), got)
	}
	// server.address strips the port (net.SplitHostPort on "host:port"), but a
	// bracketed IPv6 literal WITHOUT a port -- "[2001:db8::1]" -- has nothing
	// for SplitHostPort to split, so it errors and the brackets pass through
	// unchanged. That is the only reason this check excludes "::": a bare ":"
	// substring flags a real leftover port; "::" is a legitimate IPv6 literal.
	// A local httptest server's host is loopback (127.0.0.1 or ::1), so this
	// case does not fire in this test, but the exclusion documents the shape
	// serverAddress's own comment describes.
	if strings.Contains(got["server.address"], ":") && !strings.Contains(got["server.address"], "::") {
		t.Errorf("server.address = %q still carries the port", got["server.address"])
	}
}

// A handler that never calls WriteHeader must record 200, not 0 -- the same
// defaulting AccessLog applies at middleware.go:141-143. Without it,
// "5xx marks the span Error" reads a zero.
func TestTrace_DefaultsStatusTo200(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /quiet", func(http.ResponseWriter, *http.Request) {}) // writes nothing
	srv := httptest.NewServer(middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(mux))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/quiet")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	for _, kv := range spans[0].Attributes {
		if kv.Key == "http.response.status_code" {
			if got := kv.Value.AsInt64(); got != 200 {
				t.Errorf("status_code = %d, want 200", got)
			}
			return
		}
	}
	t.Fatal("no http.response.status_code attribute")
}

// A 4xx is a rejected request, not a server fault: it must NOT mark the span
// Error. Only a 5xx does. Guards the `>= 500` boundary in Trace, which a
// `>= 400` mutant would still pass every other TestTrace case.
func TestTrace_OnlyServerErrorMarksSpanError(t *testing.T) {
	for _, tt := range []struct {
		name       string
		status     int
		wantStatus codes.Code
	}{
		{"4xx leaves span unset", http.StatusNotFound, codes.Unset},
		{"5xx marks span Error", http.StatusInternalServerError, codes.Error},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exp := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
			t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

			mux := http.NewServeMux()
			mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			srv := httptest.NewServer(middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(mux))
			t.Cleanup(srv.Close)
			resp, err := srv.Client().Get(srv.URL + "/status")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()

			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if got := spans[0].Status.Code; got != tt.wantStatus {
				t.Errorf("span status = %v, want %v", got, tt.wantStatus)
			}
		})
	}
}

// An inbound W3C traceparent continues the upstream trace.
// middleware.go:30 sized maxRequestIDLen at 128 specifically to admit one.
func TestTrace_ContinuesInboundTraceparent(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	srv := httptest.NewServer(middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(mux))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/healthz", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got, want := spans[0].SpanContext.TraceID().String(), "4bf92f3577b34da6a3ce929d0e0e4736"; got != want {
		t.Errorf("trace id = %s, want %s -- the propagator did not extract", got, want)
	}
}

// The duration histogram is recorded once per request, in SECONDS.
func TestTrace_RecordsDurationInSeconds(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	srv := httptest.NewServer(middleware.Trace(tracenoop.NewTracerProvider().Tracer("t"), hist)(mux))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	h := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	if n := h.DataPoints[0].Count; n != 1 {
		t.Fatalf("recorded %d times, want 1", n)
	}
	// A local request is sub-millisecond. In SECONDS that is well under 1;
	// if the implementation recorded milliseconds it would be >= 1 only on a
	// slow box, so assert the shape rather than a threshold: the sum must be
	// smaller than a whole second.
	if sum := h.DataPoints[0].Sum; sum >= 1 {
		t.Errorf("sum = %v; a local request should be well under 1 SECOND — are you recording ms?", sum)
	}
}

// The histogram's label set gets its OWN pin, separate from the span's.
// Fix round 1's critic mutation M12 -- add a 5th attribute to
// metric.WithAttributes(...) ONLY, leaving the span's SetAttributes
// untouched -- survived the entire package suite, because nothing asserted
// the datapoint's attribute set independently of the span's.
func TestTrace_HistogramAttributeSet(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	srv := httptest.NewServer(middleware.Trace(tracenoop.NewTracerProvider().Tracer("t"), hist)(mux))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	h := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	if n := len(h.DataPoints); n != 1 {
		t.Fatalf("got %d datapoints, want 1", n)
	}

	got := map[string]string{}
	for _, kv := range h.DataPoints[0].Attributes.ToSlice() {
		got[string(kv.Key)] = kv.Value.String()
	}
	for _, want := range []string{"http.request.method", "http.route", "http.response.status_code"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing attribute %s (have %v)", want, got)
		}
	}
	// EXACTLY three: no server.address (span-only) and no url.path (design
	// D8/B1's cardinality hazard for the metric specifically).
	if len(got) != 3 {
		t.Errorf("got %d attributes %v, want exactly 3", len(got), got)
	}
}

// B1 (fix round 1, Blocking): a method semconv knows passes through
// unchanged in all three cardinality surfaces -- the span name's unmatched-
// route fallback, the span attribute, and the histogram label.
//
// POST and QUERY, not GET: GET is already exercised by every other
// TestTrace_* case, so POST proves passthrough independently of them; QUERY
// specifically locks in reading the PINNED httpconv package's own constant
// list rather than a hand-typed set of the nine RFC 9110 verbs -- QUERY is
// the tenth method httpconv actually ships (the httpbis-safe-method-w-body
// draft method, attribute_group.go:7222-7226 in the pinned semconv), and a
// hand-typed nine-method set would silently normalize it to _OTHER.
func TestTrace_KnownMethodPassesThrough(t *testing.T) {
	for _, method := range []string{"POST", "QUERY"} {
		t.Run(method, func(t *testing.T) {
			exp := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
			t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
			if err != nil {
				t.Fatalf("Float64Histogram: %v", err)
			}

			h := middleware.Trace(tp.Tracer("test"), hist)(http.NewServeMux())
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/nope", nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()

			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if got, want := spans[0].Name, "HTTP "+method; got != want {
				t.Errorf("span name = %q, want %q", got, want)
			}
			if got := methodAttr(t, spans[0].Attributes); got != method {
				t.Errorf("span http.request.method = %q, want %s", got, method)
			}

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(t.Context(), &rm); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			dp := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64]).DataPoints[0]
			if got := methodAttr(t, dp.Attributes.ToSlice()); got != method {
				t.Errorf("metric http.request.method = %q, want %s", got, method)
			}
		})
	}
}

// B1: an unknown method normalizes to "_OTHER" in all three surfaces, never
// leaking the raw verb. Without this, an unauthenticated caller mints one
// span name and one time series per junk verb (sdk/metric@v1.46.0's
// defaultCardinalityLimit is 2000 datapoints -- a small budget an attacker
// can exhaust, spilling legitimate routes into otel.metric.overflow
// permanently under cumulative temporality).
func TestTrace_UnknownMethodNormalizesToOther(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	h := middleware.Trace(tp.Tracer("test"), hist)(http.NewServeMux())
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), "FROBNICATE", srv.URL+"/x", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got, want := spans[0].Name, "HTTP _OTHER"; got != want {
		t.Errorf("span name = %q, want %q -- did the raw verb leak into the name?", got, want)
	}
	if got := methodAttr(t, spans[0].Attributes); got != "_OTHER" {
		t.Errorf("span http.request.method = %q, want _OTHER", got)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dp := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64]).DataPoints[0]
	if got := methodAttr(t, dp.Attributes.ToSlice()); got != "_OTHER" {
		t.Errorf("metric http.request.method = %q, want _OTHER", got)
	}
}

// B1: matching is case-SENSITIVE. semconv's http.request.method definition
// (attribute_group.go:7249-7250 in the pinned semconv) says the value "MUST
// match a known HTTP method name exactly" -- "get" is not "GET" and must
// normalize to _OTHER, the same as any other unknown token.
func TestTrace_LowercaseKnownMethodNormalizesToOther(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	h := middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(http.NewServeMux())
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), "get", srv.URL+"/x", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := methodAttr(t, spans[0].Attributes); got != "_OTHER" {
		t.Errorf("http.request.method = %q for lowercase \"get\", want _OTHER", got)
	}
}

// B1: two distinct junk methods sent over raw TCP -- no httptest.Client
// method validation in the way -- must mint exactly ONE time series, not one
// per verb. This is the actual denial-of-telemetry scenario B1 defends
// against: an unauthenticated caller cannot grow the histogram's cardinality
// by varying the request line.
func TestTrace_JunkMethodsOverRawTCPMintNoNewTimeSeries(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	h := middleware.Trace(tracenoop.NewTracerProvider().Tracer("t"), hist)(http.NewServeMux())
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, junk := range []string{"FROG", "ZORP", "QUUX"} {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if _, err := fmt.Fprintf(conn, "%s /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", junk); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // drain the response so the handler completes
		_ = conn.Close()
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	h2 := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	if n := len(h2.DataPoints); n != 1 {
		t.Fatalf("got %d time series for 3 junk methods, want 1 (all should collapse to _OTHER): %+v", n, h2.DataPoints)
	}
	if got := h2.DataPoints[0].Count; got != 3 {
		t.Errorf("the single series recorded %d requests, want 3", got)
	}
}

// methodAttr extracts the http.request.method value from an attribute list,
// failing the test if absent. Shared by the B1 tests above.
func methodAttr(t *testing.T, attrs []attribute.KeyValue) string {
	t.Helper()
	for _, kv := range attrs {
		if kv.Key == "http.request.method" {
			return kv.Value.AsString()
		}
	}
	t.Fatal("no http.request.method attribute")
	return ""
}

// A request held open for a KNOWN duration makes the unit unambiguous, unlike
// TestTrace_RecordsDurationInSeconds above: a sub-millisecond local request
// truncates to 0 under an int-milliseconds bug too, so that test alone cannot
// tell seconds from milliseconds on a fast box. Here the handler sleeps 40ms,
// so a seconds-unit recording lands near 0.04 while a milliseconds-unit
// recording lands near 40 -- unmistakably over the 1-second ceiling.
func TestTrace_DurationUnitIsSecondsNotMilliseconds(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	hist, err := mp.Meter("test").Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	const sleep = 40 * time.Millisecond
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(http.ResponseWriter, *http.Request) { time.Sleep(sleep) })
	srv := httptest.NewServer(middleware.Trace(tracenoop.NewTracerProvider().Tracer("t"), hist)(mux))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/slow")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	h := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
	if sum := h.DataPoints[0].Sum; sum < sleep.Seconds() || sum >= 1 {
		t.Errorf("sum = %v seconds for a %v sleep; want roughly %v — are you recording ms?", sum, sleep, sleep.Seconds())
	}
}

// An unauthenticated caller must not get to put an unbounded string on a span.
// r.Host is attacker-chosen, server.go sets no MaxHeaderBytes so Go's 1 MiB
// default applies, and the trace SDK's default AttributeValueLengthLimit is -1
// -- unlimited (sdk/trace@v1.46.0/span_limits.go:9-11). The span is then
// retained in the batch processor's 2048-slot queue across the export window,
// so those bytes are held rather than freed at end of request.
//
// This is the same argument maxRequestIDLen already accepts for request_id
// (middleware.go's validRequestID), applied to the one other untrusted value
// this package copies onto every record of a request.
//
// 700 KiB is the size a reviewer landed through a real listener, which produced
// a span whose server.address attribute was 716,800 bytes.
func TestTrace_OverLongHostDoesNotReachTheSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	h := middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = strings.Repeat("a", 700<<10)
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	var got string
	var found bool
	for _, kv := range spans[0].Attributes {
		if kv.Key == "server.address" {
			got, found = kv.Value.AsString(), true
		}
	}
	if !found {
		t.Fatal("no server.address attribute")
	}
	// 253 is the maximum length of a DNS name, the longest thing a legitimate
	// Host header can carry; an IP literal is far shorter. Asserted as a
	// literal rather than against the production constant because this test
	// lives in the external test package.
	if len(got) > 253 {
		t.Errorf("server.address is %d bytes; an untrusted Host must be bounded", len(got))
	}
}

// A Host header carrying bytes outside printable ASCII must not reach the span.
// This is not cosmetic and not about length: httpguts.ValidHeaderFieldValue
// permits 0x80-0xFF, so net/http hands those bytes through intact, and an OTLP
// attribute value is a protobuf `string` field. google.golang.org/protobuf
// REFUSES to marshal invalid UTF-8 there -- measured directly:
// proto.Marshal of a KeyValue whose StringValue is "\xff\xfe" returns
// "string field contains invalid UTF-8". The exporter marshals a whole batch at
// once, so a single such request drops every span batched with it, and a caller
// repeating it silently stops trace export process-wide. Bounding the length
// (TestTrace_OverLongHostDoesNotReachTheSpan) does not cover it: two bytes are
// enough.
func TestTrace_NonASCIIHostDoesNotReachTheSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	h := middleware.Trace(tp.Tracer("test"), noop.Float64Histogram{})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "\xff\xfe.example.com"
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	var got string
	var found bool
	for _, kv := range spans[0].Attributes {
		if kv.Key == "server.address" {
			got, found = kv.Value.AsString(), true
		}
	}
	if !found {
		t.Fatal("no server.address attribute")
	}
	for i := range len(got) {
		if got[i] < 0x20 || got[i] > 0x7E {
			t.Errorf("server.address byte %d is %#x; an untrusted Host must be printable ASCII "+
				"or the OTLP batch carrying this span fails to marshal (value %q)", i, got[i], got)
			break
		}
	}
}
