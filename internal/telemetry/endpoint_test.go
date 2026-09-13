package telemetry

import "testing"

func TestSignalEndpoint(t *testing.T) {
	tests := []struct {
		name, in, want string
		wantFatal      bool
	}{
		{"plain", "http://otel-collector:4318", "http://otel-collector:4318/v1/traces", false},
		{"trailing slash", "http://otel-collector:4318/", "http://otel-collector:4318/v1/traces", false},
		{"sub-path", "http://otel-collector:4318/otlp", "http://otel-collector:4318/otlp/v1/traces", false},
		{"https", "https://collector.example.com", "https://collector.example.com/v1/traces", false},
		{"ipv6", "http://[2001:db8::1]:4318", "http://[2001:db8::1]:4318/v1/traces", false},
		// Whitespace must NOT be fatal: an endpoint from a k8s secret or an
		// --env-file routinely carries a trailing newline, and design D5
		// forbids telemetry being the reason this server refuses to start.
		{"trailing newline", "http://otel-collector:4318\n", "http://otel-collector:4318/v1/traces", false},
		{"surrounding space", "  http://otel-collector:4318  ", "http://otel-collector:4318/v1/traces", false},
		// These are the silent killers the guard exists for.
		{"no scheme", "otel-collector:4318", "", true},
		{"not a url", "not a url", "", true},
		{"scheme only", "http://", "", true},
		{"wrong scheme", "grpc://otel-collector:4317", "", true},
		{"schemeless authority", "//otel-collector:4318", "", true},
		// A base that already ends in the signal path would otherwise be
		// silently doubled into POST /v1/traces/v1/traces, which 404s and
		// retries forever while Shutdown reports success -- the same
		// silent-failure signature the scheme/host guard exists to eliminate.
		// Plausible input: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is specified as
		// a full per-signal path, and an operator can copy that value here.
		{"already has signal path", "http://otel-collector:4318/v1/traces", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, st := signalEndpoint(tt.in, signalTraces)
			if st.Fatal != tt.wantFatal {
				t.Fatalf("Fatal = %v (reason %q), want %v", st.Fatal, st.Reason, tt.wantFatal)
			}
			if tt.wantFatal {
				if st.Reason == "" {
					t.Error("Fatal status must carry a Reason")
				}
				if got != "" {
					t.Errorf("Fatal status must return an empty endpoint, got %q", got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("signalEndpoint(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Every signal gets its own path; a base URL is not an endpoint.
func TestSignalEndpoint_PerSignalPaths(t *testing.T) {
	const base = "http://c:4318"
	tests := []struct {
		sig  otlpSignal
		want string
	}{
		{signalTraces, "http://c:4318/v1/traces"},
		{signalMetrics, "http://c:4318/v1/metrics"},
		{signalLogs, "http://c:4318/v1/logs"},
	}
	for _, tt := range tests {
		t.Run(tt.sig.name, func(t *testing.T) {
			got, st := signalEndpoint(base, tt.sig)
			if st.Fatal || got != tt.want {
				t.Errorf("signalEndpoint(%q, %+v) = %q (fatal %v), want %q", base, tt.sig, got, st.Fatal, tt.want)
			}
		})
	}
}

// WithTimeout must be suppressed for a signal when EITHER the generic or that
// signal's specific timeout variable is set, and applied otherwise. A
// _TRACES_TIMEOUT alone must not suppress it on the metrics exporter. LOGS
// gets its own row: it is the one signal that does NOT go through
// otlptracehttp/otlpmetrichttp's shared envconfig package -- otlploghttp has
// its own env lookup (config.go:60-61, 509-528) -- so nothing else in this
// table exercises that code path.
func TestTimeoutIsOperatorOverridable(t *testing.T) {
	tests := []struct {
		name, generic, traces, metrics, logs string
		wantTraces, wantMetrics, wantLogs    bool // true = apply our default
	}{
		{"nothing set", "", "", "", "", true, true, true},
		{"generic set", "30s", "", "", "", false, false, false},
		{"traces only", "", "30s", "", "", false, true, true},
		{"metrics only", "", "", "30s", "", true, false, true},
		{"logs only", "", "", "", "30s", true, true, false},
		// A whitespace-only value is what this function's own trim guards
		// against: the SDK trims and falls back to its 10s default, so
		// treating it as "set" here would suppress our tighter timeout and
		// let the untrimmed variable win nothing -- the operator's env var
		// would still be a dead key, just via a different mechanism.
		{"whitespace generic treated as unset", "  ", "", "", "", true, true, true},
		{"whitespace signal-specific treated as unset", "", "  ", "  ", "  ", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", tt.generic)
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", tt.traces)
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", tt.metrics)
			t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", tt.logs)
			if got := applyOurTimeout(signalTraces); got != tt.wantTraces {
				t.Errorf("TRACES: applyOurTimeout = %v, want %v", got, tt.wantTraces)
			}
			if got := applyOurTimeout(signalMetrics); got != tt.wantMetrics {
				t.Errorf("METRICS: applyOurTimeout = %v, want %v", got, tt.wantMetrics)
			}
			if got := applyOurTimeout(signalLogs); got != tt.wantLogs {
				t.Errorf("LOGS: applyOurTimeout = %v, want %v", got, tt.wantLogs)
			}
		})
	}
}
