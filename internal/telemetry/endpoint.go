package telemetry

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// otlpSignal pairs a signal's env-var infix with its OTLP path. One value, so
// a call site cannot get the two halves out of step, and cannot pass a name
// the SDK does not read -- a bare string parameter fails silent-open: a wrong
// literal ("Traces", "TRACE", "") makes applyOurTimeout return true and turns
// the operator's env var into a dead key, the exact bug this package exists
// to prevent.
type otlpSignal struct{ name, path string }

var (
	signalTraces  = otlpSignal{"TRACES", "/v1/traces"}
	signalMetrics = otlpSignal{"METRICS", "/v1/metrics"}
	signalLogs    = otlpSignal{"LOGS", "/v1/logs"}
)

// signalEndpoint turns the operator's collector base URL into the full
// per-signal endpoint an otlp*http exporter needs, or returns a Fatal Status.
//
// No exporter option has the environment variable's semantics:
// WithEndpointURL uses the path AS-IS and does NOT append the default signal
// path (otlptracehttp@v1.46.0/options.go:106-109), while WithEndpoint takes a
// host:port and defaults to TLS (options.go:79). The environment variable
// joins the path itself (internal/otlpconfig/envconfig.go:56-60). So this
// function does the join, and the caller passes WithEndpointURL.
//
// The url.Parse guard is the load-bearing part. url.JoinPath errors only on
// input url.Parse itself rejects, which almost nothing is: "otel-collector:4318"
// joins cleanly, parses as an OPAQUE url with an empty Host, and the exporter
// then POSTs to "http:///" forever while Shutdown reports success.
func signalEndpoint(raw string, sig otlpSignal) (string, Status) {
	// TrimSpace FIRST: an endpoint sourced from a k8s secret or an --env-file
	// routinely carries a trailing newline, and design D5 forbids that being
	// the reason this server refuses to start. The SDK trims too
	// (resource/env.go:39-40).
	endpoint := strings.TrimSpace(raw)

	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", Status{
			Reason: fmt.Sprintf(
				"telemetry: observability.otlp.endpoint %q must be an absolute http:// or https:// URL with a host",
				raw),
			Fatal: true,
		}
	}

	// A base that already ends in the signal's path would otherwise be
	// silently doubled -- "http://h:4318/v1/traces" joined with "/v1/traces"
	// posts to "/v1/traces/v1/traces", 404s, and retries forever while
	// Shutdown still reports success. Plausible input: the sibling
	// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT variable IS specified as a full
	// per-signal path, and an operator can reuse that value here.
	if strings.HasSuffix(u.Path, sig.path) {
		return "", Status{
			Reason: fmt.Sprintf(
				"telemetry: observability.otlp.endpoint %q already ends in %s; set it to the collector's base URL, not a per-signal endpoint",
				raw, sig.path),
			Fatal: true,
		}
	}

	// JoinPath errors only when Parse(endpoint) itself would reject the
	// joined result -- endpoint already parsed successfully above, and
	// sig.path is one of three fixed literals, so this cannot fail. Fuzzed
	// 18,012,248 times in Task 4 review round 1 with zero reaches.
	joined, _ := url.JoinPath(endpoint, sig.path)
	return joined, Status{}
}

// applyOurTimeout reports whether this package should pass its own
// WithTimeout for sig.
//
// An explicitly passed option overrides the environment, so passing
// WithTimeout unconditionally would make OTEL_EXPORTER_OTLP_TIMEOUT and its
// per-signal variants dead keys (otlptracehttp's shared
// .../otlpconfig/envconfig.go:105-106; otlploghttp has no envconfig package
// and does its own lookup at config.go:60-61, 509-528). The per-attempt
// timeout is the one shutdown-budget input an operator can tune, so it must
// stay tunable -- see the note on the shutdown guarantee in Task 7.
//
// Both lookups are trimmed: a whitespace-only value (the same k8s-secret /
// --env-file origin as the endpoint above) is not "set" to the SDK either --
// traces/metrics fall back to their untrimmed-parse-failure default of 10s
// (otlpconfig/envconfig.go:45-48, options.go:39), and otlploghttp's
// convDuration fails the same way (config.go:517) -- so treating it as unset
// here keeps our tighter timeout in force instead of silently losing most of
// the shutdown budget to that 10s fallback.
func applyOurTimeout(sig otlpSignal) bool {
	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TIMEOUT")) != "" {
		return false
	}
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_"+sig.name+"_TIMEOUT")) == ""
}
