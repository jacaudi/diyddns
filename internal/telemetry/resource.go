package telemetry

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"

	// MUST match the semconv version the SDK's own detectors carry
	// (sdk@v1.46.0/resource/builtin.go:16). resource.Merge returns
	// ErrSchemaURLConflict AND a schemaless resource when they disagree, so a
	// drift here exports telemetry with no schema and nothing fails loudly.
	// If the SDK is upgraded, this import moves with it.
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// buildResource assembles the OTel Resource every signal is stamped with. res
// is nil when Status.Fatal is true; callers must check Fatal first.
//
// It uses resource.New, NEVER resource.Default: Default is memoized by a
// package-level sync.Once (sdk@v1.46.0/resource/resource.go:43, :254), so the
// environment is read once per process at whatever moment something first
// calls it -- which makes t.Setenv a no-op in tests and makes the result
// depend on test order.
func buildResource(ctx context.Context, cfg config.OTLPSection, info version.Info) (*resource.Resource, Status) {
	// WithHost() is deliberately absent: host.name would be exported to
	// whatever third-party backend the operator points at, and no present
	// requirement names it. Same posture as design D8, which keeps device and
	// user ids off spans.
	//
	// The error is deliberately discarded: resource.New returns the PARTIAL
	// resource alongside it, and a partial resource is usable. This is NOT a
	// degradation: Status stays zero so serveCmd does not log "telemetry not
	// exporting" on a healthy server.
	base, _ := resource.New(ctx, resource.WithFromEnv(), resource.WithTelemetrySDK())

	// Ask the resource the SDK already built instead of re-implementing its
	// OTEL_RESOURCE_ATTRIBUTES parser. A substring match on "service.name="
	// is lossy in both directions: the SDK's parser splits on ",", cuts on
	// "=", then TrimSpaces the key (env.go:71-88), so "service.name =
	// spaced-name" is valid and a substring match misses it -- and
	// "k8s.service.name=..." merely CONTAINS "service.name=" without BEING
	// service.name, which a substring match wrongly treats as already set.
	var attrs []attribute.KeyValue
	switch {
	case cfg.ServiceName != "":
		// A non-empty YAML value wins over the environment.
		attrs = append(attrs, semconv.ServiceName(cfg.ServiceName))
	default:
		if _, ok := base.Set().Value(semconv.ServiceNameKey); !ok {
			// Mandatory. resource.New's explicit detector set has no
			// defaultServiceNameDetector, and no WithResource implementation
			// falls back to one -- all three merge only
			// resource.Environment() underneath (sdk/trace/provider.go:389,
			// sdk/metric/config.go:118, sdk/log/provider.go:287). Without
			// this branch there is no service.name key at all.
			attrs = append(attrs, semconv.ServiceName("diyddns"))
		}
	}
	attrs = append(attrs, semconv.ServiceVersion(info.Version))

	res, err := resource.Merge(base, resource.NewWithAttributes(semconv.SchemaURL, attrs...))
	if err != nil {
		// A schema-URL conflict means this package's semconv import and the SDK
		// have drifted apart: a programming error, clause (b) of THE FATAL RULE.
		return nil, Status{Reason: fmt.Sprintf("telemetry: resource merge: %v", err), Fatal: true}
	}
	return res, Status{}
}
