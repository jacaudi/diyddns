package telemetry

import (
	"os"
	"regexp"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// resourceDefaultCallSite matches resource.Default() and
// resource.DefaultWithContext(: both share the same package-level
// defaultResourceOnce (sdk@v1.46.0/resource/resource.go:43, :254). A plain
// substring match on "resource.Default" would also fire on prose mentioning
// the name (see buildResource's doc comment), so this matches call syntax --
// the "(" immediately following -- not commentary.
var resourceDefaultCallSite = regexp.MustCompile(`resource\.Default(\(\)|WithContext\()`)

func serviceName(t *testing.T, cfg config.OTLPSection) string {
	t.Helper()
	res, st := buildResource(t.Context(), cfg, version.Info{Version: "v1.2.3"})
	if st.Fatal {
		t.Fatalf("buildResource: %s", st.Reason)
	}
	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceNameKey {
			return kv.Value.AsString()
		}
	}
	return ""
}

// YAML wins over both environment forms.
func TestBuildResource_YAMLWins(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=from-attrs")
	if got := serviceName(t, config.OTLPSection{ServiceName: "from-yaml"}); got != "from-yaml" {
		t.Errorf("service.name = %q, want from-yaml", got)
	}
}

// Empty YAML defers to OTEL_SERVICE_NAME.
func TestBuildResource_EnvWins(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	if got := serviceName(t, config.OTLPSection{}); got != "from-env" {
		t.Errorf("service.name = %q, want from-env", got)
	}
}

// Empty YAML also defers to service.name inside OTEL_RESOURCE_ATTRIBUTES.
// Testing only OTEL_SERVICE_NAME would let the fallback silently override this.
//
// OTEL_SERVICE_NAME is cleared explicitly: the SDK gives it precedence over
// OTEL_RESOURCE_ATTRIBUTES (env.go:54-56), so an ambient OTEL_SERVICE_NAME
// left set in a developer's shell would make this test pass for the wrong
// reason.
func TestBuildResource_ResourceAttributesWins(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=from-attrs,deployment.environment=prod")
	if got := serviceName(t, config.OTLPSection{}); got != "from-attrs" {
		t.Errorf("service.name = %q, want from-attrs", got)
	}
}

// The SDK's OTEL_RESOURCE_ATTRIBUTES parser splits on ",", cuts on "=", then
// TrimSpaces the key (env.go:71-88) -- so "service.name = spaced-name" is a
// valid way to set it. A substring match on "service.name=" (no space) misses
// this and lets the "diyddns" fallback silently override the operator.
func TestBuildResource_SpacedKeyInResourceAttributes(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name = spaced-name")
	if got := serviceName(t, config.OTLPSection{}); got != "spaced-name" {
		t.Errorf("service.name = %q, want spaced-name", got)
	}
}

// A key that merely CONTAINS "service.name=" as a substring, such as
// "k8s.service.name=...", is not service.name. A substring match treats it as
// if service.name were set and skips the mandatory fallback, leaving no
// service.name key at all -- exactly what the fallback exists to prevent.
func TestBuildResource_SuffixKeyIsNotServiceName(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "k8s.service.name=some-k8s-svc")
	if got := serviceName(t, config.OTLPSection{}); got != "diyddns" {
		t.Errorf("service.name = %q, want diyddns (fallback)", got)
	}
}

// With neither, the explicit fallback applies. It is MANDATORY: resource.New
// with an explicit detector set does not include defaultServiceNameDetector,
// and no WithResource implementation falls back to it -- all three merge only
// resource.Environment() underneath. Without the fallback there is no
// service.name key AT ALL, which is worse than a placeholder.
func TestBuildResource_FallbackWhenNothingSet(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	if got := serviceName(t, config.OTLPSection{}); got != "diyddns" {
		t.Errorf("service.name = %q, want diyddns", got)
	}
}

// The schema URLs must agree or Merge yields a SCHEMALESS resource.
func TestBuildResource_SchemaMergesCleanly(t *testing.T) {
	res, st := buildResource(t.Context(), config.OTLPSection{}, version.Info{Version: "v1.2.3"})
	if st.Fatal {
		t.Fatalf("buildResource: %s", st.Reason)
	}
	if got := res.SchemaURL(); got != semconv.SchemaURL {
		t.Errorf("SchemaURL = %q, want %q -- the semconv import and the SDK have drifted", got, semconv.SchemaURL)
	}
}

// resource.Default (and resource.DefaultWithContext, which shares the same
// memoization) is memoized process-wide; this design must not call either.
// A grep test is cheap and pins the rule where a comment would not.
func TestBuildResource_DoesNotUseResourceDefault(t *testing.T) {
	src, err := os.ReadFile("resource.go")
	if err != nil {
		t.Fatalf("read resource.go: %v", err)
	}
	if resourceDefaultCallSite.Match(src) {
		t.Error("resource.Default() and resource.DefaultWithContext() are memoized by a package-level sync.Once; use resource.New")
	}
}

// A partial resource (resource.New returning an error alongside a usable
// Resource, e.g. one malformed OTEL_RESOURCE_ATTRIBUTES pair) is NOT a
// degradation: Status must stay zero, or a healthy server logs
// "telemetry not exporting" at every boot.
func TestBuildResource_PartialResourceIsNotFatal(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "badpair")
	res, st := buildResource(t.Context(), config.OTLPSection{}, version.Info{Version: "v1.2.3"})
	if st != (Status{}) {
		t.Errorf("Status = %+v, want zero Status -- a partial resource is usable, not a failure", st)
	}
	if res == nil {
		t.Fatal("buildResource returned a nil resource alongside a zero Status")
	}
}

// WithTelemetrySDK is what contributes the SDK-side schema URL: WithFromEnv
// alone returns a schemaless resource (env.go:49,94), so
// TestBuildResource_SchemaMergesCleanly only holds transitively on this
// option. Assert the attribute directly so deleting WithTelemetrySDK fails
// loudly here instead of only hollowing out an unrelated test.
func TestBuildResource_IncludesTelemetrySDKName(t *testing.T) {
	res, st := buildResource(t.Context(), config.OTLPSection{}, version.Info{Version: "v1.2.3"})
	if st.Fatal {
		t.Fatalf("buildResource: %s", st.Reason)
	}
	if _, ok := res.Set().Value(semconv.TelemetrySDKNameKey); !ok {
		t.Error("telemetry.sdk.name missing -- WithTelemetrySDK() was dropped")
	}
}

// info.Version exists to become service.version; nothing else pins it.
func TestBuildResource_IncludesServiceVersion(t *testing.T) {
	res, st := buildResource(t.Context(), config.OTLPSection{}, version.Info{Version: "v1.2.3"})
	if st.Fatal {
		t.Fatalf("buildResource: %s", st.Reason)
	}
	val, ok := res.Set().Value(semconv.ServiceVersionKey)
	if !ok || val.AsString() != "v1.2.3" {
		t.Errorf("service.version = (%q, %v), want (v1.2.3, true)", val.AsString(), ok)
	}
}
