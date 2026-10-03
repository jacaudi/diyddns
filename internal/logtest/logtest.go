// Package logtest decodes the JSON lines slog's JSON handler writes, for tests
// that assert on log records. It is a real package, not a _test.go file, so
// internal and external test packages alike can import it.
package logtest

import (
	"encoding/json"
	"strings"
	"testing"
)

// Records decodes every non-blank line of log as one JSON record, failing t on
// a line that is not JSON.
func Records(t testing.TB, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(log), "\n") {
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

// Find returns the first record in log whose msg is msg, failing t if there is
// none.
func Find(t testing.TB, log, msg string) map[string]any {
	t.Helper()
	for _, rec := range Records(t, log) {
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no record with msg %q in:\n%s", msg, log)
	return nil
}
