package service

import (
	"log/slog"
	"testing"

	"github.com/jacaudi/diyddns/internal/logtest"
)

// captureLog returns a JSON logger at Debug and the buffer it writes to, for
// tests that assert on the records a service emits.
func captureLog() (*slog.Logger, *lockedBuffer) {
	var buf lockedBuffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// reset discards everything logged so far, so a test can set up with the
// capture logger and then assert only on the step under test.
func (b *lockedBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// logRecords decodes every line written to buf.
func logRecords(t *testing.T, buf *lockedBuffer) []map[string]any {
	t.Helper()
	return logtest.Records(t, buf.String())
}

// onlyRecord asserts buf holds exactly one line, at level with message msg, and
// returns it.
func onlyRecord(t *testing.T, buf *lockedBuffer, level, msg string) map[string]any {
	t.Helper()
	recs := logRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("log lines = %d, want exactly 1 (%q at %s):\n%s", len(recs), msg, level, buf.String())
	}
	if recs[0]["level"] != level || recs[0]["msg"] != msg {
		t.Fatalf("log line = %s/%q, want %s/%q:\n%s", recs[0]["level"], recs[0]["msg"], level, msg, buf.String())
	}
	return recs[0]
}
