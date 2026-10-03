package logtest_test

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/logtest"
)

// sample is three records as slog's JSON handler writes them, with a blank
// line between the first two.
const sample = `{"level":"INFO","msg":"a","n":1}

{"level":"ERROR","msg":"b"}
{"level":"INFO","msg":"a","n":2}
`

// fatalRecorder is a testing.TB that records a Fatalf instead of stopping the
// test, so the helpers' failure paths can be asserted. The helpers call only
// Helper and Fatalf; any other method would panic on the nil embedded TB.
type fatalRecorder struct {
	testing.TB
	failed bool
}

func (*fatalRecorder) Helper() {}

func (f *fatalRecorder) Fatalf(string, ...any) { f.failed = true }

func TestRecords_DecodesEveryLineAndSkipsBlanks(t *testing.T) {
	recs := logtest.Records(t, sample)

	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3: %v", len(recs), recs)
	}
	if recs[1]["level"] != "ERROR" || recs[1]["msg"] != "b" {
		t.Errorf("records[1] = %v, want the ERROR record b", recs[1])
	}
	if got := logtest.Records(t, ""); len(got) != 0 {
		t.Errorf("an empty log decoded to %v, want no records", got)
	}
}

func TestFind_ReturnsTheFirstRecordWithTheMessage(t *testing.T) {
	if got := logtest.Find(t, sample, "a")["n"]; got != float64(1) {
		t.Errorf(`Find(sample, "a")["n"] = %v, want 1 (the first match)`, got)
	}
}

func TestHelpers_FailTheTestOnBadInput(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(t testing.TB)
	}{
		{"Records on a line that is not JSON", func(t testing.TB) { logtest.Records(t, sample+"not json\n") }},
		{"Find with no record carrying the message", func(t testing.TB) { logtest.Find(t, sample, "c") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := &fatalRecorder{}
			tt.call(rec)
			if !rec.failed {
				t.Error("the helper did not fail the test")
			}
		})
	}
}
