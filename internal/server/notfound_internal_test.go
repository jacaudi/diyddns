package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// countingWriter records every WriteHeader call it receives, including
// repeats — unlike httptest.ResponseRecorder, which (correctly, matching a
// real connection) keeps only the first code and silently no-ops on a
// superfluous second call. That makes ResponseRecorder unsuitable for
// proving a call reached the underlying writer at all; this fake exists only
// to make that call count observable.
type countingWriter struct {
	http.ResponseWriter
	codes []int
}

func (w *countingWriter) WriteHeader(code int) {
	w.codes = append(w.codes, code)
	w.ResponseWriter.WriteHeader(code)
}

// TestNotFoundInterceptor_WriteHeader_ForwardsSuperfluousCall pins Fix 4: a
// non-caught WriteHeader call must forward to the underlying ResponseWriter
// on every call, including a genuinely-superfluous second one, exactly as it
// would without this wrapper — not just on the first. wroteHeader/caught
// exist to latch the ONE caught 404, not to swallow unrelated repeat calls
// server-wide.
func TestNotFoundInterceptor_WriteHeader_ForwardsSuperfluousCall(t *testing.T) {
	cw := &countingWriter{ResponseWriter: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/devices/x", nil)
	req.Pattern = "GET /devices/{id}" // matched route, never eligible to be caught
	iw := &notFoundInterceptor{ResponseWriter: cw, r: req}

	iw.WriteHeader(http.StatusOK)
	iw.WriteHeader(http.StatusTeapot) // superfluous, but must still reach cw

	want := []int{http.StatusOK, http.StatusTeapot}
	if len(cw.codes) != len(want) || cw.codes[0] != want[0] || cw.codes[1] != want[1] {
		t.Errorf("underlying WriteHeader calls = %v, want %v (second call must forward, not be silently dropped)", cw.codes, want)
	}
}
