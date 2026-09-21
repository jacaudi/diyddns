package server

import (
	"net/http"
	"strings"
)

// nonWebUIPrefixes are this server's machine-consumed surfaces. An unmatched
// request under one of these must keep stdlib's exact 404 (and any real 405)
// untouched — never redirected to the browser-facing /login. See
// notFoundInterceptor's doc comment for the full reasoning (issue #168).
//
// This is intentionally the FOURTH place these prefixes are named (alongside
// api/api.go's groupConfig calls, feed's own route prefix, and server.go's
// existing comment) — a future new top-level machine surface (e.g.
// /metrics) must add itself here too, or its 404s will incorrectly redirect.
var nonWebUIPrefixes = []string{"/api/", "/agent/", "/feed/"}

func isWebUIPath(path string) bool {
	for _, p := range nonWebUIPrefixes {
		// p is always "/foo/"-shaped; also exclude the bare root "/foo"
		// (no trailing slash), or an unmatched request to it would fall
		// through to the webui redirect instead of staying stdlib's 404.
		if strings.HasPrefix(path, p) || path == strings.TrimSuffix(p, "/") {
			return false
		}
	}
	return true
}

// notFoundInterceptor wraps mux's ResponseWriter so a genuinely unmatched
// webui-space request can be redirected to /login (unauthenticated) or given
// the app's own 404 page (authenticated) instead of Go's stdlib default —
// without registering any new pattern on the shared http.ServeMux.
//
// A route-table catch-all ("/") was tried and rejected: on http.ServeMux, a
// bare method-less "/" pattern becomes a fallback match for ANY (method,
// path) not covered by a more specific pattern, not just unmatched ones —
// it silently converts every wrong-method request server-wide from 405 to
// whatever the catch-all answers, and swallows unauthenticated /api, /agent,
// /feed 404s into a redirect too. This type never touches route
// registration, so none of that applies: it only ever reacts to a response
// the real mux already decided, after the fact.
//
// The distinguishing signal is r.Pattern == "" combined with a 404 status:
// Go's ServeMux sets r.Pattern before dispatching to a handler, and leaves
// it empty ONLY when nothing matched (the same signal middleware.AccessLog
// already relies on to log an empty route on both 404 and 405). A route
// that DID match and chose to answer 404 for its own reasons (e.g. "device
// not found") has a non-empty r.Pattern and is left completely alone — this
// only intercepts a true "nothing matched" case, and only when it isn't
// under one of nonWebUIPrefixes.
type notFoundInterceptor struct {
	http.ResponseWriter
	r           *http.Request
	wroteHeader bool
	caught      bool
}

func (w *notFoundInterceptor) WriteHeader(code int) {
	// Once caught, the caught 404 stays fully suppressed (Write mirrors this
	// for the body) until notFound writes its own response. Every OTHER call
	// forwards to the real ResponseWriter on every invocation, including a
	// genuinely-superfluous repeat one — stdlib's own WriteHeader logs a
	// second call (and ignores it), and this wrapper must not silently
	// swallow it first just because it happens to sit in the chain.
	if w.caught {
		return
	}
	if !w.wroteHeader && code == http.StatusNotFound && w.r.Pattern == "" && isWebUIPath(w.r.URL.Path) {
		w.wroteHeader = true
		w.caught = true
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *notFoundInterceptor) Write(b []byte) (int, error) {
	if w.caught {
		return len(b), nil
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the wrapped writer, matching middleware.statusRecorder's
// own Unwrap (internal/server/middleware/middleware.go) — needed for the
// same reason: http.ResponseController and a WebSocket upgrade's Hijacker
// walk Unwrap to reach the real connection through any wrapper layer.
func (w *notFoundInterceptor) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// withNotFoundRedirect wraps mux so a genuinely-unmatched webui-space
// request gets notFound's treatment instead of stdlib's default 404 body.
// It must wrap mux directly (nothing between this and mux may call
// r.WithContext/r.Clone, or r.Pattern won't be visible on the same request —
// same constraint middleware.AccessLog documents in server.go's handler()).
func withNotFoundRedirect(mux http.Handler, notFound http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iw := &notFoundInterceptor{ResponseWriter: w, r: r}
		mux.ServeHTTP(iw, r)
		if iw.caught {
			// http.Error (what stdlib's swallowed 404 ran under the hood)
			// already set these on the real header map before WriteHeader was
			// called, since notFoundInterceptor embeds the real
			// http.ResponseWriter and Header() returns its live map. Strip
			// them so notFound's own response — a redirect or a rendered page
			// — isn't stuck with a stdlib-404 Content-Type it never chose.
			w.Header().Del("Content-Type")
			w.Header().Del("X-Content-Type-Options")
			notFound(w, r)
		}
	})
}
