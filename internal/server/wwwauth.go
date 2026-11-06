package server

import (
	"net/http"
	"strings"
)

// RFC 9110 §15.5.2: "A server generating a 401 response MUST send at least one
// WWW-Authenticate header field containing at least one challenge applicable to
// the target resource." Before #191 no 401 carried one. The applicable challenge
// differs by route group (the three mounts assembled in buildMux): the agent API
// authenticates with the HMAC request-signing envelope, the feed authenticates a
// Bearer feed token, and the UI API accepts EITHER a Bearer API key OR a cookie
// session (which has no IANA-registered scheme, so a vendor scheme names it).
//
// Basic is deliberately NEVER advertised: a `WWW-Authenticate: Basic` on the UI
// API's fetch() 401s would make the browser pop its native credentials prompt
// over the passkey/OIDC web UI. Bearer and the vendor schemes below trigger no
// such prompt. The realm is a constant that names the server and leaks nothing;
// the uniform 401 body and the "reason to the log, never the client" rule (#100)
// are untouched — this adds a response header and nothing else.
const (
	challengeAgent   = `DIYDDNS-HMAC realm="diyddns"`
	challengeFeed    = `Bearer realm="diyddns"`
	challengeAPI     = `Bearer realm="diyddns", DIYDDNS-Session realm="diyddns"`
	challengeSession = `DIYDDNS-Session realm="diyddns"`
)

// challengeForPath returns the WWW-Authenticate challenge(s) for a request path's
// route group. Prefixes track the mounts: "/agent/v1" and "/api/v1" (api.go's
// humago.New groups) and "/feed/v1" (feed/handlers.go). Anything else is a
// server-rendered UI page, which authenticates by cookie session; it normally
// redirects to /login rather than answering 401, but a stray 401 there still
// gets a valid, non-Basic challenge rather than none.
func challengeForPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/agent/"):
		return challengeAgent
	case strings.HasPrefix(p, "/feed/"):
		return challengeFeed
	case strings.HasPrefix(p, "/api/"):
		return challengeAPI
	default:
		return challengeSession
	}
}

// wwwAuthenticate wraps a handler so every 401 it emits carries a
// WWW-Authenticate header (RFC 9110 §15.5.2). The challenge is chosen by route
// group from the request path; a 401 that already set the header (none do today)
// is left as it is, and no other status is touched. One interceptor covers all
// three 401 producers — the feed net/http middleware, the huma auth middleware,
// and the huma handler errors (huma.Error401Unauthorized in passkey/enroll) —
// none of which can set the header uniformly on their own.
func wwwAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&wwwAuthWriter{ResponseWriter: w, challenge: challengeForPath(r.URL.Path)}, r)
	})
}

// wwwAuthWriter injects the challenge on the first WriteHeader(401). It mirrors
// middleware.statusRecorder, including Unwrap: a WebSocket upgrade walks Unwrap
// looking for http.Hijacker (and http.ResponseController reaches Flush the same
// way), so the feed stream still upgrades through this layer. Headers must be
// set before the status is written, which is exactly when WriteHeader runs.
type wwwAuthWriter struct {
	http.ResponseWriter
	challenge string
	wrote     bool
}

func (w *wwwAuthWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code == http.StatusUnauthorized && w.challenge != "" && w.Header().Get("WWW-Authenticate") == "" {
			w.Header().Set("WWW-Authenticate", w.challenge)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *wwwAuthWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
