package api

import (
	"net/http"
	"net/netip"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/server/clientip"
)

// observeMW resolves the origin address of each request with resolve (the
// per-listener policy: clientip.ObservedFromXFF on the main port,
// clientip.ObservedFromPeer on the agent listener) and carries it on the
// context for the check-in handler.
//
// It forwards through huma.WithContext, which wraps the huma context and leaves
// the *http.Request alone. Calling r.WithContext or r.Clone here would break
// AccessLog, which reads r.Pattern off the original request (see the hazard
// comment in server.go's handler) and the agent listener's r.TLS.
func observeMW(resolve func(*http.Request, []netip.Prefix) (netip.Addr, bool), trusted []netip.Prefix) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		addr, ok := resolve(r, trusted)
		var peer netip.Addr
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			peer = ap.Addr().Unmap()
		}
		next(huma.WithContext(ctx, clientip.WithObservation(ctx.Context(), clientip.Observation{Peer: peer, Addr: addr, OK: ok})))
	}
}
