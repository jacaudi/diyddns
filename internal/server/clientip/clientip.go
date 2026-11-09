// Package clientip resolves the network origin of a request: the peer itself,
// or, when the peer is a trusted proxy, the origin named by X-Forwarded-For.
// The result is the server-observed address; it never comes from anything the
// client alone controls.
package clientip

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// Trusted reports whether a is inside any prefix of list. a is normalized
// first: a 4-in-6 address (a dual-stack listener reports an IPv4 peer that
// way) is unmapped, because netip.Prefix.Contains never matches a 4-in-6
// address against an IPv4 prefix; and a zone is dropped, because Contains
// never matches a zoned address against anything.
func Trusted(a netip.Addr, list []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	return slices.ContainsFunc(list, func(p netip.Prefix) bool { return p.Contains(a) })
}

// peer parses r.RemoteAddr and unmaps it.
func peer(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// ObservedFromPeer returns the connection peer as the observed address. A
// trusted peer is a proxy, not an origin, and an unparseable RemoteAddr names
// nothing; both yield no observation.
func ObservedFromPeer(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	a, ok := peer(r)
	if !ok || Trusted(a, trusted) {
		return netip.Addr{}, false
	}
	return a, true
}

// ObservedFromXFF returns the origin of r. An untrusted peer is the origin.
// For a trusted peer the X-Forwarded-For entries, across every header line,
// are walked right to left: trusted entries are skipped and the first
// untrusted one is the origin. A malformed entry (including one with a port),
// an empty header, or a header of only trusted entries yields no observation;
// a trusted address is never returned.
func ObservedFromXFF(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	p, ok := peer(r)
	if !ok {
		return netip.Addr{}, false
	}
	if !Trusted(p, trusted) {
		return p, true
	}
	var entries []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for e := range strings.SplitSeq(line, ",") {
			entries = append(entries, strings.TrimSpace(e))
		}
	}
	for _, e := range slices.Backward(entries) {
		a, err := netip.ParseAddr(e)
		if err != nil {
			return netip.Addr{}, false
		}
		if a = a.Unmap(); !Trusted(a, trusted) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// AuditIP is the address recorded in audit logs: r.RemoteAddr verbatim unless
// the peer is a trusted proxy and X-Forwarded-For names an origin, then that
// origin.
func AuditIP(r *http.Request, trusted []netip.Prefix) string {
	if p, ok := peer(r); ok && Trusted(p, trusted) {
		if a, ok := ObservedFromXFF(r, trusted); ok {
			return a.String()
		}
	}
	return r.RemoteAddr
}

// Observation is the resolved origin of one request. OK is false when no
// origin could be determined; Peer is the unmapped connection peer, kept for
// diagnostics.
type Observation struct {
	Peer, Addr netip.Addr
	OK         bool
}

type ctxKey struct{}

// WithObservation returns ctx carrying o.
func WithObservation(ctx context.Context, o Observation) context.Context {
	return context.WithValue(ctx, ctxKey{}, o)
}

// ObservationFrom returns the Observation in ctx, or the zero value (OK false)
// when there is none.
func ObservationFrom(ctx context.Context) Observation {
	o, _ := ctx.Value(ctxKey{}).(Observation)
	return o
}
