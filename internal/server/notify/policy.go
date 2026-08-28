// Package notify delivers outbound IP-change events to user-configured HTTPS
// endpoints. It owns the destination policy, the guarded HTTP clients, and the
// background delivery worker.
package notify

import (
	"errors"
	"fmt"
	"net/netip"
)

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// ErrDenied is returned (wrapped) by Permit for every rejection. The delivery
// worker classifies failures into six fixed classes and must distinguish a
// guard rejection from a connection error — but both surface as *net.OpError
// once they come back through Dialer.Control, so errors.Is on this sentinel is
// the only reliable discriminator. String matching on the message is not.
var ErrDenied = errors.New("notify: destination denied by policy")

// denied is the destination-policy table and the sole authority on what is
// reachable — there is no parallel prose rule (design §5.2.1). An address is
// DENIED if it is not global unicast, or if any prefix here contains it.
//
// The first two groups are transcribed from the IANA IPv4 and IPv6
// Special-Purpose Address Registries. The last three are NOT registry entries;
// each is retained because it is global unicast, would otherwise be reachable,
// and has no legitimate use as a target.
//
// This table is data on purpose: adding a newly-registered range is one line,
// and policy_test.go can drive it directly.
var denied = []netip.Prefix{
	// IANA IPv4 Special-Purpose Address Registry
	mp("0.0.0.0/8"), mp("10.0.0.0/8"), mp("100.64.0.0/10"), mp("127.0.0.0/8"),
	mp("169.254.0.0/16"), mp("172.16.0.0/12"), mp("192.0.0.0/24"), mp("192.0.2.0/24"),
	mp("192.31.196.0/24"), mp("192.52.193.0/24"), mp("192.88.99.0/24"), mp("192.168.0.0/16"),
	mp("192.175.48.0/24"), mp("198.18.0.0/15"), mp("198.51.100.0/24"), mp("203.0.113.0/24"),
	mp("240.0.0.0/4"),
	// IANA IPv6 Special-Purpose Address Registry
	mp("::1/128"), mp("::/128"), mp("::ffff:0:0/96"), mp("64:ff9b::/96"),
	mp("64:ff9b:1::/48"), mp("100::/64"), mp("100:0:0:1::/64"), mp("2001::/23"),
	mp("2001:db8::/32"), mp("2002::/16"), mp("2620:4f:8000::/48"), mp("3fff::/20"),
	mp("5f00::/16"), mp("fc00::/7"), mp("fe80::/10"),
	// Not registry entries.
	mp("::/96"),           // IPv4-compatible IPv6, deprecated RFC 4291
	mp("fec0::/10"),       // site-local, deprecated RFC 3879
	mp("::ffff:0:0:0/96"), // IPv4-translated, RFC 2765
}

// ParseAllowed converts operator-configured CIDR strings into prefixes.
// config.validateNotifications has already rejected malformed entries at
// startup; this re-parses rather than threading parsed values through config.
func ParseAllowed(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("notify: allowed prefix %q: %w", c, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Permit implements design §5.3's eight ordered steps. The order is
// load-bearing at two points and must not be rearranged:
//
//   - The zone check is FIRST. Prefix.Contains returns false for any zoned
//     address (net/netip: "Prefixes strip zones"), which fails closed against
//     an allow prefix but fails OPEN against `denied` — a zoned fec0::1%eth0
//     is global unicast and matches no entry. This check is the only thing
//     preventing that, not a corollary of anything.
//   - Unmap comes before both checks, so `denied` and `allowed` see the same
//     address. Without it an operator's 192.168.0.0/16 never matches a 4-in-6
//     target, because Contains is false for mapped forms.
func Permit(scheme string, a netip.Addr, allowed []netip.Prefix) error {
	if a.Zone() != "" { // 1
		return fmt.Errorf("%w: zoned address %s", ErrDenied, a)
	}
	a = a.Unmap() // 2

	if !containsAddr(allowed, a) { // 3 — operator override wins over 4 and 5
		if !a.IsGlobalUnicast() { // 4
			return fmt.Errorf("%w: %s is not global unicast", ErrDenied, a)
		}
		if p, ok := matchPrefix(denied, a); ok { // 5
			return fmt.Errorf("%w: %s denied by %s", ErrDenied, a, p)
		}
	}

	switch scheme { // 6, 7, 8
	case "https":
		return nil
	case "http":
		if a.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%w: http permitted only to loopback, got %s", ErrDenied, a)
	default:
		return fmt.Errorf("%w: unsupported scheme %q", ErrDenied, scheme)
	}
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	_, ok := matchPrefix(ps, a)
	return ok
}

func matchPrefix(ps []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	for _, p := range ps {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
