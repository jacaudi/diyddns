// Package notify delivers outbound device events to admin-configured HTTPS
// endpoints. It owns the destination policy, the guarded HTTP clients, and the
// background delivery worker.
package notify

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/jacaudi/diyddns/internal/shared/ipclass"
)

// ErrDenied is returned (wrapped) by Permit for every rejection. The delivery
// worker classifies failures into six fixed classes and must distinguish a
// guard rejection from a connection error — but both surface as *net.OpError
// once they come back through Dialer.Control, so errors.Is on this sentinel is
// the only reliable discriminator. String matching on the message is not.
var ErrDenied = errors.New("notify: destination denied by policy")

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
//     an allow prefix but fails OPEN against the special-purpose table — a zoned fec0::1%eth0
//     is global unicast and matches no entry. This check is the only thing
//     preventing that, not a corollary of anything.
//   - Unmap comes before both checks, so the table and `allowed` see the same
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
		if p, ok := ipclass.SpecialPurpose(a); ok { // 5
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
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a) })
}
