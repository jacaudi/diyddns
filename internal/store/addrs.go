package store

import (
	"net/netip"
	"slices"
)

// ParseAddr normalises a stored address: Unmap so a 4-in-6 form and the bare
// form are one entry, WithZone("") so a zoned IPv6 can never render as an
// invalid CIDR. ok is false for "" or an unparseable value.
func ParseAddr(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// DedupeAddrs collects addrs into one sorted, deduplicated set (IPv4 before
// IPv6, then numeric) -- the gateway feed's dedup semantics (design #106),
// reused by any caller that needs the same "unique currently-known address"
// set rather than a per-device listing (#150). Callers parse each stored
// address with ParseAddr themselves and pass only the valid ones -- a corrupt
// or absent address is a caller's problem to drop, not this function's,
// since callers already need ParseAddr's ok result for their own per-device
// output (the feed's JSON device entries; see feed.Render).
func DedupeAddrs(addrs []netip.Addr) []netip.Addr {
	out := slices.Clone(addrs)
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// CIDRString renders a deduplicated address as a single-address CIDR (/32 for
// IPv4, /128 for IPv6) -- the wire format both the feed's devices.txt/json and
// the admin IP-list endpoint use, single-sourced here so the two audiences
// can never render the same address two different ways.
func CIDRString(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
