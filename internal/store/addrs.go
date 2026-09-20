package store

import (
	"net/netip"
	"slices"
)

// AddrPair is the raw IPv4/IPv6 address strings one device row carries -- ""
// when a family has never been reported (the same NULL-as-empty-string
// convention this package's scan helpers apply when reading these columns).
// It is the minimal shape DedupeAddrs needs, so both FeedDevice and Device
// rows can be adapted to it without either type depending on the other.
type AddrPair struct {
	IPv4 string
	IPv6 string
}

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

// DedupeAddrs collects every valid address across pairs into one sorted,
// deduplicated set (IPv4 before IPv6, then numeric) -- the gateway feed's
// dedup semantics (design #106), reused by any caller that needs the same
// "unique currently-known address" set rather than a per-device listing
// (#150). A corrupt or absent address is dropped, never an error: one bad
// row must not fail the whole set.
func DedupeAddrs(pairs []AddrPair) []netip.Addr {
	addrs := make([]netip.Addr, 0, 2*len(pairs))
	for _, p := range pairs {
		if a, ok := ParseAddr(p.IPv4); ok {
			addrs = append(addrs, a)
		}
		if a, ok := ParseAddr(p.IPv6); ok {
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// CIDRString renders a deduplicated address as a single-address CIDR (/32 for
// IPv4, /128 for IPv6) -- the wire format both the feed's devices.txt/json and
// the admin IP-list endpoint use, single-sourced here so the two audiences
// can never render the same address two different ways.
func CIDRString(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
