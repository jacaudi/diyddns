// Package ipclass classifies IP addresses against the IANA special-purpose
// registries. It owns the one table that decides which addresses are not
// publicly routable, so every caller agrees on the answer.
package ipclass

import "net/netip"

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// table is the special-purpose address table. It backs both ipclass.Public and
// notify's Permit, and is the sole authority on what is reachable — there is no
// parallel prose rule. An address is special-purpose if it is not global
// unicast, or if any prefix here contains it.
//
// The first two groups are transcribed from the IANA IPv4 and IPv6
// Special-Purpose Address Registries. The last three are NOT registry entries;
// each is retained because it is global unicast, would otherwise be reachable,
// and has no legitimate use as a target.
//
// This table is data on purpose: adding a newly-registered range is one line.
// Re-check the IANA registries when they change.
var table = []netip.Prefix{
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

// SpecialPurpose reports the table prefix that contains a. The caller must
// have unmapped a already: Prefix.Contains is false for 4-in-6 and zoned
// forms, so they would escape the table.
func SpecialPurpose(a netip.Addr) (netip.Prefix, bool) {
	for _, p := range table {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// Public reports whether a is a global unicast address that no special-purpose
// registry claims. A zoned address is never public; the zone is checked before
// unmapping because Prefix.Contains is false for any zoned address, which would
// otherwise fail open against the table.
func Public(a netip.Addr) bool {
	if a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	_, special := SpecialPurpose(a)
	return !special
}
