package ipclass

import (
	"net/netip"
	"testing"
)

// Every prefix must be in masked form. This is NOT because Contains
// misbehaves on an unmasked prefix — netip.Prefix.Contains truncates both
// operands to the prefix length on the fly, so a masked and an unmasked
// prefix over the same network match identically (verified against Go's
// stdlib source and empirically). Masking is still correct practice: it
// keeps the table in canonical form, keeps error messages honest (the table
// has no parse step to mask through), and makes the prefixes safe as map
// keys, where an unmasked and masked prefix over the same network compare
// unequal.
func TestTableCanonical(t *testing.T) {
	for _, p := range table {
		if p.Masked() != p {
			t.Errorf("prefix %s is not masked (want %s)", p, p.Masked())
		}
	}
}

func TestPublic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"::ffff:8.8.8.8", true},

		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"192.0.0.9", false},
		{"192.0.0.10", false},
		{"192.0.2.1", false},
		{"192.31.196.1", false},
		{"192.52.193.1", false},
		{"192.88.99.1", false},
		{"192.175.48.1", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fec0::1", false},
		{"2001:db8::1", false},
		{"64:ff9b::808:808", false},
		{"2001::1", false},
		{"2001:1::1", false},
		{"2001:3::1", false},
		{"2001:4:112::1", false},
		{"2001:20::1", false},
		{"2001:30::1", false},
		{"2620:4f:8000::1", false},
		{"2002:808:808::1", false},
		// A zone is rejected before unmap: Prefix.Contains is false for any
		// zoned address, so a zoned special-purpose address would otherwise
		// escape the table.
		{"fec0::1%eth0", false},
		{"::ffff:8.8.8.8%eth0", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			if got := Public(netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Errorf("Public(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}

	t.Run("zero Addr", func(t *testing.T) {
		if Public(netip.Addr{}) {
			t.Error("Public(netip.Addr{}) = true, want false")
		}
	})
}

func TestSpecialPurpose(t *testing.T) {
	tests := []struct {
		addr   string
		want   string
		wantOK bool
	}{
		{"192.0.2.1", "192.0.2.0/24", true},
		{"64:ff9b::808:808", "64:ff9b::/96", true},
		{"8.8.8.8", "", false},
		{"2606:4700:4700::1111", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got, ok := SpecialPurpose(netip.MustParseAddr(tc.addr))
			if ok != tc.wantOK {
				t.Fatalf("SpecialPurpose(%s) ok = %v, want %v", tc.addr, ok, tc.wantOK)
			}
			if tc.wantOK && got != netip.MustParsePrefix(tc.want) {
				t.Errorf("SpecialPurpose(%s) = %s, want %s", tc.addr, got, tc.want)
			}
		})
	}
}
