package store

import (
	"net/netip"
	"testing"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // "" means ok should be false
	}{
		{name: "empty string is absent", in: "", want: ""},
		{name: "malformed value is absent", in: "not-an-ip", want: ""},
		{name: "plain IPv4", in: "203.0.113.9", want: "203.0.113.9"},
		{name: "4-in-6 mapped form unmaps to bare IPv4", in: "::ffff:203.0.113.9", want: "203.0.113.9"},
		{name: "zoned IPv6 has its zone stripped", in: "fe80::1%eth0", want: "fe80::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseAddr(tt.in)
			if tt.want == "" {
				if ok {
					t.Fatalf("ParseAddr(%q) ok = true, want false", tt.in)
				}
				return
			}
			if !ok {
				t.Fatalf("ParseAddr(%q) ok = false, want true", tt.in)
			}
			if got.String() != tt.want {
				t.Errorf("ParseAddr(%q) = %q, want %q", tt.in, got.String(), tt.want)
			}
		})
	}
}

func TestDedupeAddrs(t *testing.T) {
	tests := []struct {
		name  string
		addrs []netip.Addr
		want  []string
	}{
		{
			name:  "empty input yields empty output",
			addrs: nil,
			want:  nil,
		},
		{
			name: "duplicate address across two devices collapses to one",
			addrs: []netip.Addr{
				netip.MustParseAddr("203.0.113.9"),
				netip.MustParseAddr("203.0.113.9"),
			},
			want: []string{"203.0.113.9"},
		},
		{
			name: "IPv4 sorts before IPv6, each numeric",
			addrs: []netip.Addr{
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("203.0.113.9"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("198.51.100.1"),
			},
			want: []string{"198.51.100.1", "203.0.113.9", "2001:db8::1", "2001:db8::2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DedupeAddrs(tt.addrs)
			if len(got) != len(tt.want) {
				t.Fatalf("DedupeAddrs() = %v, want %v", got, tt.want)
			}
			for i, a := range got {
				if a.String() != tt.want[i] {
					t.Errorf("DedupeAddrs()[%d] = %q, want %q", i, a.String(), tt.want[i])
				}
			}
		})
	}
}

func TestCIDRString(t *testing.T) {
	tests := []struct {
		name string
		in   netip.Addr
		want string
	}{
		{name: "IPv4 gets a /32", in: netip.MustParseAddr("203.0.113.9"), want: "203.0.113.9/32"},
		{name: "IPv6 gets a /128", in: netip.MustParseAddr("2001:db8::1"), want: "2001:db8::1/128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CIDRString(tt.in); got != tt.want {
				t.Errorf("CIDRString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
