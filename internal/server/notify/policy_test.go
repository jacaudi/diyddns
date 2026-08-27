package notify

import (
	"errors"
	"net/netip"
	"testing"
)

// Every prefix must be in masked form, or Contains silently misbehaves.
func TestDeniedTableIsMasked(t *testing.T) {
	for _, p := range denied {
		if p.Masked() != p {
			t.Errorf("prefix %s is not masked (want %s)", p, p.Masked())
		}
	}
}

func TestPermit(t *testing.T) {
	tests := []struct {
		name, addr, scheme string
		allowed            []string
		wantErr            bool
	}{
		// The four forms an enumerated denylist missed (design §5.2.1).
		{"nat64 metadata", "64:ff9b::a9fe:a9fe", "https", nil, true},
		{"6to4 loopback", "2002:7f00:1::1", "https", nil, true},
		{"v4-compatible", "::7f00:1", "https", nil, true},
		{"0.0.0.0/8", "0.1.2.3", "https", nil, true},
		// IPv4-translated, RFC 2765 — also not a registry entry.
		{"v4-translated loopback", "::ffff:0:7f00:1", "https", nil, true},
		{"v4-translated metadata", "::ffff:0:a9fe:a9fe", "https", nil, true},
		// Zoned forms are global unicast AND escape every prefix, because
		// Prefix.Contains is false for zoned addrs. Step 1 is what stops them.
		{"zoned site-local", "fec0::1%eth0", "https", nil, true},
		{"zoned nat64", "64:ff9b::a9fe:a9fe%eth0", "https", nil, true},
		{"zoned 6to4", "2002:7f00:1::1%eth0", "https", nil, true},
		// Classics.
		{"metadata", "169.254.169.254", "https", nil, true},
		{"rfc1918", "192.168.1.50", "https", nil, true},
		{"cgnat", "100.64.1.1", "https", nil, true},
		{"loopback", "127.0.0.1", "https", nil, true},
		{"ula", "fd00::1", "https", nil, true},
		{"multicast", "224.0.0.1", "https", nil, true},
		{"unspecified", "0.0.0.0", "https", nil, true},
		// Legitimate targets.
		{"public v4", "8.8.8.8", "https", nil, false},
		{"public v4 mapped", "::ffff:8.8.8.8", "https", nil, false},
		{"public v6", "2606:4700:4700::1111", "https", nil, false},
		// Scheme composition (design §5.3 steps 6-8).
		{"http to public denied", "8.8.8.8", "http", nil, true},
		{"http to loopback, not allowed", "127.0.0.1", "http", nil, true},
		{"http to loopback, allowed", "127.0.0.1", "http", []string{"127.0.0.0/8"}, false},
		{"http to LAN, LAN allowed", "192.168.1.50", "http", []string{"192.168.0.0/16"}, true},
		{"https to LAN, LAN allowed", "192.168.1.50", "https", []string{"192.168.0.0/16"}, false},
		{"unknown scheme", "8.8.8.8", "ftp", nil, true},
		// Operator override beats the global-unicast leg too (design §5.2.3).
		{"multicast re-permitted", "224.0.0.1", "https", []string{"224.0.0.0/4"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := ParseAllowed(tc.allowed)
			if err != nil {
				t.Fatalf("ParseAllowed: %v", err)
			}
			a, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tc.addr, err)
			}
			err = Permit(tc.scheme, a, allowed)
			if (err != nil) != tc.wantErr {
				t.Errorf("Permit(%q, %s) err = %v, wantErr = %v", tc.scheme, tc.addr, err, tc.wantErr)
			}
		})
	}
}

// The worker classifies on this sentinel, so it must survive wrapping through
// net.Dialer.Control and out of http.Client.Do.
func TestPermit_ErrorsWrapErrDenied(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "169.254.169.254", "fec0::1%eth0"} {
		a := netip.MustParseAddr(addr)
		err := Permit("https", a, nil)
		if err == nil {
			t.Fatalf("Permit(%s) = nil, want denial", addr)
		}
		if !errors.Is(err, ErrDenied) {
			t.Errorf("Permit(%s) error does not wrap ErrDenied: %v", addr, err)
		}
	}
}

func TestParseAllowed_RejectsGarbage(t *testing.T) {
	if _, err := ParseAllowed([]string{"nonsense"}); err == nil {
		t.Fatal("ParseAllowed accepted garbage")
	}
}
