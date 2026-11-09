package clientip_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/clientip"
)

var trusted10 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

// request builds a request from remote with one X-Forwarded-For header line
// per xff element.
func request(t *testing.T, remote string, xff ...string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestTrusted(t *testing.T) {
	tests := []struct {
		name string
		addr string
		list []netip.Prefix
		want bool
	}{
		{"4-in-6 inside v4 prefix", "::ffff:10.0.0.5", trusted10, true},
		{"outside prefix", "11.0.0.1", trusted10, false},
		{"empty list", "10.0.0.5", nil, false},
		{"zoned v6 inside prefix", "fe80::1%eth0", []netip.Prefix{netip.MustParsePrefix("fe80::/10")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientip.Trusted(netip.MustParseAddr(tt.addr), tt.list)
			if got != tt.want {
				t.Errorf("Trusted(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestObservedFromXFF(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string // empty means no observation
	}{
		{"untrusted peer is the observation", "203.0.113.9:1", []string{"1.1.1.1"}, "203.0.113.9"},
		{"trusted peer, single entry", "10.0.0.2:5", []string{"1.1.1.1"}, "1.1.1.1"},
		{"trusted hop skipped right to left", "10.0.0.2:5", []string{"9.9.9.9, 1.1.1.1, 10.0.0.3"}, "1.1.1.1"},
		{"rightmost untrusted wins over a spoofed left entry", "10.0.0.2:5", []string{"9.9.9.9", "1.1.1.1"}, "1.1.1.1"},
		{"entry with a port", "10.0.0.2:5", []string{"1.1.1.1:443"}, ""},
		{"garbage entry", "10.0.0.2:5", []string{"garbage"}, ""},
		{"garbage rightmost hides a good left entry", "10.0.0.2:5", []string{"1.1.1.1, garbage"}, ""},
		{"empty entry", "10.0.0.2:5", []string{"1.1.1.1,"}, ""},
		{"no header", "10.0.0.2:5", nil, ""},
		{"only trusted entries", "10.0.0.2:5", []string{"10.0.0.3, 10.0.0.4"}, ""},
		{"4-in-6 peer is trusted", "[::ffff:10.0.0.2]:5", []string{"1.1.1.1"}, "1.1.1.1"},
		{"4-in-6 entry is unmapped and trusted", "10.0.0.2:5", []string{"::ffff:10.0.0.3"}, ""},
		{"4-in-6 untrusted entry is returned unmapped", "10.0.0.2:5", []string{"::ffff:1.1.1.1"}, "1.1.1.1"},
		{"unparseable RemoteAddr", "bogus", []string{"1.1.1.1"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := clientip.ObservedFromXFF(request(t, tt.remote, tt.xff...), trusted10)
			if tt.want == "" {
				if ok || got.IsValid() {
					t.Errorf("ObservedFromXFF = (%s, %v), want no observation", got, ok)
				}
				return
			}
			if !ok || got != netip.MustParseAddr(tt.want) {
				t.Errorf("ObservedFromXFF = (%s, %v), want (%s, true)", got, ok, tt.want)
			}
		})
	}
}

func TestObservedFromPeer(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		trusted []netip.Prefix
		want    string // empty means no observation
	}{
		{"public peer", "8.8.8.8:1", nil, "8.8.8.8"},
		{"trusted peer", "10.0.0.2:1", trusted10, ""},
		{"4-in-6 trusted peer", "[::ffff:10.0.0.2]:1", trusted10, ""},
		{"4-in-6 untrusted peer is unmapped", "[::ffff:8.8.8.8]:1", trusted10, "8.8.8.8"},
		{"unparseable RemoteAddr", "bogus", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := clientip.ObservedFromPeer(request(t, tt.remote), tt.trusted)
			if tt.want == "" {
				if ok || got.IsValid() {
					t.Errorf("ObservedFromPeer = (%s, %v), want no observation", got, ok)
				}
				return
			}
			if !ok || got != netip.MustParseAddr(tt.want) {
				t.Errorf("ObservedFromPeer = (%s, %v), want (%s, true)", got, ok, tt.want)
			}
		})
	}
}

func TestAuditIP(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"no trusted proxies keeps RemoteAddr verbatim", "1.2.3.4:5", nil, nil, "1.2.3.4:5"},
		{"untrusted peer ignores XFF", "1.2.3.4:5", []string{"9.9.9.9"}, trusted10, "1.2.3.4:5"},
		{"trusted peer uses the XFF origin", "10.0.0.2:5", []string{"1.1.1.1"}, trusted10, "1.1.1.1"},
		{"trusted peer with a bad XFF keeps RemoteAddr", "10.0.0.2:5", []string{"1.1.1.1:443"}, trusted10, "10.0.0.2:5"},
		{"unparseable RemoteAddr is kept verbatim", "bogus", []string{"1.1.1.1"}, trusted10, "bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientip.AuditIP(request(t, tt.remote, tt.xff...), tt.trusted)
			if got != tt.want {
				t.Errorf("AuditIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestObservationRoundTrip(t *testing.T) {
	if got := clientip.ObservationFrom(context.Background()); got != (clientip.Observation{}) {
		t.Errorf("ObservationFrom(empty ctx) = %+v, want zero value", got)
	}

	want := clientip.Observation{
		Peer: netip.MustParseAddr("10.0.0.2"),
		Addr: netip.MustParseAddr("1.1.1.1"),
		OK:   true,
	}
	ctx := clientip.WithObservation(t.Context(), want)
	if got := clientip.ObservationFrom(ctx); got != want {
		t.Errorf("ObservationFrom = %+v, want %+v", got, want)
	}
}
