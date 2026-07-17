package ipdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeProvider struct {
	addr netip.Addr
	err  error
}

func (f fakeProvider) Lookup(context.Context) (netip.Addr, error) { return f.addr, f.err }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDiscoverer_Quorum(t *testing.T) {
	a := mustAddr("203.0.113.7")
	b := mustAddr("203.0.113.8")
	tests := []struct {
		name      string
		providers []Provider
		quorum    int
		wantOK    bool
		wantAddr  netip.Addr
	}{
		{"two agree of three", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: b}}, 2, true, a},
		{"all three agree", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: a}}, 2, true, a},
		{"no agreement", []Provider{fakeProvider{addr: a}, fakeProvider{addr: b}, fakeProvider{err: errors.New("x")}}, 2, false, netip.Addr{}},
		{"one up below quorum", []Provider{fakeProvider{addr: a}, fakeProvider{err: errors.New("x")}, fakeProvider{err: errors.New("y")}}, 2, false, netip.Addr{}},
		{"top-count tie → no winner", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}, fakeProvider{addr: b}, fakeProvider{addr: b}}, 2, false, netip.Addr{}},
		{"exact threshold boundary", []Provider{fakeProvider{addr: a}, fakeProvider{addr: a}}, 2, true, a},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDiscoverer(tt.providers, nil, tt.quorum, time.Second)
			if err != nil {
				t.Fatalf("NewDiscoverer: %v", err)
			}
			v4, _ := d.Discover(context.Background())
			if v4.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v", v4.OK, tt.wantOK)
			}
			if tt.wantOK && v4.Addr != tt.wantAddr {
				t.Errorf("Addr = %v, want %v", v4.Addr, tt.wantAddr)
			}
		})
	}
}

func TestNewDiscoverer_Validation(t *testing.T) {
	p := []Provider{fakeProvider{addr: mustAddr("203.0.113.7")}}
	if _, err := NewDiscoverer(p, nil, 2, time.Second); err == nil {
		t.Error("want error when quorum (2) > len(providers) (1)")
	}
	if _, err := NewDiscoverer(p, nil, 0, time.Second); err == nil {
		t.Error("want error when quorum < 1")
	}
	// Disabled family (nil providers) must not trip validation.
	if _, err := NewDiscoverer(nil, p, 1, time.Second); err != nil {
		t.Errorf("nil v4 family should be allowed (disabled): %v", err)
	}
}

func TestDiscoverer_DisabledFamilySkipped(t *testing.T) {
	d, err := NewDiscoverer(nil, nil, 2, time.Second)
	if err != nil {
		t.Fatalf("NewDiscoverer: %v", err)
	}
	v4, v6 := d.Discover(context.Background())
	if v4.OK || v6.OK {
		t.Errorf("disabled families should both be !OK, got v4=%v v6=%v", v4.OK, v6.OK)
	}
}
