// Package ipdiscovery discovers the host's public IP address for each address
// family from a quorum of independent lookup providers. A family's result is
// trusted only when at least `quorum` providers agree on the same address, so
// a single wrong, stale, or hijacked provider cannot set the reported IP.
package ipdiscovery

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Family is an IP address family.
type Family int

const (
	// FamilyV4 is the IPv4 address family.
	FamilyV4 Family = iota
	// FamilyV6 is the IPv6 address family.
	FamilyV6
)

func (f Family) String() string {
	if f == FamilyV6 {
		return "ipv6"
	}
	return "ipv4"
}

// Provider looks up the host's public IP for one address family.
type Provider interface {
	Lookup(ctx context.Context) (netip.Addr, error)
}

// Result is the per-family discovery outcome. OK is false when the family is
// disabled or no address reached quorum.
type Result struct {
	Addr netip.Addr
	OK   bool
}

// Discoverer runs each family's providers concurrently and applies a majority
// quorum. A family with no providers is disabled.
type Discoverer struct {
	v4, v6 []Provider
	quorum int
	perReq time.Duration
}

// NewDiscoverer validates quorum against each ENABLED (non-empty) family and
// returns a ready Discoverer. A nil/empty family list disables that family.
func NewDiscoverer(v4, v6 []Provider, quorum int, perReq time.Duration) (*Discoverer, error) {
	if quorum < 1 {
		return nil, fmt.Errorf("ipdiscovery: quorum must be >= 1, got %d", quorum)
	}
	if len(v4) > 0 && quorum > len(v4) {
		return nil, fmt.Errorf("ipdiscovery: ipv4 quorum %d exceeds provider count %d", quorum, len(v4))
	}
	if len(v6) > 0 && quorum > len(v6) {
		return nil, fmt.Errorf("ipdiscovery: ipv6 quorum %d exceeds provider count %d", quorum, len(v6))
	}
	if perReq <= 0 {
		perReq = 5 * time.Second
	}
	return &Discoverer{v4: v4, v6: v6, quorum: quorum, perReq: perReq}, nil
}

// Discover runs both families concurrently and returns their quorum results.
func (d *Discoverer) Discover(ctx context.Context) (v4, v6 Result) {
	var wg sync.WaitGroup
	wg.Go(func() { v4 = d.discoverFamily(ctx, d.v4) })
	wg.Go(func() { v6 = d.discoverFamily(ctx, d.v6) })
	wg.Wait()
	return v4, v6
}

// discoverFamily queries one family's providers concurrently (each bounded by
// perReq) and applies the majority quorum with a strict tie-break: if two or
// more addresses share the top count, there is no winner (fail-safe).
func (d *Discoverer) discoverFamily(ctx context.Context, providers []Provider) Result {
	if len(providers) == 0 {
		return Result{}
	}
	addrs := make(chan netip.Addr, len(providers))
	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Go(func() {
			pctx, cancel := context.WithTimeout(ctx, d.perReq)
			defer cancel()
			addr, err := p.Lookup(pctx)
			if err == nil && addr.IsValid() {
				addrs <- addr
			}
		})
	}
	wg.Wait()
	close(addrs)

	counts := make(map[netip.Addr]int)
	for a := range addrs {
		counts[a]++
	}
	var winner netip.Addr
	top, tie := 0, false
	for a, n := range counts {
		switch {
		case n > top:
			top, winner, tie = n, a, false
		case n == top:
			tie = true
		}
	}
	if top >= d.quorum && !tie {
		return Result{Addr: winner, OK: true}
	}
	return Result{}
}
