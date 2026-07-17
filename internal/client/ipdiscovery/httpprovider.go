package ipdiscovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxProviderBody bounds how much a provider response we read — a public-IP
// endpoint returns a short string; anything larger is treated as junk.
const maxProviderBody = 1 << 12

// httpProvider GETs a URL and parses the plain-text body as this family's IP.
type httpProvider struct {
	url    string
	family Family
	http   *http.Client
}

// NewHTTPProvider builds a Provider that GETs url with hc and validates the
// parsed address belongs to family.
func NewHTTPProvider(url string, family Family, hc *http.Client) Provider {
	return &httpProvider{url: url, family: family, http: hc}
}

func (p *httpProvider) Lookup(ctx context.Context) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, http.NoBody)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: request %s: %w", p.url, err)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: get %s: %w", p.url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProviderBody)); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: %s status %d", p.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: read %s: %w", p.url, err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: parse %s: %w", p.url, err)
	}
	if !familyMatches(addr, p.family) {
		return netip.Addr{}, fmt.Errorf("ipdiscovery: %s returned %s, not %s", p.url, addr, p.family)
	}
	return addr, nil
}

// familyMatches reports whether addr is genuinely of the given family
// (rejecting v4-in-v6 for the v6 family).
func familyMatches(addr netip.Addr, family Family) bool {
	if family == FamilyV6 {
		return addr.Is6() && !addr.Is4In6()
	}
	return addr.Is4()
}

// FamilyHTTPClient returns an http.Client whose dialer is locked to tcp4 or
// tcp6, guaranteeing a query measures the intended family even against a
// dual-stack endpoint.
func FamilyHTTPClient(family Family) *http.Client {
	network := "tcp4"
	if family == FamilyV6 {
		network = "tcp6"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}
}

// Default providers: three independent operators per family so the 2-of-N
// quorum spans distinct operators.
var (
	defaultURLsV4 = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://4.ident.me"}
	defaultURLsV6 = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://6.ident.me"}
)

// DefaultProvidersV4 returns the built-in IPv4 providers sharing one
// family-locked client (connection reuse).
func DefaultProvidersV4() []Provider { return ProvidersFromURLs(defaultURLsV4, FamilyV4) }

// DefaultProvidersV6 returns the built-in IPv6 providers.
func DefaultProvidersV6() []Provider { return ProvidersFromURLs(defaultURLsV6, FamilyV6) }

// ProvidersFromURLs builds family-locked providers for the given URLs, sharing
// a single client per call.
func ProvidersFromURLs(urls []string, family Family) []Provider {
	hc := FamilyHTTPClient(family)
	ps := make([]Provider, 0, len(urls))
	for _, u := range urls {
		ps = append(ps, NewHTTPProvider(u, family, hc))
	}
	return ps
}
