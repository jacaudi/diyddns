package notify

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Clients holds the two schemes' delivery clients. They differ only in dial
// policy: HTTPS carries the full destination policy, HTTP additionally
// requires loopback. Selecting between them at send time is what makes design
// D3 enforceable at dial time rather than only at endpoint creation.
type Clients struct {
	HTTPS *http.Client
	HTTP  *http.Client
}

// NewClients builds both clients against one allow-list and timeout.
func NewClients(allowed []netip.Prefix, timeout time.Duration) *Clients {
	return &Clients{
		HTTPS: newClient("https", allowed, timeout),
		HTTP:  newClient("http", allowed, timeout),
	}
}

// For returns the client for scheme. An unknown scheme is an error rather than
// a default, so a stored URL that is neither http nor https can never reach a
// client.
func (c *Clients) For(scheme string) (*http.Client, error) {
	switch scheme {
	case "https":
		return c.HTTPS, nil
	case "http":
		return c.HTTP, nil
	default:
		return nil, fmt.Errorf("notify: unsupported scheme %q", scheme)
	}
}

func newClient(scheme string, allowed []netip.Prefix, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		// Control runs after resolution and before connect, with the address
		// the kernel is about to dial. Checking here rather than at URL-parse
		// time is what closes the DNS-rebinding window and makes obfuscated
		// hosts irrelevant.
		Control: func(_, address string, _ syscall.RawConn) error {
			// Control receives raddr.String(). For IPv6 that can carry a zone
			// ("[fe80::1%eth0]:443"), which net.ParseIP rejects and
			// netip.ParseAddrPort accepts. Parse failure FAILS CLOSED.
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("notify: unparseable dial address %q: %w", address, err)
			}
			return Permit(scheme, ap.Addr(), allowed)
		},
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Load-bearing, not tidiness. Clone copies Proxy: ProxyFromEnvironment,
	// so without this an ambient HTTPS_PROXY routes every non-loopback
	// delivery through a proxy and Control only ever sees the proxy address.
	// There is deliberately no config key to re-enable proxying: a proxy and a
	// destination policy cannot both be authoritative.
	tr.Proxy = nil
	tr.DialContext = dialer.DialContext

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
