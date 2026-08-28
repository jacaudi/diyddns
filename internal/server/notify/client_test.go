package notify

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// The single most important assertion in this package. A cloned
// DefaultTransport inherits Proxy: ProxyFromEnvironment
// (net/http/transport.go:46-47, and Clone copies it at :337,340), which would
// route every non-loopback delivery through a proxy and reduce the dial-time
// guard to inspecting the proxy's address.
//
// Structural, not end-to-end: this cannot silently disarm, needs no TestMain
// env ordering, and catches the regression directly.
func TestNewClients_ProxyDisabled(t *testing.T) {
	c := NewClients(nil, time.Second)
	for name, cl := range map[string]*http.Client{"https": c.HTTPS, "http": c.HTTP} {
		tr, ok := cl.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s: transport is %T, want *http.Transport", name, cl.Transport)
		}
		if tr.Proxy != nil {
			t.Errorf("%s: tr.Proxy is set; deliveries would be proxied past the guard", name)
		}
	}
}

// Proves the guard is actually wired into the transport, not merely that the
// predicate works. A predicate test alone passes even if someone swaps the
// transport out.
func TestClients_GuardIsWired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// Loopback not permitted: the dial must be refused.
	// Bind and close the response even on the error path — golangci-lint's
	// bodyclose runs on _test.go here (.golangci.yml's test exclusions cover
	// gocyclo, dupl, gosec, errcheck, unparam, prealloc — NOT bodyclose), so
	// `if _, err := ...Get(...)` fails `task lint`.
	blockedResp, err := NewClients(nil, 2*time.Second).HTTP.Get(srv.URL)
	if err == nil {
		blockedResp.Body.Close()
		t.Fatal("reached a loopback server with loopback not permitted")
	}

	// Loopback permitted: the same request must succeed.
	allowed, err := ParseAllowed([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	ok := NewClients(allowed, 2*time.Second)
	resp, err := ok.HTTP.Get(srv.URL)
	if err != nil {
		t.Fatalf("blocked with loopback permitted: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

func TestClients_RedirectsNotFollowed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/second", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	allowed, _ := ParseAllowed([]string{"127.0.0.0/8"})
	c := NewClients(allowed, 2*time.Second)
	resp, err := c.HTTP.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect must not be followed)", resp.StatusCode)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1", hits)
	}
}

// Control's parse-failure branch must fail closed. Design §14 asks for this.
// The previous version of this test only asserted that netip.ParseAddrPort
// rejects malformed strings — it never invoked the Control closure at all,
// so mutating the parse-error branch to `return nil` (fail OPEN) left it
// passing. This calls dialControl's returned func directly with a malformed
// address, the same way net.Dialer would, and asserts it returns an error.
func TestPermit_UnparseableAddressFailsClosed(t *testing.T) {
	control := dialControl("https", nil)
	for _, bad := range []string{"", "not-an-address", "127.0.0.1", "[::1]"} { // no port / malformed
		if err := control("tcp", bad, nil); err == nil {
			t.Errorf("dialControl's Control(%q) = nil error, want a failure (fail-closed on an unparseable dial address)", bad)
		}
	}
}

func TestClients_For(t *testing.T) {
	c := NewClients(nil, time.Second)
	if got, err := c.For("https"); err != nil || got != c.HTTPS {
		t.Errorf("For(https) = %v, %v", got, err)
	}
	if got, err := c.For("http"); err != nil || got != c.HTTP {
		t.Errorf("For(http) = %v, %v", got, err)
	}
	if _, err := c.For("ftp"); err == nil {
		t.Error("For(ftp) succeeded, want error")
	}
}

// Guards the scheme rule at the predicate layer. Binding a TLS listener on a
// 192.168/16 address with a Go-trusted certificate is not available on a
// standard runner, so the end-to-end half is covered by GuardIsWired above.
func TestPermit_SchemeRuleOnLAN(t *testing.T) {
	allowed, _ := ParseAllowed([]string{"192.168.0.0/16", "127.0.0.0/8"})
	lan := netip.MustParseAddr("192.168.1.50")

	if err := Permit("http", lan, allowed); err == nil {
		t.Error("http to a permitted LAN address was allowed; must be loopback-only")
	}
	if err := Permit("https", lan, allowed); err != nil {
		t.Errorf("https to a permitted LAN address was denied: %v", err)
	}
	// And the composition: loopback alone is not enough without the operator.
	if err := Permit("http", netip.MustParseAddr("127.0.0.1"), nil); err == nil {
		t.Error("http to loopback allowed with no allowed_private_cidrs; must compose")
	}
}
