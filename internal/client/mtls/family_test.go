package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/shared"
)

const (
	pubV4 = "8.8.8.8"
	pubV6 = "2606:4700::1"

	srcObserved = "observed"
	srcNone     = "none"

	msgFallback      = "server did not observe a public address; looking it up for this family"
	msgMissingSource = "server response carried no ip_source for this family; treating it as none"
	msgUnknownSource = "server response carried an unknown ip_source value; treating it as none"
	msgNeverNone     = "server recorded no address for this family; set run.ip_discovery to auto or always"
	msgNeverUnsup    = "server does not support observed IPs and run.ip_discovery is never; nothing is being recorded"
)

var (
	famV4   = []ipdiscovery.Family{ipdiscovery.FamilyV4}
	famBoth = []ipdiscovery.Family{ipdiscovery.FamilyV4, ipdiscovery.FamilyV6}
)

// fakeLookup is the Manager's Lookup: a fixed address per family, with every
// call recorded.
type fakeLookup struct {
	mu    sync.Mutex
	addrs map[ipdiscovery.Family]netip.Addr
	calls []ipdiscovery.Family
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{addrs: map[ipdiscovery.Family]netip.Addr{
		ipdiscovery.FamilyV4: netip.MustParseAddr(pubV4),
		ipdiscovery.FamilyV6: netip.MustParseAddr(pubV6),
	}}
}

func (l *fakeLookup) lookup(_ context.Context, f ipdiscovery.Family) ipdiscovery.Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, f)
	a, ok := l.addrs[f]
	return ipdiscovery.Result{Addr: a, OK: ok}
}

func (l *fakeLookup) called() []ipdiscovery.Family {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ipdiscovery.Family(nil), l.calls...)
}

// serveDualStack serves h on 127.0.0.1 and [::1] at one shared port, over TLS
// when tlsCfg is set, and returns the port. It skips the test when ::1 is
// unavailable.
func serveDualStack(t *testing.T, h http.Handler, tlsCfg *tls.Config) string {
	t.Helper()
	var lc net.ListenConfig
	l4, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	_, port, err := net.SplitHostPort(l4.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", l4.Addr(), err)
	}
	l6, err := lc.Listen(t.Context(), "tcp6", net.JoinHostPort("::1", port))
	if err != nil {
		_ = l4.Close()
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	for _, l := range []net.Listener{l4, l6} {
		s := httptest.NewUnstartedServer(h)
		if err := s.Listener.Close(); err != nil {
			t.Fatalf("close the unused listener: %v", err)
		}
		s.Listener = l
		if tlsCfg != nil {
			s.TLS = tlsCfg.Clone()
			s.StartTLS()
		} else {
			s.Start()
		}
		t.Cleanup(s.Close)
	}
	return port
}

// newDualStackServer serves h on 127.0.0.1 and [::1] and returns its
// http://localhost:<port> URL.
func newDualStackServer(t *testing.T, h http.Handler) string {
	t.Helper()
	return "http://localhost:" + serveDualStack(t, h, nil)
}

// sourceAnswer builds a check-in answer. A request that carries an address is
// answered "reported" for it; a request with none is answered noIP(family)
// ("" leaves ip_source out).
func sourceAnswer(noIP func(ipdiscovery.Family) string) func(seenReq) (int, map[string]any) {
	return func(r seenReq) (int, map[string]any) {
		src := map[string]string{}
		if r.body["ipv4"] != "" {
			src["ipv4"] = "reported"
		}
		if r.body["ipv6"] != "" {
			src["ipv6"] = "reported"
		}
		if len(src) == 0 {
			if s := noIP(r.fam); s != "" {
				src[r.fam.String()] = s
			}
		}
		body := map[string]any{"device_id": testDeviceID, "current_ipv4": testIPv4, "stored": true}
		if len(src) > 0 {
			body["ip_source"] = src
		}
		return http.StatusOK, body
	}
}

func always(s string) func(ipdiscovery.Family) string {
	return func(ipdiscovery.Family) string { return s }
}

// dualStackEnv is an env whose main port listens on 127.0.0.1 and [::1] and
// advertises observed_ip but no agent_mtls (so the Manager never provisions);
// the Manager runs in auto over both families and the server answers every
// address-less check-in "observed".
func dualStackEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	e.fs.setObservedIP(true)
	e.mainURL = newDualStackServer(t, e.fs.handler(portMain))
	e.discovery, e.families = config.IPDiscoveryAuto, famBoth
	e.fs.setCheckin(sourceAnswer(always(srcObserved)))
	return e
}

// v4OnlyServerEnv is dualStackEnv against a server that listens on 127.0.0.1
// only, reached as localhost: a family-pinned tcp6 dial lands on ::1 and is
// refused, while an unpinned dial falls back to IPv4.
func v4OnlyServerEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	e.fs.setObservedIP(true)
	e.mainURL = "http://localhost:" + portOf(t, e.fs.main.URL)
	e.discovery, e.families = config.IPDiscoveryAuto, famBoth
	e.fs.setCheckin(sourceAnswer(always(srcObserved)))
	return e
}

// reqWant describes one expected check-in. An unpinned request may arrive on
// either loopback family, so fam is ignored for it.
type reqWant struct {
	fam        ipdiscovery.Family
	unpinned   bool
	ipv4, ipv6 string
}

func wantRequests(t *testing.T, got []seenReq, want ...reqWant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("check-ins = %d, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if !w.unpinned && g.fam != w.fam {
			t.Errorf("request %d arrived over %s, want %s", i, g.fam, w.fam)
		}
		if g.body["ipv4"] != w.ipv4 || g.body["ipv6"] != w.ipv6 {
			t.Errorf("request %d carried ipv4=%q ipv6=%q, want ipv4=%q ipv6=%q", i, g.body["ipv4"], g.body["ipv6"], w.ipv4, w.ipv6)
		}
		if g.body["hostname"] != "host" {
			t.Errorf("request %d hostname = %q, want the report's metadata", i, g.body["hostname"])
		}
	}
}

func noIP(f ipdiscovery.Family) reqWant { return reqWant{fam: f} }

func TestManagerMainNoStateUsesFamilies(t *testing.T) {
	e := dualStackEnv(t)
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))
	if got := e.lk.called(); len(got) != 0 {
		t.Errorf("Lookup called for %v, want never", got)
	}
}

func TestManagerProbationFailUsesFamilies(t *testing.T) {
	e := dualStackEnv(t)
	e.seed(false)
	e.fs.agent.Close()
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))
	wantCount(t, e.logs.count(slog.LevelWarn, "probation"), 1, "probation WARNs")
}

// serveAgentDualStack serves e's agent handler over TLS on 127.0.0.1 and [::1]
// and seeds a committed state that points at it as https://localhost.
func serveAgentDualStack(t *testing.T, e *env) {
	t.Helper()
	cert, key := e.fs.ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "agent"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatalf("agent key pair: %v", err)
	}
	port := serveDualStack(t, e.fs.handler(portAgent), &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	e.seed(true, func(s *State) { s.AgentURL = "https://localhost:" + port })
}

func TestManagerAgentUsesFamilies(t *testing.T) {
	e := dualStackEnv(t)
	serveAgentDualStack(t, e)
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portAgent), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))
	wantCount(t, e.fs.count(portMain, routeCheckin), 0, "main checkins")
}

// A rejected client certificate on one family must not be masked by the other
// family's success: the loop stops, the state is dropped and the cycle goes on.
func TestManagerCertRejectedStopsFamilyLoop(t *testing.T) {
	e := dualStackEnv(t)
	serveAgentDualStack(t, e)
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusUnauthorized, code: shared.CodeClientCertRejected, times: 1})
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portAgent, routeCheckin), 1, "agent checkins (v6 never tried)")
	if _, ok := e.state(); ok {
		t.Error("state kept after the agent rejected the client certificate")
	}
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))
}

func TestManagerNeverCapsAreKnownAndSupported(t *testing.T) {
	supported := dualStackEnv(t)
	supported.discovery, supported.families = config.IPDiscoveryNever, famV4

	unfetched := newEnv(t, false)
	unfetched.fs.script(portMain, routeCaps, scripted{status: http.StatusInternalServerError, times: -1})

	for name, e := range map[string]*env{"observed_ip advertised": supported, "capabilities not fetched": unfetched} {
		t.Run(name, func(t *testing.T) {
			mustCycle(t, e.manager())

			wantCount(t, e.logs.count(slog.LevelError, msgNeverUnsup), 0, "never_unsupported ERRORs")
		})
	}
}

func TestManagerNeverUnsupportedServerErrors(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	m := e.manager()

	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelError, msgNeverUnsup), 1, "ERRORs after cycle 1")
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4))

	e.clk.Advance(time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelError, msgNeverUnsup), 1, "ERRORs inside 24h")

	e.clk.Advance(24 * time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelError, msgNeverUnsup), 2, "ERRORs after 24h")
}

func TestManagerUnknownSourceIsNone(t *testing.T) {
	e := dualStackEnv(t)
	e.families = famV4
	e.fs.setCheckin(sourceAnswer(always("bogus")))
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.logs.count(slog.LevelWarn, msgUnknownSource+" family=ipv4 value=bogus"), 1, "unknown_source WARNs")
	if got := e.lk.called(); len(got) != 0 {
		t.Fatalf("Lookup called for %v in cycle 1, want never", got)
	}
	e.fs.newCheckins(portMain)

	e.clk.Advance(time.Minute)
	mustCycle(t, m)

	if got := e.lk.called(); len(got) != 1 || got[0] != ipdiscovery.FamilyV4 {
		t.Errorf("Lookup calls = %v, want [ipv4]", got)
	}
	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4})
	wantCount(t, e.logs.count(slog.LevelWarn, msgUnknownSource), 1, "unknown_source WARNs after cycle 2")
}

func TestManagerAlwaysSingleUnpinnedRequest(t *testing.T) {
	e := dualStackEnv(t)
	e.discovery = config.IPDiscoveryAlways
	m := e.manager()

	_, err := m.Checkin(t.Context(), checkin.Report{IPv4: pubV4, IPv6: pubV6, Hostname: "host"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4, ipv6: pubV6})
}

func TestManagerAlwaysNothingToSend(t *testing.T) {
	e := dualStackEnv(t)
	e.discovery = config.IPDiscoveryAlways
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, ErrNoFamily) {
		t.Fatalf("err = %v, want ErrNoFamily", err)
	}
	wantCount(t, len(e.fs.newCheckins(portMain)), 0, "check-ins")
}

func TestManagerNoFamiliesIsErrNoFamily(t *testing.T) {
	e := dualStackEnv(t)
	e.families = nil
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, ErrNoFamily) {
		t.Fatalf("err = %v, want ErrNoFamily", err)
	}
}

func TestManagerAutoSendsNoIP(t *testing.T) {
	e := dualStackEnv(t)
	e.families = famV4
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4))
	if got := e.lk.called(); len(got) != 0 {
		t.Errorf("Lookup called for %v, want never", got)
	}
}

func TestManagerAutoOldServerLooksUp(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	e.discovery, e.families = config.IPDiscoveryAuto, famV4
	m := e.manager()

	mustCycle(t, m)

	if got := e.lk.called(); len(got) != 1 || got[0] != ipdiscovery.FamilyV4 {
		t.Errorf("Lookup calls = %v, want [ipv4]", got)
	}
	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4})
	wantCount(t, e.logs.count(slog.LevelWarn, msgFallback+" family=ipv4 reason=old server"), 1, "fallback WARNs after cycle 1")

	e.clk.Advance(time.Minute)
	mustCycle(t, m)

	wantCount(t, e.logs.count(slog.LevelWarn, msgFallback), 1, "fallback WARNs inside 24h")
	wantCount(t, e.logs.count(slog.LevelWarn, "ip_source"), 0, "ip_source WARNs (the server never advertised it)")
}

func TestManagerAutoCapsNotFetchedLooksUp(t *testing.T) {
	e := newEnv(t, false)
	e.fs.script(portMain, routeCaps, scripted{status: http.StatusInternalServerError, times: -1})
	e.discovery, e.families = config.IPDiscoveryAuto, famV4
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4})
	wantCount(t, e.logs.count(slog.LevelWarn, msgFallback+" family=ipv4 reason=capabilities not fetched"), 1, "fallback WARNs")
}

func TestManagerAutoNoneFlipsFamilyOnly(t *testing.T) {
	e := dualStackEnv(t)
	var v4Observed atomic.Bool
	e.fs.setCheckin(sourceAnswer(func(f ipdiscovery.Family) string {
		if f == ipdiscovery.FamilyV4 && !v4Observed.Load() {
			return srcNone
		}
		return srcObserved
	}))
	m := e.manager()

	mustCycle(t, m)
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))

	e.clk.Advance(time.Minute)
	mustCycle(t, m)
	wantRequests(t, e.fs.newCheckins(portMain),
		reqWant{unpinned: true, ipv4: pubV4}, noIP(ipdiscovery.FamilyV6))
	if got := e.lk.called(); len(got) != 1 || got[0] != ipdiscovery.FamilyV4 {
		t.Fatalf("Lookup calls = %v, want [ipv4] only", got)
	}

	v4Observed.Store(true)
	e.clk.Advance(61 * time.Minute)
	mustCycle(t, m)
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))

	e.clk.Advance(time.Minute)
	mustCycle(t, m)
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV6))
	if got := e.lk.called(); len(got) != 1 {
		t.Errorf("Lookup calls = %v, want the one from cycle 2 only", got)
	}
}

func TestManagerAutoReportedKeepsLookup(t *testing.T) {
	e := dualStackEnv(t)
	e.families = famV4
	e.fs.setCheckin(sourceAnswer(always(srcNone)))
	m := e.manager()

	mustCycle(t, m) // none: the family flips to lookup
	e.fs.newCheckins(portMain)

	e.clk.Advance(time.Minute)
	mustCycle(t, m) // looked up, answered reported
	e.clk.Advance(10 * time.Minute)
	mustCycle(t, m) // still looked up: reported never flips the state back
	wantRequests(t, e.fs.newCheckins(portMain),
		reqWant{unpinned: true, ipv4: pubV4}, reqWant{unpinned: true, ipv4: pubV4})
	if got := e.lk.called(); len(got) != 2 {
		t.Fatalf("Lookup calls = %v, want 2", got)
	}

	e.clk.Advance(61 * time.Minute)
	mustCycle(t, m) // the hourly probe goes pinned and address-less
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4))
	if got := e.lk.called(); len(got) != 2 {
		t.Errorf("Lookup calls = %v after the probe, want still 2", got)
	}
}

func TestManagerAutoMissingSourceIsNone(t *testing.T) {
	e := dualStackEnv(t)
	e.families = famV4
	e.fs.setCheckin(sourceAnswer(always("")))
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.logs.count(slog.LevelWarn, msgMissingSource+" family=ipv4"), 1, "missing_source WARNs")
	e.fs.newCheckins(portMain)

	e.clk.Advance(time.Minute)
	mustCycle(t, m)

	if got := e.lk.called(); len(got) != 1 {
		t.Errorf("Lookup calls = %v, want 1", got)
	}
	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4})
	wantCount(t, e.logs.count(slog.LevelWarn, msgMissingSource), 1, "missing_source WARNs after cycle 2")
}

func TestManagerAutoRealErrorKeepsState(t *testing.T) {
	e := dualStackEnv(t)
	e.families = famV4
	var n atomic.Int32
	observed := sourceAnswer(always(srcObserved))
	e.fs.setCheckin(func(r seenReq) (int, map[string]any) {
		if n.Add(1) == 2 {
			return http.StatusInternalServerError, map[string]any{"detail": "boom"}
		}
		return observed(r)
	})
	m := e.manager()

	mustCycle(t, m)
	_, err := cycle(t, m)
	if !errors.Is(err, checkin.ErrServer) {
		t.Fatalf("cycle 2 err = %v, want checkin.ErrServer", err)
	}
	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV4))
	if got := e.lk.called(); len(got) != 0 {
		t.Errorf("Lookup called for %v, want never", got)
	}
}

func TestManagerNeverNeverLooksUp(t *testing.T) {
	e := dualStackEnv(t)
	e.discovery, e.families = config.IPDiscoveryNever, famV4
	e.fs.setCheckin(sourceAnswer(always(srcNone)))
	m := e.manager() // Lookup is nil outside auto: a call would panic

	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, msgNeverNone+" family=ipv4"), 1, "never_none WARNs after cycle 1")

	e.clk.Advance(time.Minute)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, msgNeverNone), 1, "never_none WARNs inside 24h")

	e.clk.Advance(24 * time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, msgNeverNone), 2, "never_none WARNs after 24h")
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV4), noIP(ipdiscovery.FamilyV4))
}

func TestFamilyDialFailureSkipped(t *testing.T) {
	e := v4OnlyServerEnv(t)
	m := e.manager()

	mustCycle(t, m)

	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4))
	wantCount(t, e.logs.count(slog.LevelDebug, "family=ipv6"), 1, "DEBUG skip records for ipv6")
	wantCount(t, e.logs.count(slog.LevelWarn, "family"), 0, "family WARNs")
	if got := e.lk.called(); len(got) != 0 {
		t.Fatalf("Lookup called for %v in cycle 1, want never", got)
	}

	e.clk.Advance(time.Minute)
	mustCycle(t, m)

	if got := e.lk.called(); len(got) != 1 || got[0] != ipdiscovery.FamilyV6 {
		t.Errorf("Lookup calls = %v, want [ipv6]", got)
	}
	wantRequests(t, e.fs.newCheckins(portMain), noIP(ipdiscovery.FamilyV4), reqWant{unpinned: true, ipv6: pubV6})
}

func TestDualStackV4OnlyServerRecordsV6Always(t *testing.T) {
	e := v4OnlyServerEnv(t)
	e.discovery = config.IPDiscoveryAlways
	m := e.manager()

	_, err := m.Checkin(t.Context(), checkin.Report{IPv4: pubV4, IPv6: pubV6, Hostname: "host"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4, ipv6: pubV6})
}

func TestDualStackV4OnlyServerRecordsV6Auto(t *testing.T) {
	e := v4OnlyServerEnv(t)
	m := e.manager()

	mustCycle(t, m)
	e.clk.Advance(time.Minute)
	mustCycle(t, m)

	got := e.fs.newCheckins(portMain)
	if len(got) != 3 || got[2].body["ipv6"] != pubV6 {
		t.Fatalf("check-ins = %+v, want the third to carry ipv6 %s", got, pubV6)
	}
}

func TestAllFamiliesFailJoined(t *testing.T) {
	e := dualStackEnv(t)
	e.fs.setCheckin(func(seenReq) (int, map[string]any) {
		return http.StatusUnauthorized, map[string]any{"detail": "no"}
	})
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, checkin.ErrUnauthorized) {
		t.Fatalf("err = %v, want checkin.ErrUnauthorized", err)
	}
	wantCount(t, len(e.fs.newCheckins(portMain)), 2, "attempted check-ins")
}

func TestOne401OtherOKIsWarnNotError(t *testing.T) {
	e := dualStackEnv(t)
	observed := sourceAnswer(always(srcObserved))
	e.fs.setCheckin(func(r seenReq) (int, map[string]any) {
		if r.fam == ipdiscovery.FamilyV4 {
			return http.StatusUnauthorized, map[string]any{"detail": "no"}
		}
		return observed(r)
	})
	m := e.manager()

	res, err := cycle(t, m)

	if err != nil {
		t.Fatalf("err = %v, want nil: one family checked in", err)
	}
	if res.DeviceID != testDeviceID {
		t.Errorf("DeviceID = %q, want the surviving family's response", res.DeviceID)
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "error=ipv4 check-in: checkin: unauthorized"), 1, "WARNs for the rejected family")
}

func TestClientCertRejectedStillReprovisions(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.families = famBoth
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusUnauthorized, code: shared.CodeClientCertRejected, times: 1})
	m := e.manager()

	if _, err := cycle(t, m); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests")
	wantCount(t, e.fs.count(portAgent, routeCheckin), 2, "agent checkins (rejected, then served)")
	if !e.mustState().Committed {
		t.Error("state not committed after the post-provision probe")
	}
}

func TestAgentDialFailureAllFamiliesIsAgentUnavailable(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.families = famBoth
	e.fs.agent.Close()
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want ErrAgentUnavailable", err)
	}
	wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
}

func TestCycleResultMerged(t *testing.T) {
	// Stored is true when either family stored, whichever answered last.
	for _, v4Stored := range []bool{false, true} {
		t.Run(fmt.Sprintf("v4 stored %t, v6 stored %t", v4Stored, !v4Stored), func(t *testing.T) {
			e := dualStackEnv(t)
			e.fs.setCheckin(func(r seenReq) (int, map[string]any) {
				if r.fam == ipdiscovery.FamilyV4 {
					return http.StatusOK, map[string]any{
						"device_id": testDeviceID, "current_ipv4": "198.51.100.1", "stored": v4Stored,
						// v6 here is v4's view of the other family; it must not win.
						"ip_source": map[string]string{"ipv4": "observed", "ipv6": "reported"},
					}
				}
				return http.StatusOK, map[string]any{
					"device_id": testDeviceID, "current_ipv4": "198.51.100.1", "current_ipv6": "2001:db8::2", "stored": !v4Stored,
					"ip_source": map[string]string{"ipv6": "observed"},
				}
			})
			m := e.manager()

			res, err := cycle(t, m)

			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			want := checkin.Result{
				DeviceID: testDeviceID, CurrentIPv4: "198.51.100.1", CurrentIPv6: "2001:db8::2", Stored: true,
				IPSource: checkin.IPSource{IPv4: srcObserved, IPv6: srcObserved},
			}
			if res != want {
				t.Errorf("result = %+v, want %+v", res, want)
			}
		})
	}
}

func TestNewManagerRejectsBadDiscovery(t *testing.T) {
	tests := []struct {
		name      string
		discovery string
	}{
		{"unknown mode", "sometimes"},
		{"auto without a Lookup", config.IPDiscoveryAuto},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, false)
			cfg := e.config()
			cfg.Discovery, cfg.Lookup = tt.discovery, nil

			if _, err := NewManager(cfg); err == nil {
				t.Fatal("NewManager succeeded, want an error")
			}
		})
	}
}

func TestNewManagerZeroDiscoveryIsAlways(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	cfg := e.config()
	cfg.Discovery, cfg.Families = "", nil
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if _, err := m.Checkin(t.Context(), checkin.Report{IPv4: pubV4, Hostname: "host"}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	wantRequests(t, e.fs.newCheckins(portMain), reqWant{unpinned: true, ipv4: pubV4})
}
