package mtls

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/shared"
)

const (
	testDeviceID = "dev-1"
	testIPv4     = "203.0.113.9"

	routeCaps    = "GET /agent/v1/capabilities"
	routeSelf    = "GET /agent/v1/self"
	routeCheckin = "POST /agent/v1/checkin"
	routeCert    = "POST /agent/v1/cert"

	routeRotateSecret = "POST /agent/v1/rotation/secret"

	portMain  = "main"
	portAgent = "agent"
)

// testClock is the Manager's Now and the fake's issuance clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *testClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// recLog is a slog.Handler that keeps every record's message and attributes
// as plain text, so tests can match quoted phrases without slog escaping.
type recLog struct {
	mu   sync.Mutex
	recs []logRec
}

type logRec struct {
	level slog.Level
	text  string
}

func (l *recLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *recLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *recLog) WithGroup(string) slog.Handler            { return l }

func (l *recLog) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, logRec{level: r.Level, text: b.String()})
	return nil
}

// count returns how many records at level contain substr.
func (l *recLog) count(level slog.Level, substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.recs {
		if r.level == level && strings.Contains(r.text, substr) {
			n++
		}
	}
	return n
}

func (l *recLog) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, r := range l.recs {
		b.WriteString(r.text + "\n")
	}
	return b.String()
}

type call struct{ port, route string }

// oldKey is the env's device secret, the key the fake knows as "old".
var oldKey = []byte("0123456789abcdef")

// seenReq is one request as the fake saw it: where it landed, which loopback
// family it arrived on (the local address of the connection), the name of the
// key its signature matched ("" when unsigned or when the fake holds no keys)
// and, for a check-in or a step-3 submit, its decoded JSON body.
type seenReq struct {
	port, route string
	fam         ipdiscovery.Family
	key         string
	body        map[string]any
}

// str is the string value of body[k], "" when absent or not a string.
func (s seenReq) str(k string) string {
	v, _ := s.body[k].(string)
	return v
}

// requestFamily returns the family of the local address r arrived on.
func requestFamily(r *http.Request) ipdiscovery.Family {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && a.IP.To4() == nil {
		return ipdiscovery.FamilyV6
	}
	return ipdiscovery.FamilyV4
}

// scripted overrides the fake's answer for one (port, route). times < 0 means
// forever; otherwise it is consumed that many times. after runs before the
// response is written.
type scripted struct {
	status int
	code   string
	times  int
	after  func()
}

// fakeServer is a main-port server and an agent-port server (TLS 1.3,
// RequireAnyClientCert) backed by one in-test CA. It records every request by
// port and route and can be scripted per route.
type fakeServer struct {
	ca          testCA
	clock       *testClock
	main, agent *httptest.Server

	// down makes the agent drop connections without answering.
	down atomic.Bool
	// onSelf runs when the agent answers GET /self.
	onSelf func()

	mu           sync.Mutex
	calls        []call
	seen         []seenReq
	taken        map[string]int // check-ins already handed out by newCheckins, per port
	scripts      map[call][]scripted
	issued       int
	advertise    bool
	observedIP   bool
	capsAgentURL string
	// checkinFn, when set, answers every check-in the scripts do not claim.
	// Status 0 means 200.
	checkinFn func(seenReq) (int, map[string]any)
	// certAgentURL and certBundle are what POST /cert answers with.
	certAgentURL string
	certBundle   string

	// keys is the name-to-key table signatures are checked against; nil checks
	// nothing. accept narrows which matched names are served: nil accepts every
	// request, otherwise a signed request whose matched name is not accepted
	// gets a plain 401. Unsigned routes (routeCaps) are never checked.
	keys   map[string][]byte
	accept map[string]bool
	// rotation is added as "rotation" to every check-in answer when non-nil.
	rotation map[string]any
	// capsRotation adds "rotation": true to the capabilities answer.
	capsRotation bool
	// stepThree holds the secret of every authenticated step-3 submit.
	stepThree []string
}

func newFakeServer(t *testing.T, clk *testClock, tlsMain bool) *fakeServer {
	t.Helper()
	f := &fakeServer{
		ca:        newTestCA(t, "fake agent CA"),
		clock:     clk,
		scripts:   map[call][]scripted{},
		taken:     map[string]int{},
		advertise: true,
	}
	if tlsMain {
		f.main = httptest.NewTLSServer(f.handler(portMain))
	} else {
		f.main = httptest.NewServer(f.handler(portMain))
	}
	t.Cleanup(f.main.Close)

	serverCert, serverKey := f.ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "agent"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	pair, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		t.Fatalf("agent key pair: %v", err)
	}
	f.agent = httptest.NewUnstartedServer(f.handler(portAgent))
	f.agent.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	f.agent.StartTLS()
	t.Cleanup(f.agent.Close)

	f.capsAgentURL = f.agent.URL
	f.certAgentURL = f.agent.URL
	f.certBundle = f.ca.pem
	return f
}

func (f *fakeServer) setCaps(advertise bool, agentURL string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advertise = advertise
	f.capsAgentURL = agentURL
}

func (f *fakeServer) setObservedIP(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observedIP = v
}

func (f *fakeServer) setCheckin(fn func(seenReq) (int, map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkinFn = fn
}

// newCheckins returns the check-ins port received since the previous call.
func (f *fakeServer) newCheckins(port string) []seenReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []seenReq
	for _, s := range f.seen {
		if s.port == port && s.route == routeCheckin {
			all = append(all, s)
		}
	}
	out := all[f.taken[port]:]
	f.taken[port] = len(all)
	return out
}

func (f *fakeServer) script(port, route string, s scripted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := call{port, route}
	f.scripts[c] = append(f.scripts[c], s)
}

// next pops the scripted answer for c, if any. Caller holds f.mu.
func (f *fakeServer) next(c call) (scripted, bool) {
	q := f.scripts[c]
	if len(q) == 0 {
		return scripted{}, false
	}
	s := q[0]
	if s.times >= 0 {
		s.times--
		if s.times <= 0 {
			f.scripts[c] = q[1:]
		} else {
			q[0] = s
		}
	}
	return s, true
}

// authenticate matches r's signature against the fake's key table and reports
// the matched key's name. ok is false when the request must get a 401: it
// carries a signature no key made, or one made by a key that is not accepted.
// Without a key table nothing is checked.
func (f *fakeServer) authenticate(r *http.Request, body []byte) (name string, ok bool) {
	f.mu.Lock()
	keys, accept := f.keys, f.accept
	f.mu.Unlock()
	if keys == nil {
		return "", true
	}
	canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
		r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
	got := r.Header.Get(shared.HeaderSignature)
	for n, k := range keys {
		if hmac.Equal([]byte(shared.Sign(k, canonical)), []byte(got)) {
			return n, accept == nil || accept[n]
		}
	}
	return "", false
}

func (f *fakeServer) handler(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if port == portAgent && f.down.Load() {
			panic(http.ErrAbortHandler)
		}
		c := call{port, r.Method + " " + r.URL.Path}
		sr := seenReq{port: port, route: c.route, fam: requestFamily(r)}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if c.route == routeCheckin || c.route == routeRotateSecret {
			if err := json.Unmarshal(raw, &sr.body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		authed := true
		if c.route != routeCaps {
			sr.key, authed = f.authenticate(r, raw)
		}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		f.seen = append(f.seen, sr)
		if authed && c.route == routeRotateSecret {
			f.stepThree = append(f.stepThree, sr.str("secret"))
		}
		sc, scripted := f.next(c)
		advertise, observed, capsURL, capsRotation := f.advertise, f.observedIP, f.capsAgentURL, f.capsRotation
		certURL, bundle, checkinFn, rotation := f.certAgentURL, f.certBundle, f.checkinFn, f.rotation
		f.mu.Unlock()

		if !authed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if scripted {
			if sc.after != nil {
				sc.after()
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(sc.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": sc.code, "detail": "scripted"})
			return
		}
		// Like the real server: the client promotes a pending key only on a JSON 2xx.
		w.Header().Set("Content-Type", "application/json")
		switch c.route {
		case routeCaps:
			body := map[string]any{"server_version": "test"}
			if advertise {
				body["agent_mtls"] = map[string]string{"agent_url": capsURL}
			}
			if observed {
				body["observed_ip"] = true
			}
			if capsRotation {
				body["rotation"] = true
			}
			_ = json.NewEncoder(w).Encode(body)
		case routeSelf:
			if f.onSelf != nil {
				f.onSelf()
			}
			_, _ = w.Write([]byte(`{}`))
		case routeRotateSecret:
			_, _ = w.Write([]byte(`{}`))
		case routeCheckin:
			status, body := http.StatusOK, map[string]any{
				"device_id": testDeviceID, "current_ipv4": testIPv4, "stored": true,
			}
			if checkinFn != nil {
				if status, body = checkinFn(sr); status == 0 {
					status = http.StatusOK
				}
			}
			if rotation != nil {
				body["rotation"] = rotation
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		case routeCert:
			var req struct {
				CSR string `json:"csr"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			certPEM, err := f.issueDevice([]byte(req.CSR))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"certificate": certPEM, "ca_bundle": bundle, "agent_url": certURL,
			})
		default:
			http.NotFound(w, r)
		}
	})
}

// issueDevice signs a one-year device certificate for csrPEM, valid relative to
// the fake's clock (the same clock the Manager runs on).
func (f *fakeServer) issueDevice(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", errors.New("no PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	f.issued++
	serial := int64(f.issued) + 100
	f.mu.Unlock()

	now := f.clock.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: testDeviceID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, f.ca.cert, csr.PublicKey, f.ca.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func (f *fakeServer) count(port, route string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.port == port && c.route == route {
			n++
		}
	}
	return n
}

// countPort counts every request that reached port, capabilities included
// unless skipCaps.
func (f *fakeServer) countPort(port string, skipCaps bool) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.port == port && (!skipCaps || c.route != routeCaps) {
			n++
		}
	}
	return n
}

// sequence returns "port route" for every request in arrival order.
func (f *fakeServer) sequence() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.port+" "+c.route)
	}
	return out
}

// env wires a fake server, a clock, a recording logger and a state path.
type env struct {
	t         *testing.T
	fs        *fakeServer
	clk       *testClock
	logs      *recLog
	statePath string
	// dir holds credentials.json (see config).
	dir      string
	caPath   string
	insecure bool

	// mainURL overrides the fake's main URL (the dual-stack tests point it at
	// localhost). discovery and families are the Manager's per-family mode.
	mainURL   string
	discovery string
	families  []ipdiscovery.Family
	lk        *fakeLookup
}

func newEnv(t *testing.T, tlsMain bool) *env {
	t.Helper()
	clk := &testClock{t: time.Now().Truncate(time.Second)}
	e := &env{
		t:         t,
		fs:        newFakeServer(t, clk, tlsMain),
		clk:       clk,
		logs:      &recLog{},
		statePath: filepath.Join(t.TempDir(), FileName),
		dir:       t.TempDir(),
		insecure:  !tlsMain,
		discovery: config.IPDiscoveryNever,
		families:  []ipdiscovery.Family{ipdiscovery.FamilyV4},
		lk:        newFakeLookup(),
	}
	if tlsMain {
		e.caPath = filepath.Join(t.TempDir(), "main-ca.pem")
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.fs.main.Certificate().Raw})
		if err := os.WriteFile(e.caPath, certPEM, 0o600); err != nil {
			t.Fatalf("write main CA: %v", err)
		}
	}
	return e
}

func (e *env) config() Config {
	cfg := Config{
		StatePath:       e.statePath,
		CredentialsPath: filepath.Join(e.dir, "credentials.json"),
		Creds: credentials.Credentials{
			ServerURL: cmp.Or(e.mainURL, e.fs.main.URL),
			DeviceID:  testDeviceID,
			Secret:    base64.StdEncoding.EncodeToString(oldKey),
		},
		CACertPath:        e.caPath,
		InsecureProvision: e.insecure,
		Log:               slog.New(e.logs),
		Now:               e.clk.Now,
		Discovery:         e.discovery,
		Families:          e.families,
	}
	if e.discovery == config.IPDiscoveryAuto {
		cfg.Lookup = e.lk.lookup
	}
	return cfg
}

func (e *env) manager() *Manager {
	e.t.Helper()
	m, err := NewManager(e.config())
	if err != nil {
		e.t.Fatalf("NewManager: %v", err)
	}
	return m
}

// seed writes a state issued by the fake CA at the current clock.
func (e *env) seed(committed bool, mutate ...func(*State)) State {
	e.t.Helper()
	keyPEM, csrPEM, err := NewKeyAndCSR(testDeviceID)
	if err != nil {
		e.t.Fatalf("NewKeyAndCSR: %v", err)
	}
	certPEM, err := e.fs.issueDevice(csrPEM)
	if err != nil {
		e.t.Fatalf("issueDevice: %v", err)
	}
	s := State{
		DeviceID:    testDeviceID,
		KeyPEM:      string(keyPEM),
		CertPEM:     certPEM,
		CABundlePEM: e.fs.ca.pem,
		AgentURL:    e.fs.agent.URL,
		Committed:   committed,
	}
	for _, f := range mutate {
		f(&s)
	}
	if err := Save(e.statePath, s); err != nil {
		e.t.Fatalf("seed Save: %v", err)
	}
	return s
}

// state loads the persisted state; ok is false when there is none.
func (e *env) state() (State, bool) {
	e.t.Helper()
	s, err := Load(e.statePath, testDeviceID, slog.New(slog.DiscardHandler))
	if errors.Is(err, ErrNotFound) {
		return State{}, false
	}
	if err != nil {
		e.t.Fatalf("Load: %v", err)
	}
	return s, true
}

func (e *env) mustState() State {
	e.t.Helper()
	s, ok := e.state()
	if !ok {
		e.t.Fatal("no mtls state on disk")
	}
	return s
}

func cycle(t *testing.T, m *Manager) (checkin.Result, error) {
	t.Helper()
	return m.Checkin(t.Context(), checkin.Report{Hostname: "host"})
}

func mustCycle(t *testing.T, m *Manager) {
	t.Helper()
	res, err := cycle(t, m)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.CurrentIPv4 != testIPv4 {
		t.Errorf("CurrentIPv4 = %q, want %q", res.CurrentIPv4, testIPv4)
	}
}

func wantCount(t *testing.T, got, want int, what string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", what, got, want)
	}
}

func TestManager_NoCapabilityStaysOnMain(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	wantCount(t, e.fs.countPort(portAgent, false), 0, "agent requests")
	if _, ok := e.state(); ok {
		t.Error("mtls.json written without the agent_mtls capability")
	}
}

func TestManager_RefusesHTTPProvisionWithoutFlag(t *testing.T) {
	e := newEnv(t, false)
	e.insecure = false
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	wantCount(t, e.fs.count(portMain, routeCert), 0, "main cert requests")
	if _, ok := e.state(); ok {
		t.Error("state written over http:// without --insecure-provision")
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "--insecure-provision"), 1, "refusal WARNs after cycle 1")

	e.clk.Advance(time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, "--insecure-provision"), 1, "refusal WARNs inside 24h")

	e.clk.Advance(25 * time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, "--insecure-provision"), 2, "refusal WARNs after 24h")
}

func TestManager_InsecureProvisionWarnsEachTime(t *testing.T) {
	e := newEnv(t, false)
	m := e.manager()

	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, "insecure"), 1, "insecure WARNs after first provisioning")

	// An expired certificate forces a second provisioning.
	e.clk.Advance(366 * 24 * time.Hour)
	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCert), 2, "main cert requests")
	wantCount(t, e.logs.count(slog.LevelWarn, "insecure"), 2, "insecure WARNs after second provisioning")
}

func TestManager_ProbationThenCommit(t *testing.T) {
	e := newEnv(t, false)
	var committedAtProbe atomic.Bool
	committedAtProbe.Store(true)
	e.fs.onSelf = func() {
		s, ok := e.state()
		committedAtProbe.Store(!ok || s.Committed)
	}
	m := e.manager()

	mustCycle(t, m)

	want := []string{
		portMain + " " + routeCaps,
		portMain + " " + routeCert,
		portAgent + " " + routeSelf,
		portAgent + " " + routeCheckin,
	}
	if got := e.fs.sequence(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("request order = %v, want %v", got, want)
	}
	if committedAtProbe.Load() {
		t.Error("state was missing or already committed when the probe ran; want saved uncommitted")
	}
	if !e.mustState().Committed {
		t.Error("state not committed after a successful agent-port probe")
	}
}

func TestManager_ProbationAgentBlockedStaysOnMain(t *testing.T) {
	e := newEnv(t, false)
	e.fs.agent.Close()
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	if e.mustState().Committed {
		t.Error("committed although the agent port is unreachable")
	}
	wantCount(t, e.logs.count(slog.LevelWarn, "probation"), 1, "probation WARNs after cycle 1")

	e.clk.Advance(time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, "probation"), 1, "probation WARNs inside 24h")

	e.clk.Advance(24 * time.Hour)
	mustCycle(t, m)
	wantCount(t, e.logs.count(slog.LevelWarn, "probation"), 2, "probation WARNs after 24h")
}

func TestManager_CommittedUsesOnlyAgent(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.fs.main.Close()
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portAgent, routeCheckin), 1, "agent checkins")
}

func TestManager_CommittedAgentDownIsHardError(t *testing.T) {
	e := newEnv(t, false)
	seed := e.seed(true)
	e.fs.agent.Close()
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want ErrAgentUnavailable", err)
	}
	if !strings.Contains(err.Error(), "diyddns-client mtls reset") {
		t.Errorf("err = %q, want it to name `diyddns-client mtls reset`", err)
	}
	wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
	if got := e.mustState(); got != seed {
		t.Error("state changed on a hard error")
	}
}

func TestManager_CommittedAgentPlain401IsErrUnauthorized(t *testing.T) {
	e := newEnv(t, false)
	seed := e.seed(true)
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusUnauthorized, times: -1})
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, checkin.ErrUnauthorized) {
		t.Fatalf("err = %v, want checkin.ErrUnauthorized", err)
	}
	if errors.Is(err, ErrAgentUnavailable) {
		t.Error("a plain 401 must not become ErrAgentUnavailable")
	}
	wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
	if got := e.mustState(); got != seed {
		t.Error("state changed on a plain 401")
	}
}

func TestManager_CommittedAgentServerErrorPassesThrough(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusInternalServerError, times: -1})
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, checkin.ErrServer) {
		t.Fatalf("err = %v, want checkin.ErrServer", err)
	}
	if errors.Is(err, ErrAgentUnavailable) {
		t.Error("a server error must not become ErrAgentUnavailable")
	}
	wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
}

func TestManager_PinMismatchIsHardError(t *testing.T) {
	e := newEnv(t, false)
	other := newTestCA(t, "unrelated CA")
	seed := e.seed(true, func(s *State) { s.CABundlePEM = other.pem })
	m := e.manager()

	_, err := cycle(t, m)

	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want ErrAgentUnavailable", err)
	}
	wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
	if got := e.mustState(); got != seed {
		t.Error("state changed on a pin mismatch")
	}
}

func TestManager_AgentRejectReprovisions(t *testing.T) {
	e := newEnv(t, false)
	seed := e.seed(true)
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusUnauthorized, code: shared.CodeClientCertRejected, times: 1})
	m := e.manager()

	res, err := cycle(t, m)

	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.CurrentIPv4 != testIPv4 {
		t.Errorf("CurrentIPv4 = %q, want %q", res.CurrentIPv4, testIPv4)
	}
	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests")
	wantCount(t, e.fs.count(portMain, routeCheckin), 0, "main checkins")
	wantCount(t, e.fs.count(portMain, routeSelf), 0, "main selfs")
	wantCount(t, e.fs.count(portAgent, routeSelf), 1, "agent probes")
	wantCount(t, e.fs.count(portAgent, routeCheckin), 2, "agent checkins (rejected, then served)")
	got := e.mustState()
	if !got.Committed {
		t.Error("state not committed after the post-provision probe")
	}
	if got.CertPEM == seed.CertPEM || got.KeyPEM == seed.KeyPEM {
		t.Error("certificate and key were not replaced")
	}
}

func TestManager_AgentRejectReprovisions_ProbeFailsFallsToMain(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.fs.script(portAgent, routeCheckin, scripted{
		status: http.StatusUnauthorized, code: shared.CodeClientCertRejected, times: 1,
		after: func() { e.fs.down.Store(true) },
	})
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests")
	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	if e.mustState().Committed {
		t.Error("committed although the post-provision probe failed")
	}
}

func TestManager_AgentRejectThen409LogsOperatorAction(t *testing.T) {
	e := newEnv(t, false)
	e.seed(true)
	e.fs.script(portAgent, routeCheckin, scripted{status: http.StatusUnauthorized, code: shared.CodeClientCertRejected, times: 1})
	e.fs.script(portMain, routeCert, scripted{status: http.StatusConflict, code: shared.CodeCertAlreadyIssued, times: -1})
	m := e.manager()

	mustCycle(t, m)

	if n := e.logs.count(slog.LevelError, `ask an admin to click "Reset certificate"`); n != 1 {
		t.Errorf("operator-action ERRORs = %d, want 1; logs:\n%s", n, e.logs.all())
	}
	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests after cycle 1")
	if _, ok := e.state(); ok {
		t.Error("state kept after the server refused to re-issue")
	}

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCert), 2, "main cert requests after cycle 2")
	wantCount(t, e.fs.count(portMain, routeCheckin), 2, "main checkins after cycle 2")
}

func TestManager_ExpiredCertReprovisions(t *testing.T) {
	e := newEnv(t, false)
	seed := e.seed(true)
	leaf, err := seed.Leaf()
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	e.clk.Set(leaf.NotAfter.Add(time.Second))
	m := e.manager()

	mustCycle(t, m)

	want := []string{
		portMain + " " + routeCaps,
		portMain + " " + routeCert,
		portAgent + " " + routeSelf,
		portAgent + " " + routeCheckin,
	}
	if got := e.fs.sequence(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("request order = %v, want %v", got, want)
	}
	got := e.mustState()
	if got.CertPEM == seed.CertPEM || !got.Committed {
		t.Error("expired certificate not replaced by a committed one")
	}
}

func TestManager_RenewsWithin60Days(t *testing.T) {
	tests := []struct {
		name      string
		remaining time.Duration
		renews    bool
	}{
		{"59 days left renews", 59 * 24 * time.Hour, true},
		{"61 days left does not", 61 * 24 * time.Hour, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, false)
			seed := e.seed(true)
			leaf, err := seed.Leaf()
			if err != nil {
				t.Fatalf("Leaf: %v", err)
			}
			e.clk.Set(leaf.NotAfter.Add(-tt.remaining))
			other := newTestCA(t, "new backup CA")
			e.fs.certBundle = e.fs.ca.pem + other.pem
			e.fs.certAgentURL = "https://localhost:" + portOf(t, e.fs.agent.URL)
			m := e.manager()

			mustCycle(t, m)

			wantCount(t, e.fs.countPort(portMain, true), 0, "non-capabilities main requests")
			wantCount(t, e.fs.count(portAgent, routeCheckin), 1, "agent checkins")
			got := e.mustState()
			if !got.Committed {
				t.Error("committed flag lost")
			}
			if !tt.renews {
				wantCount(t, e.fs.count(portAgent, routeCert), 0, "agent cert requests")
				if got != seed {
					t.Error("state changed without a renewal")
				}
				return
			}
			wantCount(t, e.fs.count(portAgent, routeCert), 1, "agent cert requests")
			if got.CABundlePEM != e.fs.certBundle || got.AgentURL != e.fs.certAgentURL {
				t.Errorf("renewed state kept stale bundle/agent_url: url=%q", got.AgentURL)
			}
			if got.CertPEM == seed.CertPEM || got.KeyPEM == seed.KeyPEM {
				t.Error("renewal reused the old key or certificate")
			}
		})
	}
}

func TestManager_AgentURLRefreshFromHTTPSCaps(t *testing.T) {
	tests := []struct {
		name    string
		tlsMain bool
		updated bool
	}{
		{"https capabilities refresh agent_url", true, true},
		{"plain http capabilities do not", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.tlsMain)
			seed := e.seed(true)
			newURL := "https://localhost:" + portOf(t, e.fs.agent.URL)
			e.fs.setCaps(true, newURL)
			m := e.manager()

			mustCycle(t, m)

			got := e.mustState()
			want := seed.AgentURL
			if tt.updated {
				want = newURL
			}
			if got.AgentURL != want {
				t.Errorf("AgentURL = %q, want %q", got.AgentURL, want)
			}
			if got.CABundlePEM != seed.CABundlePEM {
				t.Error("pinned CA bundle changed on an agent_url refresh")
			}
		})
	}
}

func TestManager_CapsWithoutAgentMTLSKeepsWorking(t *testing.T) {
	e := newEnv(t, true)
	e.seed(false)
	e.fs.setCaps(false, "")
	e.fs.agent.Close()
	before, err := os.ReadFile(e.statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.fs.count(portMain, routeCheckin), 1, "main checkins")
	after, err := os.ReadFile(e.statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("mtls.json changed")
	}
}

func TestManager_CapsRefreshedHourly(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	m := e.manager()

	mustCycle(t, m)
	wantCount(t, e.fs.count(portMain, routeCaps), 1, "caps fetches at first cycle")

	e.clk.Advance(59 * time.Minute)
	mustCycle(t, m)
	wantCount(t, e.fs.count(portMain, routeCaps), 1, "caps fetches at +59m")

	e.clk.Advance(2 * time.Minute)
	mustCycle(t, m)
	wantCount(t, e.fs.count(portMain, routeCaps), 2, "caps fetches at +61m")
}

func TestManager_UnusableLoadedStateIsReprovisioned(t *testing.T) {
	e := newEnv(t, false)
	// The certificate parses (so Load accepts it) but the pinned bundle holds
	// no certificate, so TLSConfig fails.
	seed := e.seed(true, func(s *State) { s.CABundlePEM = "not a pem bundle" })
	m := e.manager()

	mustCycle(t, m)

	wantCount(t, e.logs.count(slog.LevelWarn, "unusable"), 1, "unusable-state WARNs")
	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests")
	got := e.mustState()
	if got.CABundlePEM != e.fs.ca.pem || !got.Committed {
		t.Error("state was not replaced by a fresh committed one")
	}
	logs := e.logs.all()
	for _, secret := range []string{"PRIVATE KEY", strings.Split(seed.KeyPEM, "\n")[1]} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs leak key material %q", secret)
		}
	}
}

func TestManager_ProvisionAfterEnroll(t *testing.T) {
	e := newEnv(t, false)
	m := e.manager()

	if err := m.Provision(t.Context()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := m.Provision(t.Context()); err != nil {
		t.Fatalf("second Provision: %v", err)
	}

	wantCount(t, e.fs.count(portMain, routeCert), 1, "main cert requests")
	wantCount(t, e.fs.countPort(portAgent, false), 0, "agent requests")
	if e.mustState().Committed {
		t.Error("Provision committed; only a successful agent-port probe may")
	}
}

func TestManager_ProvisionWithoutCapabilityIsNoop(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	m := e.manager()

	if err := m.Provision(t.Context()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	wantCount(t, e.fs.count(portMain, routeCert), 0, "main cert requests")
	if _, ok := e.state(); ok {
		t.Error("state written without the agent_mtls capability")
	}
}

func TestManager_ProvisionRefusesHTTP(t *testing.T) {
	e := newEnv(t, false)
	e.insecure = false
	m := e.manager()

	err := m.Provision(t.Context())

	if !errors.Is(err, ErrInsecureProvision) {
		t.Fatalf("err = %v, want ErrInsecureProvision", err)
	}
	wantCount(t, e.fs.count(portMain, routeCert), 0, "main cert requests")
}

func TestNewManager_DefaultsNowAndLog(t *testing.T) {
	e := newEnv(t, false)
	e.fs.setCaps(false, "")
	cfg := e.config()
	cfg.Now, cfg.Log = nil, nil

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mustCycle(t, m)
}

// failingTransport is a RoundTripper that fails every request with err.
type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// doErr returns the error http.Client.Do reports when the transport fails with err.
func doErr(t *testing.T, err error) error {
	t.Helper()
	req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://agent.invalid/agent/v1/checkin", nil)
	if rerr != nil {
		t.Fatalf("NewRequest: %v", rerr)
	}
	resp, got := (&http.Client{Transport: failingTransport{err}}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if got == nil {
		t.Fatal("Do succeeded through a failing transport")
	}
	return got
}

// Every agent-port error comes out of http.Client.Do (checkin.Client.do wraps
// it with %w), and Do wraps every transport failure in *url.Error, so the
// *url.Error check alone covers each TLS and x509 type.
func TestIsRoundTripFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"url error", &url.Error{Op: "Post", URL: "https://x", Err: errors.New("refused")}, true},
		{"wrapped url error", fmt.Errorf("checkin: %w", &url.Error{Err: errors.New("eof")}), true},
		{"verification error via Do", doErr(t, &tls.CertificateVerificationError{Err: errors.New("bad")}), true},
		{"unknown authority via Do", doErr(t, x509.UnknownAuthorityError{}), true},
		{"hostname error via Do", doErr(t, x509.HostnameError{}), true},
		{"invalid cert via Do", doErr(t, x509.CertificateInvalidError{}), true},
		{"transport error via Do, wrapped like checkin", fmt.Errorf("checkin: POST /agent/v1/checkin: %w", doErr(t, errors.New("refused"))), true},
		{"bare x509 error, not from Do", x509.UnknownAuthorityError{}, false},
		{"unauthorized", checkin.ErrUnauthorized, false},
		{"server error", checkin.ErrServer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRoundTripFailure(tt.err); got != tt.want {
				t.Errorf("isRoundTripFailure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// Real handshake failures against a TLS server: an unpinned CA and a name the
// certificate does not carry.
func TestIsRoundTripFailure_RealHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tests := []struct {
		name string
		cfg  *tls.Config
	}{
		{"unknown authority", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}},
		{"hostname mismatch", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "wrong.invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &http.Client{Transport: &http.Transport{TLSClientConfig: tt.cfg}, Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
				t.Fatalf("Do err = %v, want a certificate verification failure", err)
			}
			if !isRoundTripFailure(err) {
				t.Errorf("isRoundTripFailure(%v) = false, want true", err)
			}
		})
	}
}

// portOf returns the port of an httptest server URL.
func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Port()
}
