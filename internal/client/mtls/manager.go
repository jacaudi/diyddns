package mtls

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/enroll"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
)

const (
	// capsRefresh is how long fetched capabilities stay current.
	capsRefresh = time.Hour
	// warnEvery rate-limits the repeating WARNs (probation, refused provisioning).
	warnEvery = 24 * time.Hour
	// renewBefore is how close to NotAfter the device cert is renewed.
	renewBefore = 60 * 24 * time.Hour
)

// ErrInsecureProvision means provisioning was refused because the main port is
// plain http:// and the operator did not opt in.
var ErrInsecureProvision = errors.New("mtls: refusing to provision over http:// (set --insecure-provision / run.insecure_provision to override)")

// ErrAgentUnavailable means a committed device could not complete a round trip
// with the agent port (unreachable, or the server chain fails the pin). It is a
// hard error: the Manager never falls back to the main port after commit.
var ErrAgentUnavailable = errors.New("mtls: agent port failed after commit")

// Config configures a Manager. Log and Now default when nil.
type Config struct {
	// StatePath is where mtls.json lives (see PathFor).
	StatePath string
	Creds     credentials.Credentials
	// CACertPath trusts a private CA on the main port.
	CACertPath string
	// InsecureProvision allows provisioning over an http:// main port.
	InsecureProvision bool
	Log               *slog.Logger
	Now               func() time.Time

	// Discovery is run.ip_discovery: config.IPDiscoveryAuto, IPDiscoveryAlways or
	// IPDiscoveryNever. The zero value is always: one unpinned request carrying
	// the report as given, with no family logic.
	Discovery string
	// Families are the families auto and never check in over, IPv4 before IPv6.
	Families []ipdiscovery.Family
	// Lookup resolves one family's public address. It is required in auto and
	// unused otherwise.
	Lookup func(context.Context, ipdiscovery.Family) ipdiscovery.Result
}

// active is the loaded state plus what is derived from it. The agent clients are
// rebuilt whenever the state changes (new TLSConfig, new AgentURL).
type active struct {
	state    State
	agent    *checkin.Client
	pinned   map[ipdiscovery.Family]*checkin.Client // agent, one per enabled family
	notAfter time.Time
}

// Manager decides, per check-in cycle, whether a device talks to the main port
// or the mTLS agent port, and keeps the device certificate provisioned,
// committed and renewed. It satisfies poller.Checkiner. It is not safe for
// concurrent use: the poller calls it from one goroutine.
type Manager struct {
	cfg        Config
	keys       *checkin.Keys // shared by every checkin client below
	main       *checkin.Client
	pinnedMain map[ipdiscovery.Family]*checkin.Client // main, one per enabled family
	enroll     *enroll.Client
	mainHTTPS  bool

	cur *active // nil when the device holds no usable mTLS state

	caps   enroll.Capabilities
	capsAt time.Time // zero until the first successful fetch

	fam map[ipdiscovery.Family]*familyState // one per enabled family

	lastInsecureWarn     time.Time
	lastProbationWarn    time.Time
	lastNeverUnsupported time.Time
}

// normalizeConfig applies cfg's defaults and validates ip_discovery. It is split
// out of NewManager to keep that function under the gocyclo limit.
func normalizeConfig(cfg Config) (Config, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	switch cfg.Discovery {
	case "":
		cfg.Discovery = config.IPDiscoveryAlways
	case config.IPDiscoveryAlways, config.IPDiscoveryNever:
	case config.IPDiscoveryAuto:
		if cfg.Lookup == nil {
			return cfg, errors.New("mtls: ip_discovery auto needs a Lookup")
		}
	default:
		return cfg, fmt.Errorf("mtls: unknown ip_discovery %q", cfg.Discovery)
	}
	if cfg.Discovery == config.IPDiscoveryAlways {
		cfg.Families = nil // always sends one unpinned request; no family state, no pinned clients
	}
	return cfg, nil
}

// NewManager builds the main-port clients from cfg.Creds.ServerURL and
// cfg.CACertPath and loads any saved state. State that loads but cannot be used
// (for example an unparseable pinned bundle) is deleted like a corrupt file, so
// the device provisions again.
func NewManager(cfg Config) (*Manager, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	keys, err := checkin.NewKeys(cfg.Creds.Secret, "")
	if err != nil {
		return nil, fmt.Errorf("mtls: main client: %w", err)
	}
	mainClient, err := checkin.NewClient(cfg.Creds.ServerURL, cfg.Creds.DeviceID, keys, checkin.Options{CACertPath: cfg.CACertPath})
	if err != nil {
		return nil, fmt.Errorf("mtls: main client: %w", err)
	}
	enrollClient, err := enroll.NewClient(cfg.Creds.ServerURL, enroll.ClientOptions{CACertPath: cfg.CACertPath})
	if err != nil {
		return nil, fmt.Errorf("mtls: capabilities client: %w", err)
	}
	m := &Manager{
		cfg:       cfg,
		keys:      keys,
		main:      mainClient,
		enroll:    enrollClient,
		mainHTTPS: strings.HasPrefix(mainClient.BaseURL(), "https://"),
		fam:       make(map[ipdiscovery.Family]*familyState, len(cfg.Families)),
	}
	for _, f := range cfg.Families {
		m.fam[f] = &familyState{lastWarn: map[string]time.Time{}}
	}
	if m.pinnedMain, err = m.pinnedClients(cfg.Creds.ServerURL, checkin.Options{CACertPath: cfg.CACertPath}); err != nil {
		return nil, fmt.Errorf("mtls: main client: %w", err)
	}

	s, err := Load(cfg.StatePath, cfg.Creds.DeviceID, cfg.Log)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return nil, err
	default:
		cur, err := m.activate(s)
		if err != nil {
			m.drop("mtls state unusable; deleted, will provision again", err)
			break
		}
		m.cur = cur
	}
	return m, nil
}

// Provision fetches capabilities and, when the server advertises agent_mtls and
// the device has no state, provisions a certificate over the main port. It is
// for use right after enroll; the state it saves is on probation.
func (m *Manager) Provision(ctx context.Context) error {
	if err := m.refreshCaps(ctx); err != nil {
		return fmt.Errorf("mtls: fetch capabilities: %w", err)
	}
	if m.cur != nil || m.caps.AgentMTLS == nil {
		return nil
	}
	return m.provisionOnce(ctx)
}

// Checkin runs one check-in cycle: refresh capabilities, drop an expired
// certificate, provision, probe (probation), renew, then check in on the agent
// port. At most one provisioning attempt is made per cycle. Once committed the
// agent port is the only path; the main port is used only before commit, when
// provisioning failed, or when the device has no state. Only the final check-in
// is per address family (see checkinFamilies); everything before it runs once.
func (m *Manager) Checkin(ctx context.Context, r checkin.Report) (checkin.Result, error) {
	if err := m.refreshCaps(ctx); err != nil {
		m.cfg.Log.Warn("capabilities fetch failed; keeping previous", "error", err)
	}
	if m.cur != nil && !m.cfg.Now().Before(m.cur.notAfter) {
		m.drop("device certificate expired; will provision again", nil)
	}

	provisioned := false
	for {
		if !provisioned && m.cur == nil && m.caps.AgentMTLS != nil {
			provisioned = true
			m.tryProvision(ctx)
		}
		if m.cur == nil {
			return m.checkinFamilies(ctx, m.main, m.pinnedMain, r)
		}
		m.refreshAgentURL()
		if !m.cur.state.Committed && !m.probe(ctx) {
			if m.cur == nil {
				continue // rejected during probation: provision again, or fall to main
			}
			return m.checkinFamilies(ctx, m.main, m.pinnedMain, r)
		}
		m.renew(ctx)
		res, err := m.checkinFamilies(ctx, m.cur.agent, m.cur.pinned, r)
		if errors.Is(err, checkin.ErrClientCertRejected) {
			m.drop("agent port rejected our client certificate; will provision again", nil)
			continue
		}
		return res, agentError(err)
	}
}

// refreshCaps fetches capabilities when never fetched or capsRefresh elapsed.
// On failure the previous capabilities stay.
func (m *Manager) refreshCaps(ctx context.Context) error {
	now := m.cfg.Now()
	if !m.capsAt.IsZero() && now.Sub(m.capsAt) < capsRefresh {
		return nil
	}
	caps, err := m.enroll.Capabilities(ctx)
	if err != nil {
		return err
	}
	m.caps, m.capsAt = caps, now
	return nil
}

// tryProvision provisions once and reports the outcome in the log; failures
// leave the device without state, so the cycle continues on the main port.
func (m *Manager) tryProvision(ctx context.Context) {
	switch err := m.provisionOnce(ctx); {
	case err == nil:
	case errors.Is(err, ErrInsecureProvision):
		m.warnThrottled(&m.lastInsecureWarn, "refusing to provision mTLS", "error", err)
	case errors.Is(err, checkin.ErrCertAlreadyIssued):
		m.cfg.Log.Error(`the server still records a live certificate for this device: ask an admin to click "Reset certificate" on the device's admin page; this client then provisions again on its own`)
	default:
		m.cfg.Log.Warn("mtls provisioning failed; continuing on the main port", "error", err)
	}
}

// provisionOnce requests a certificate over the main port and saves it on
// probation (Committed=false). Over http:// it needs InsecureProvision, and then
// WARNs every time.
func (m *Manager) provisionOnce(ctx context.Context) error {
	if !m.mainHTTPS {
		if !m.cfg.InsecureProvision {
			return ErrInsecureProvision
		}
		m.cfg.Log.Warn("provisioning mTLS over insecure http://: a network attacker can replace the pinned CA")
	}
	s, err := m.issue(ctx, m.main, false)
	if err != nil {
		return err
	}
	return m.persist(s)
}

// issue generates a fresh key and CSR and has c (the main client, or the agent
// client for renewal) sign it.
func (m *Manager) issue(ctx context.Context, c *checkin.Client, committed bool) (State, error) {
	keyPEM, csrPEM, err := NewKeyAndCSR(m.cfg.Creds.DeviceID)
	if err != nil {
		return State{}, err
	}
	resp, err := c.RequestCert(ctx, csrPEM)
	if err != nil {
		return State{}, fmt.Errorf("mtls: request certificate: %w", err)
	}
	return State{
		DeviceID:    m.cfg.Creds.DeviceID,
		KeyPEM:      string(keyPEM),
		CertPEM:     resp.Certificate,
		CABundlePEM: resp.CABundle,
		AgentURL:    resp.AgentURL,
		Committed:   committed,
	}, nil
}

// refreshAgentURL adopts a changed agent_url, but only when the capabilities
// came over HTTPS: over http:// they are not trustworthy. The pin is untouched.
func (m *Manager) refreshAgentURL() {
	if !m.mainHTTPS || m.caps.AgentMTLS == nil || m.caps.AgentMTLS.AgentURL == m.cur.state.AgentURL {
		return
	}
	s := m.cur.state
	s.AgentURL = m.caps.AgentMTLS.AgentURL
	if err := m.persist(s); err != nil {
		m.cfg.Log.Warn("could not adopt the advertised agent_url", "error", err)
	}
}

// probe makes one Self call on the agent port. Success commits the state and
// returns true. A rejected certificate drops the state (the caller may provision
// again); any other failure is a rate-limited probation WARN. Both return false.
func (m *Manager) probe(ctx context.Context) bool {
	err := m.cur.agent.Self(ctx)
	switch {
	case err == nil:
		s := m.cur.state
		s.Committed = true
		if err := m.persist(s); err != nil {
			m.cfg.Log.Warn("could not record the mtls commit; staying on probation", "error", err)
			return false
		}
		return true
	case errors.Is(err, checkin.ErrClientCertRejected):
		m.drop("agent port rejected our client certificate during probation; will provision again", nil)
	default:
		m.warnThrottled(&m.lastProbationWarn, "mtls probation: agent port not usable yet; still checking in on the main port", "error", err)
	}
	return false
}

// renew swaps in a fresh certificate over the agent port when fewer than
// renewBefore remain. Failure is a WARN; the old certificate keeps working.
func (m *Manager) renew(ctx context.Context) {
	if m.cur.notAfter.Sub(m.cfg.Now()) >= renewBefore {
		return
	}
	s, err := m.issue(ctx, m.cur.agent, true)
	if err == nil {
		err = m.persist(s)
	}
	if err != nil {
		m.cfg.Log.Warn("mtls certificate renewal failed; will retry next cycle", "error", err)
	}
}

// activate parses s and builds its agent client. It does not touch the disk.
func (m *Manager) activate(s State) (*active, error) {
	leaf, err := s.Leaf()
	if err != nil {
		return nil, err
	}
	tc, err := s.TLSConfig()
	if err != nil {
		return nil, err
	}
	opts := checkin.Options{TLSConfig: tc}
	agent, err := checkin.NewClient(s.AgentURL, m.cfg.Creds.DeviceID, m.keys, opts)
	if err != nil {
		return nil, err
	}
	pinned, err := m.pinnedClients(s.AgentURL, opts)
	if err != nil {
		return nil, err
	}
	return &active{state: s, agent: agent, pinned: pinned, notAfter: leaf.NotAfter}, nil
}

// pinnedClients builds one client per enabled family for baseURL, each pinned to
// its family's network. opts carries the trust settings.
func (m *Manager) pinnedClients(baseURL string, opts checkin.Options) (map[ipdiscovery.Family]*checkin.Client, error) {
	out := make(map[ipdiscovery.Family]*checkin.Client, len(m.cfg.Families))
	for _, f := range m.cfg.Families {
		opts.Network = networkOf(f)
		c, err := checkin.NewClient(baseURL, m.cfg.Creds.DeviceID, m.keys, opts)
		if err != nil {
			return nil, err
		}
		out[f] = c
	}
	return out, nil
}

// persist activates s, saves it and only then makes it current, so an unusable
// state (say a bad bundle in a server response) never reaches the disk.
func (m *Manager) persist(s State) error {
	a, err := m.activate(s)
	if err != nil {
		return err
	}
	if err := Save(m.cfg.StatePath, s); err != nil {
		return err
	}
	m.cur = a
	return nil
}

// drop forgets the current state and deletes mtls.json. cause may be nil. It
// never logs the state: it holds the device key.
func (m *Manager) drop(msg string, cause error) {
	attrs := make([]any, 0, 4)
	if cause != nil {
		attrs = append(attrs, "error", cause)
	}
	if err := Remove(m.cfg.StatePath); err != nil {
		attrs = append(attrs, "remove_error", err)
	}
	m.cur = nil
	m.cfg.Log.Warn(msg, attrs...)
}

// due reports whether a message throttled by last is due, and if so starts a
// new warnEvery window.
func (m *Manager) due(last *time.Time) bool {
	now := m.cfg.Now()
	if !last.IsZero() && now.Sub(*last) < warnEvery {
		return false
	}
	*last = now
	return true
}

// warnThrottled logs a WARN at most once per warnEvery, tracked in last.
func (m *Manager) warnThrottled(last *time.Time, msg string, args ...any) {
	if m.due(last) {
		m.cfg.Log.Warn(msg, args...)
	}
}

// agentError turns an agent-port round-trip failure into ErrAgentUnavailable
// with the operator action. Everything else (ErrUnauthorized, ErrServer, ...)
// passes through unchanged so callers, notably the poller's unauthorized
// counter, still see the original sentinel.
func agentError(err error) error {
	if err == nil || !isRoundTripFailure(err) {
		return err
	}
	return fmt.Errorf("%w: %w; if this persists, run \"diyddns-client mtls reset\" and ask an admin to click \"Reset certificate\" for this device", ErrAgentUnavailable, err)
}

// isRoundTripFailure reports a transport or TLS-verification failure: no usable
// answer came back from the agent port. Every such error comes out of
// http.Client.Do, which wraps it in *url.Error.
func isRoundTripFailure(err error) bool {
	_, ok := errors.AsType[*url.Error](err)
	return ok
}
