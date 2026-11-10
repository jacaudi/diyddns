package mtls

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/config"
)

// probeEvery is how long a family stays on lookup before one address-less,
// family-pinned request asks the server again whether it can see this host.
const probeEvery = time.Hour

// ErrNoFamily means a cycle had no address family to check in over: always mode
// with nothing to report, or no family enabled.
var ErrNoFamily = errors.New("mtls: no address family to check in")

// The reasons a family looks its address up (the fallback WARN's reason
// attribute). The last two are what a family's familyState.reason holds.
const (
	reasonCapsUnfetched = "capabilities not fetched"
	reasonOldServer     = "old server"
	reasonNone          = "none"
	reasonSkipped       = "skipped"
)

// The client's reading of the server's ip_source values (internal/server/service
// owns the contract; the client never imports the server).
const (
	sourceReported = "reported"
	sourceObserved = "observed"
	sourceNone     = "none"
)

// WARN kinds, each rate-limited per family by warnEvery.
const (
	kindFallback      = "fallback"
	kindMissingSource = "missing_source"
	kindUnknownSource = "unknown_source"
	kindNeverNone     = "never_none"
)

// familyState is one family's memory across cycles. lookup is true while the
// server did not see a public address for the family (reason says why, and
// lastProbe when it last tried); lastWarn rate-limits the family's WARNs by kind.
type familyState struct {
	lookup    bool
	reason    string
	lastProbe time.Time
	lastWarn  map[string]time.Time
}

// networkOf is the net.Dial network a family-pinned client connects with.
func networkOf(f ipdiscovery.Family) string {
	if f == ipdiscovery.FamilyV6 {
		return "tcp6"
	}
	return "tcp4"
}

// reportFor is r carrying only addr for family f ("" carries no address).
func reportFor(r checkin.Report, f ipdiscovery.Family, addr string) checkin.Report {
	r.IPv4, r.IPv6 = "", ""
	if f == ipdiscovery.FamilyV6 {
		r.IPv6 = addr
	} else {
		r.IPv4 = addr
	}
	return r
}

// sourceFor is f's ip_source value in s.
func sourceFor(s checkin.IPSource, f ipdiscovery.Family) string {
	if f == ipdiscovery.FamilyV6 {
		return s.IPv6
	}
	return s.IPv4
}

// withSource is s with f's value set to v.
func withSource(s checkin.IPSource, f ipdiscovery.Family, v string) checkin.IPSource {
	if f == ipdiscovery.FamilyV6 {
		s.IPv6 = v
	} else {
		s.IPv4 = v
	}
	return s
}

// checkinFamilies sends the cycle's final check-in over unpinned or the
// family-pinned clients, per run.ip_discovery.
//
// always sends one unpinned request carrying r as given. auto and never send,
// for each enabled family in order, one request carrying no address over that
// family's pinned client so the server records the address it sees; auto
// instead looks the address up, and reports it over unpinned, for a family the
// server cannot observe.
//
// A family whose pinned dial fails is skipped. The cycle succeeds when at least
// one family checked in; otherwise it fails with the joined per-family errors,
// so errors.Is still finds checkin.ErrUnauthorized.
func (m *Manager) checkinFamilies(ctx context.Context, unpinned *checkin.Client, pinned map[ipdiscovery.Family]*checkin.Client, r checkin.Report) (checkin.Result, error) {
	if m.cfg.Discovery == config.IPDiscoveryAlways {
		if r.IPv4 == "" && r.IPv6 == "" {
			return checkin.Result{}, ErrNoFamily
		}
		return unpinned.Checkin(ctx, r)
	}
	m.checkNeverSupported()

	var (
		out           checkin.Result
		ok            bool
		failed, dials []error
	)
	for _, f := range m.cfg.Families {
		res, skipped, err := m.checkinFamily(ctx, f, unpinned, pinned[f], r)
		switch {
		case errors.Is(err, checkin.ErrClientCertRejected):
			// The credential is fine, the certificate is not: Checkin drops the
			// state and starts the cycle over, so no family's answer matters.
			return checkin.Result{}, err
		case skipped:
			dials = append(dials, err)
		case err != nil:
			failed = append(failed, err)
		default:
			// The cycle's result is the last answer, with Stored and the rotation
			// request OR-ed across families and each family's ip_source taken from its
			// own response.
			res.Stored = res.Stored || out.Stored
			res.Rotation.Secret = res.Rotation.Secret || out.Rotation.Secret
			res.Rotation.Cert = res.Rotation.Cert || out.Rotation.Cert
			res.IPSource = withSource(out.IPSource, f, sourceFor(res.IPSource, f))
			out, ok = res, true
		}
	}
	switch {
	case ok:
		for _, err := range failed {
			m.cfg.Log.Warn("check-in failed for one address family; the other succeeded", "error", err)
		}
		return out, nil
	case len(failed) > 0:
		return checkin.Result{}, errors.Join(failed...)
	case len(dials) > 0:
		return checkin.Result{}, errors.Join(dials...)
	default:
		return checkin.Result{}, ErrNoFamily
	}
}

// checkNeverSupported logs, at most once a day, that a never-mode device is
// talking to a server that cannot record observed addresses: every check-in
// then records nothing. Unfetched capabilities say nothing either way.
func (m *Manager) checkNeverSupported() {
	if m.cfg.Discovery != config.IPDiscoveryNever || m.capsAt.IsZero() || m.caps.ObservedIP {
		return
	}
	if m.due(&m.lastNeverUnsupported) {
		m.cfg.Log.Error("server does not support observed IPs and run.ip_discovery is never; nothing is being recorded")
	}
}

// checkinFamily runs one family's attempt. skipped is true, with err the dial
// failure, when the family's pinned client could not connect: the family is
// unreachable from this host and the caller moves on.
func (m *Manager) checkinFamily(ctx context.Context, f ipdiscovery.Family, unpinned, pinned *checkin.Client, r checkin.Report) (res checkin.Result, skipped bool, err error) {
	st := m.fam[f]
	lookup, reason := m.plan(st)
	if lookup {
		m.warnFamily(f, st, kindFallback, "server did not observe a public address; looking it up for this family", "reason", reason)
		addr := m.cfg.Lookup(ctx, f)
		if !addr.OK {
			return checkin.Result{}, false, fmt.Errorf("lookup %s: no quorum", f)
		}
		// A looked-up address is reported, so it goes over the unpinned client.
		res, err = unpinned.Checkin(ctx, reportFor(r, f, addr.Addr.String()))
		if err != nil {
			return checkin.Result{}, false, fmt.Errorf("%s check-in: %w", f, err)
		}
		return res, false, nil
	}

	res, err = pinned.Checkin(ctx, reportFor(r, f, ""))
	switch {
	case checkin.IsDialSkip(err):
		m.skip(f, st, err)
		return checkin.Result{}, true, err
	case err != nil:
		return checkin.Result{}, false, fmt.Errorf("%s check-in: %w", f, err)
	}
	m.settle(f, st, res.IPSource)
	return res, false, nil
}

// plan decides whether f looks its address up this cycle, and why. Only auto
// does, for a server that cannot observe addresses (or whose capabilities are
// unknown) and for a family the server recently could not see. Such a family is
// re-asked, address-less and pinned, once per probeEvery; that probe is not a
// lookup, and the cycle's answer decides the family's state again.
func (m *Manager) plan(st *familyState) (lookup bool, reason string) {
	if m.cfg.Discovery != config.IPDiscoveryAuto {
		return false, ""
	}
	switch {
	case m.capsAt.IsZero():
		return true, reasonCapsUnfetched
	case !m.caps.ObservedIP:
		return true, reasonOldServer
	case !st.lookup:
		return false, ""
	case m.cfg.Now().Sub(st.lastProbe) >= probeEvery:
		st.lastProbe = m.cfg.Now()
		return false, ""
	default:
		return true, st.reason
	}
}

// skip records that f's pinned dial failed. auto then looks the family up from
// the next cycle on and probes again in an hour; never has no lookup to fall
// back to and just tries again next cycle.
func (m *Manager) skip(f ipdiscovery.Family, st *familyState, err error) {
	m.cfg.Log.Debug("address family unreachable; skipping it", "family", f.String(), "error", err)
	if m.cfg.Discovery == config.IPDiscoveryAuto {
		st.lookup, st.reason, st.lastProbe = true, reasonSkipped, m.cfg.Now()
	}
}

// settle reads f's ip_source from an address-less check-in and moves the
// family's state. "observed" is the goal; "reported" cannot come back for an
// address-less request and changes nothing; "none", a missing value and an
// unknown value all mean the server recorded no address for f. A missing value
// from a server that never advertised observed_ip is just an old server.
func (m *Manager) settle(f ipdiscovery.Family, st *familyState, src checkin.IPSource) {
	v := sourceFor(src, f)
	if v == "" && !m.caps.ObservedIP {
		return
	}
	switch v {
	case sourceObserved:
		st.lookup = false
		return
	case sourceReported:
		return
	case sourceNone:
	case "":
		m.warnFamily(f, st, kindMissingSource, "server response carried no ip_source for this family; treating it as none")
	default:
		m.warnFamily(f, st, kindUnknownSource, "server response carried an unknown ip_source value; treating it as none", "value", v)
	}
	switch m.cfg.Discovery {
	case config.IPDiscoveryAuto:
		st.lookup, st.reason, st.lastProbe = true, reasonNone, m.cfg.Now()
	case config.IPDiscoveryNever:
		m.warnFamily(f, st, kindNeverNone, "server recorded no address for this family; set run.ip_discovery to auto or always")
	}
}

// warnFamily logs a WARN about f at most once per warnEvery for each kind.
func (m *Manager) warnFamily(f ipdiscovery.Family, st *familyState, kind, msg string, args ...any) {
	last := st.lastWarn[kind]
	if m.due(&last) {
		st.lastWarn[kind] = last
		m.cfg.Log.Warn(msg, append([]any{"family", f.String()}, args...)...)
	}
}
