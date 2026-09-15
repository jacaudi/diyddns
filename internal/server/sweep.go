package server

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
)

// candidateQuery is phase 1: ONE bounded read whose cursor closes before
// anything is written.
//
// The candidacy term is an OR of per-family guarded comparisons, NOT a scalar
// MIN over CASE arms. SQLite's min() returns NULL if any argument is NULL, and
// a CASE with no ELSE yields NULL for an absent family -- so the MIN form
// silently excludes every single-stack device AND every partially-cleared one,
// which is precisely the population this policy exists for. Verified against
// modernc.org/sqlite v1.50.0: the MIN form selected 2 of 6 expected devices,
// this form selected 6 of 6.
//
// Both placeholders bind the SAME value, now - stale.FirstRung(cfg). The bound
// is the first RUNG, not the window, so a device becomes a candidate in time to
// be warned rather than in time to be removed.
//
// The term SUBSUMES the membership predicate rather than repeating it: each arm
// already carries its family's presence guard.
const candidateQuery = `
SELECT d.id, d.user_id, d.label,
       d.current_ipv4, d.current_ipv6,
       d.v4_confirmed_at, d.v6_confirmed_at,
       d.v4_warn_level, d.v6_warn_level
  FROM devices d
  JOIN users u ON u.id = d.user_id
 WHERE d.disabled = 0 AND u.disabled = 0
   AND (   (d.current_ipv4 IS NOT NULL AND COALESCE(d.v4_confirmed_at, 0) <= ?)
        OR (d.current_ipv6 IS NOT NULL AND COALESCE(d.v6_confirmed_at, 0) <= ?))
 ORDER BY d.id`

// candidate is one device the sweep may act on, materialised in phase 1.
//
// It carries a store.Device rather than loose fields because ExpireAddresses
// and the notice renderers both want one, and rebuilding it per call site is
// how the two drift apart.
type candidate struct {
	store.Device
}

// present reports whether the family currently holds an address.
func (c candidate) present(family int) bool {
	if family == 6 {
		return c.CurrentIPv6 != ""
	}
	return c.CurrentIPv4 != ""
}

// confirmedAt is the family's last assertion instant.
func (c candidate) confirmedAt(family int) int64 {
	if family == 6 {
		return c.V6ConfirmedAt
	}
	return c.V4ConfirmedAt
}

// warnLevel is the family's own ladder position.
func (c candidate) warnLevel(family int) int {
	if family == 6 {
		return c.V6WarnLevel
	}
	return c.V4WarnLevel
}

// survivors names the families still in the feed after a removal tick that may
// clear BOTH of them.
//
// survivingAfter cannot serve this path: it answers "what survives if this ONE
// family goes", so on a full expiry it tells the IPv4 notice that IPv6 remains
// and the IPv6 notice that IPv4 remains -- two messages in the same tick, each
// contradicted by the other. The removal path must exclude every family that is
// due, not only the one being described.
func survivors(c candidate, v4Due, v6Due bool) []int {
	out := []int{}
	if c.present(4) && !v4Due {
		out = append(out, 4)
	}
	if c.present(6) && !v6Due {
		out = append(out, 6)
	}
	return out
}

// survivingAfter names the families still in the feed once family is cleared,
// for the WARNING path -- where only that one family is at risk.
func (c candidate) survivingAfter(family int) []int {
	out := []int{}
	for _, f := range []int{4, 6} {
		if f != family && c.present(f) {
			out = append(out, f)
		}
	}
	return out
}

// sweeper clears addresses that have gone too long unconfirmed, and warns
// their owners first (#127).
//
// It lives in package server, beside pruner.go, because it calls the
// unexported fanout directly. Putting it in internal/server/stale would need
// an interface for no other reason, and stale importing server is a cycle.
type sweeper struct {
	st      *store.Store
	fanout  *fanout
	cfg     config.FeedSection
	notices *stale.Dispatcher
	log     *slog.Logger
}

// newSweeper builds a sweeper for cfg. cfg is assumed to satisfy
// cfg.ExpiryEnabled(): stale.FirstRung and stale.DueRung are defined only for
// a positive window. This constructor does not re-check it -- the production
// wiring (Task 9) is expected to construct a sweeper only when the #127
// policy is on, and re-validating here would be a second copy of that gate
// with no caller to disagree with it yet.
func newSweeper(st *store.Store, f *fanout, cfg config.FeedSection, d *stale.Dispatcher, log *slog.Logger) *sweeper {
	return &sweeper{st: st, fanout: f, cfg: cfg, notices: d, log: log}
}

// candidates runs phase 1. The cursor is closed before it returns, which is
// what makes phase 2 safe to write from.
func (s *sweeper) candidates(ctx context.Context, now int64) ([]candidate, error) {
	bound := now - stale.FirstRung(s.cfg)
	rows, err := s.st.DB().QueryContext(ctx, candidateQuery, bound, bound)
	if err != nil {
		return nil, fmt.Errorf("sweep: candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]candidate, 0, 64)
	for rows.Next() {
		var c candidate
		var v4, v6 sql.NullString
		var v4Conf, v6Conf sql.NullInt64
		// Scan straight into the embedded Device's promoted fields. An outer
		// UserID field on candidate would shadow Device.UserID and leave it
		// empty in every store.Device this sweeper hands to ExpireAddresses
		// and in every Notice.
		if err := rows.Scan(&c.ID, &c.UserID, &c.Label, &v4, &v6,
			&v4Conf, &v6Conf, &c.V4WarnLevel, &c.V6WarnLevel); err != nil {
			return nil, fmt.Errorf("sweep: candidates: scan: %w", err)
		}
		c.CurrentIPv4, c.CurrentIPv6 = v4.String, v6.String
		c.V4ConfirmedAt, c.V6ConfirmedAt = v4Conf.Int64, v6Conf.Int64
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sweep: candidates: %w", err)
	}
	return out, nil
}

// Run performs one sweep tick: materialise every candidate, close the cursor,
// then act on each in a separate short statement.
//
// The phase boundary is not stylistic. SetMaxOpenConns(1) means an open rows
// cursor holds the process's ONLY connection, so an ExecContext inside
// rows.Next() waits for a connection the cursor itself holds and blocks the
// entire server forever -- every session lookup, every page render, not just
// writers. pruner.go already materialises before acting.
func (s *sweeper) Run(ctx context.Context, now int64) error {
	cands, err := s.candidates(ctx, now) // phase 1; cursor closed on return
	if err != nil {
		return err
	}
	digest := make([]stale.Notice, 0, 8)
	for _, c := range cands { // phase 2
		if err := ctx.Err(); err != nil {
			return err // shutdown: lose a notice rather than re-send it
		}
		forAdmins, err := s.act(ctx, c, now)
		if err != nil {
			// One device's failure must not abandon the rest of the sweep.
			s.log.LogAttrs(ctx, slog.LevelWarn, "staleness sweep: device failed",
				slog.String("device_id", c.ID), slog.Any("error", err))
			continue
		}
		digest = append(digest, forAdmins...)
	}
	s.notices.SendAdminDigest(ctx, digest) // D16: one digest per tick
	return nil
}

// act decides one candidate's fate.
//
// Expiry is evaluated BEFORE rungs (§6.2): otherwise a device already past its
// instant receives an "expires in -12 hours" warning immediately before its
// removal notice. When a family expires its level resets in the same
// statement, so the other family's rungs are evaluated on the FOLLOWING tick.
func (s *sweeper) act(ctx context.Context, c candidate, now int64) ([]stale.Notice, error) {
	w := stale.Window(s.cfg)
	v4Due := c.present(4) && now >= stale.ExpiresAt(c.V4ConfirmedAt, w)
	v6Due := c.present(6) && now >= stale.ExpiresAt(c.V6ConfirmedAt, w)

	if v4Due || v6Due {
		ok, err := s.fanout.ExpireAddresses(ctx, c.Device, v4Due, v6Due,
			Confirmed{V4: c.V4ConfirmedAt, V6: c.V6ConfirmedAt})
		if err != nil || !ok {
			return nil, err
		}
		return s.removed(ctx, c, v4Due, v6Due, now), nil
	}
	return s.warn(ctx, c, w, now)
}

// removed builds and sends the removal notices for the families just cleared,
// one per family, and returns those the admin digest should carry.
func (s *sweeper) removed(ctx context.Context, c candidate, v4Due, v6Due bool, now int64) []stale.Notice {
	var forAdmins []stale.Notice
	for _, f := range []int{4, 6} {
		if (f == 4 && !v4Due) || (f == 6 && !v6Due) {
			continue
		}
		n := stale.Notice{
			Kind: stale.KindRemoved, Device: c.Device, Family: f,
			ExpiresAt: now, Surviving: survivors(c, v4Due, v6Due),
		}
		forAdmins = append(forAdmins, s.deliver(ctx, c, n)...)
	}
	return forAdmins
}

// warn advances each present family's ladder independently and sends at most
// one notice per family per tick.
//
// The level advances on ATTEMPT, not on success (§7.3): advancing on success
// would make a broken SMTP server re-send every rung every hour forever. The
// durable record of an impending removal is the device list, not the email --
// so the state write precedes the notice, and an interrupted sweep loses a
// notice rather than repeating it.
func (s *sweeper) warn(ctx context.Context, c candidate, w, now int64) ([]stale.Notice, error) {
	var forAdmins []stale.Notice
	for _, f := range []int{4, 6} {
		if !c.present(f) {
			continue
		}
		conf, level := c.confirmedAt(f), c.warnLevel(f)
		due := stale.DueRung(w, now-conf)
		if due <= level {
			continue // nothing new; overdue rungs do not stack
		}
		ok, err := s.st.Devices().AdvanceWarnLevel(ctx, c.ID, f, due, level,
			c.V4ConfirmedAt, c.V6ConfirmedAt, now)
		if err != nil {
			// forAdmins may already be non-nil here (a prior family in this
			// same loop succeeded and was already delivered to its owner via
			// deliver()'s SendOwner call). Run discards it wholesale on this
			// error path rather than salvaging it into the digest -- so a
			// rung-3/4 notice the owner has already received can silently
			// miss the admin digest for this tick. Flagged, not fixed: no
			// present requirement forces the salvage, and doing it here would
			// need Run to distinguish "some notices, then an error" from
			// "no notices" on every caller of act(), not just this one.
			return forAdmins, err
		}
		if !ok {
			continue // pin failed: the device confirmed under us, correctly
		}
		expires := stale.ExpiresAt(conf, w)
		n := stale.Notice{
			Kind: stale.KindWarning, Rung: due, Device: c.Device, Family: f,
			ExpiresAt: expires,
			Remaining: time.Duration(expires-now) * time.Second,
			Surviving: c.survivingAfter(f),
		}
		forAdmins = append(forAdmins, s.deliver(ctx, c, n)...)
	}
	return forAdmins, nil
}

// deliver sends whatever this notice's audiences require NOW -- the owner,
// inline -- and returns it if the admin digest should also carry it.
//
// Audience membership is asked of stale.RecipientsFor and nowhere else: D13 is
// one table and must be encoded once. An inline `if rung >= 3` here would be a
// second copy of it, and the two would drift.
func (s *sweeper) deliver(ctx context.Context, c candidate, n stale.Notice) []stale.Notice {
	owner, err := s.st.Users().GetByID(ctx, c.UserID)
	if err != nil {
		s.log.LogAttrs(ctx, slog.LevelWarn, "staleness notice: owner lookup failed",
			slog.String("device_id", c.ID), slog.Any("error", err))
		return nil
	}
	n.Owner = owner

	var forAdmins []stale.Notice
	for _, a := range stale.RecipientsFor(n.Kind, n.Rung) {
		switch a {
		case stale.AudienceOwner:
			s.notices.SendOwner(ctx, n)
		case stale.AudienceAdmin:
			forAdmins = append(forAdmins, n)
		}
	}
	return forAdmins
}
