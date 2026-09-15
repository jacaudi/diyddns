// Package stale implements the #127 gateway-feed staleness policy: deciding
// when an address has gone too long unconfirmed to stay in the allow-list, and
// warning its owner before it does.
package stale

import "github.com/jacaudi/diyddns/internal/config"

// secondsPerDay converts the config's day-valued key into the seconds every
// computation here uses. Days appear ONLY at the config boundary: integer-day
// arithmetic inside FirstRung yields 0 for expire_after_days < 3, which would
// make every feed member a candidate on every hourly tick.
const secondsPerDay = 86400

// Window is how long an address may go unconfirmed, in seconds.
//
// One number, from one config key. There is no derived per-device window: see
// design §4.1 for why the adaptive one was cut -- chiefly that it never
// engaged for the stable-address lines a long window exists to protect.
func Window(cfg config.FeedSection) int64 {
	return int64(cfg.ExpireAfterDays) * secondsPerDay
}

// ExpiresAt is the instant one family's address stops being trustworthy.
//
// COMPUTED, never stored. Storing it would make the operator's config inert
// for exactly the silent devices the policy targets: lowering
// expire_after_days would never reach a device that had already stopped
// checking in, which is the entire population this exists for.
func ExpiresAt(confirmedAt, window int64) int64 { return confirmedAt + window }

// Rungs returns the four warning rungs as elapsed seconds (D11).
//
// W x {1/3, 2/3, 17/21, 20/21}, reproducing days 7/14/17/20 exactly at the
// default 21-day window and scaling proportionally elsewhere. D11's literal
// days are undefined for any other window, and expire_after_days accepts
// 0..36500, where 0 disables expiry entirely and is the documented operator
// opt-out.
//
// No merge rule is needed: minimum adjacent separation is W/7, which even at
// the smallest legal window (1 day) is 3.43 hours.
//
// Defined only for window > 0. Callers must gate on
// config.FeedSection.ExpiryEnabled() before calling in: at window == 0 all
// four rungs collapse onto 0, so none falls before removal and none is
// distinct from another -- see FirstRung and DueRung for what that collapse
// does to the sweep.
func Rungs(window int64) [4]int64 {
	return [4]int64{
		window / 3,
		2 * window / 3,
		17 * window / 21,
		20 * window / 21,
	}
}

// FirstRung is how far before expiry the sweep must already be looking at a
// device, in seconds.
//
// The first rung, NOT the window. With the window as the candidacy bound a
// device would first be seen already past expiry, every rung would be in the
// past, and they would all collapse into the removal notice -- the user gets
// zero warnings, silently.
//
// Defined only for cfg.ExpiryEnabled(); see Rungs. With expiry off,
// Window(cfg) is 0 and FirstRung returns a candidacy bound of 0, making
// every feed member a candidate on every hourly tick.
func FirstRung(cfg config.FeedSection) int64 { return Rungs(Window(cfg))[0] }

// DueRung returns the highest rung due at elapsed, or 0 for none.
//
// Highest, not lowest: after an outage, or on the first sweep following an
// upgrade, several can be due at once, and the device gets one notice rather
// than a burst (§7.1).
//
// Defined only for window > 0; see Rungs. At window == 0, DueRung returns
// the terminal rung 4 -- immediate removal -- for every device on the first
// call, regardless of elapsed.
func DueRung(window, elapsed int64) int {
	due := 0
	for i, at := range Rungs(window) {
		if elapsed >= at {
			due = i + 1
		}
	}
	return due
}
