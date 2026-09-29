package email

import (
	"strconv"
	"time"
)

// FormatDuration renders a registration link's lifetime or remaining time in
// words, for every surface that states it (#179): the admin pages and the
// grant emails, so one link never reads as two different windows. It rounds
// UP to the next whole minute (a 61-second remainder reads "2 minutes") and
// has no days unit ("48 hours"). A zero or negative d returns "".
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	mins := int64((d + time.Minute - 1) / time.Minute)
	h, m := mins/60, mins%60
	switch {
	case h == 0:
		return pluralUnit(m, "minute")
	case m == 0:
		return pluralUnit(h, "hour")
	default:
		return pluralUnit(h, "hour") + " " + pluralUnit(m, "minute")
	}
}

// pluralUnit renders n and its unit, pluralising the unit unless n is 1.
func pluralUnit(n int64, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.FormatInt(n, 10) + " " + unit + "s"
}
