package stale_test

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/stale"
)

const day = 86400

func cfg(days int) config.FeedSection {
	return config.FeedSection{Enabled: true, ExpireAfterDays: days}
}

func TestWindow_IsTheConfiguredDaysInSeconds(t *testing.T) {
	if got := stale.Window(cfg(21)); got != 21*day {
		t.Errorf("Window(21) = %d, want %d", got, 21*day)
	}
}

// D11: days 7/14/17/20 at the default window, scaled proportionally elsewhere.
// expire_after_days accepts 0..36500 (0 is the documented opt-out), so
// literal days are undefined for every window but 21.
func TestRungs_ExactAtTheDefaultWindow(t *testing.T) {
	got := stale.Rungs(21 * day)
	want := [4]int64{7 * day, 14 * day, 17 * day, 20 * day}
	if got != want {
		t.Fatalf("Rungs(21d) = %v, want %v", got, want)
	}
}

func TestRungs_NoRungFallsAtOrAfterRemoval(t *testing.T) {
	for _, days := range []int{1, 2, 3, 10, 21, 365, 36500} {
		w := int64(days) * day
		r := stale.Rungs(w)
		for i, at := range r {
			if at >= w {
				t.Errorf("W=%dd: rung %d at %d is not before removal at %d", days, i+1, at, w)
			}
		}
		// And they must be strictly increasing, or "highest due rung" is
		// meaningless.
		for i := 1; i < len(r); i++ {
			if r[i] <= r[i-1] {
				t.Errorf("W=%dd: rungs not strictly increasing: %v", days, r)
			}
		}
	}
}

// The candidacy bound is the FIRST RUNG, not the window. With the window as
// the bound a device would first be seen already past expiry and every rung
// would collapse into the removal notice -- zero warnings, silently.
func TestFirstRung_IsSecondsAndIsTheFirstRung(t *testing.T) {
	if got, want := stale.FirstRung(cfg(21)), int64(7*day); got != want {
		t.Errorf("FirstRung(21) = %d, want %d", got, want)
	}
	// Integer-day arithmetic would give 2/3 = 0 here.
	if got := stale.FirstRung(cfg(2)); got == 0 {
		t.Fatal("FirstRung = 0: computed in integer DAYS, so every member is a candidate every tick")
	}
}

// §7.1: overdue rungs do not stack. After an outage several can be due at
// once; the sweeper advances to the highest and sends exactly one notice.
func TestDueRung_HighestDueNotLowest(t *testing.T) {
	w := int64(21 * day)
	for _, tc := range []struct {
		elapsed int64
		want    int
	}{
		{0, 0},
		{6 * day, 0},
		{7 * day, 1},
		{13 * day, 1},
		{14 * day, 2},
		{17 * day, 3},
		{18 * day, 3},
		{20 * day, 4},
		{20*day + 1, 4},
		{22 * day, 4},
	} {
		if got := stale.DueRung(w, tc.elapsed); got != tc.want {
			t.Errorf("DueRung(21d, %dd) = %d, want %d", tc.elapsed/day, got, tc.want)
		}
	}
}

func TestExpiresAt(t *testing.T) {
	if got := stale.ExpiresAt(1000, 21*day); got != 1000+21*day {
		t.Errorf("ExpiresAt = %d, want %d", got, 1000+21*day)
	}
}
