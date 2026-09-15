package stale_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
)

// D13 says WHO hears what. It is a table, so it is tested as a table rather
// than through the delivery machinery -- and it must be the ONLY encoding of
// that table in the tree.
func TestRecipientsFor(t *testing.T) {
	for _, tc := range []struct {
		kind stale.Kind
		rung int
		want []stale.Audience
	}{
		{stale.KindWarning, 1, []stale.Audience{stale.AudienceOwner}},
		{stale.KindWarning, 2, []stale.Audience{stale.AudienceOwner}},
		{stale.KindWarning, 3, []stale.Audience{stale.AudienceOwner, stale.AudienceAdmin}},
		{stale.KindWarning, 4, []stale.Audience{stale.AudienceOwner, stale.AudienceAdmin}},
		{stale.KindRemoved, 0, []stale.Audience{stale.AudienceOwner, stale.AudienceAdmin}},
	} {
		if got := stale.RecipientsFor(tc.kind, tc.rung); !slices.Equal(got, tc.want) {
			t.Errorf("RecipientsFor(%v, %d) = %v, want %v", tc.kind, tc.rung, got, tc.want)
		}
	}
}

// A notice must name the family at risk and say what survives, so the owner
// can tell "my IPv6 is going" from "my device is going". Driven both
// directions (6-at-risk/4-survives and 4-at-risk/6-survives) and asserted by
// WHOLE CLAUSE, not by bare substring: a bare Contains("IPv6") passes whether
// IPv6 is named in the at-risk clause or the survivor clause, so an inverted
// familyName mapping (or the two clauses swapped) would still pass a
// substring-only check. Asserting the mirrored clause is ABSENT is what pins
// the direction.
func TestRenderOwnerBody_NamesTheFamilyAndTheSurvivors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		family    int
		surviving []int
	}{
		{"v6 at risk, v4 survives", 6, []int{4}},
		{"v4 at risk, v6 survives", 4, []int{6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := stale.RenderOwnerBody(stale.Notice{
				Kind: stale.KindWarning, Rung: 2,
				Device: store.Device{Label: "laptop"}, Family: tc.family,
				Surviving: tc.surviving, Remaining: 72 * time.Hour,
			})
			atRisk := familyNameForTest(tc.family)
			survives := familyNameForTest(tc.surviving[0])

			atRiskClause := fmt.Sprintf(`The %s address for your device "laptop" will be removed`, atRisk)
			survivorClause := fmt.Sprintf("Its %s address is unaffected", survives)
			swappedAtRiskClause := fmt.Sprintf(`The %s address for your device "laptop" will be removed`, survives)
			swappedSurvivorClause := fmt.Sprintf("Its %s address is unaffected", atRisk)

			if !strings.Contains(body, atRiskClause) {
				t.Errorf("body missing at-risk clause %q:\n%s", atRiskClause, body)
			}
			if !strings.Contains(body, survivorClause) {
				t.Errorf("body missing survivor clause %q:\n%s", survivorClause, body)
			}
			if strings.Contains(body, swappedAtRiskClause) {
				t.Errorf("body names the SURVIVING family as at risk (%q):\n%s", swappedAtRiskClause, body)
			}
			if strings.Contains(body, swappedSurvivorClause) {
				t.Errorf("body names the AT-RISK family as surviving (%q):\n%s", swappedSurvivorClause, body)
			}
			if !strings.Contains(body, "3 days") {
				t.Errorf("body missing remaining time %q:\n%s", "3 days", body)
			}
		})
	}
}

// familyNameForTest mirrors the package's unexported familyName mapping so
// the table above can build the exact clause text without exporting it.
func familyNameForTest(f int) string {
	if f == 6 {
		return "IPv6"
	}
	return "IPv4"
}

// A single-stack device's warning must not claim the device is ALREADY gone:
// it has expire_after_days left to live, and the removal notice (not this
// one) is what fires when that time is up.
func TestRenderOwnerBody_WarningWithNoSurvivorsIsFutureTense(t *testing.T) {
	body := stale.RenderOwnerBody(stale.Notice{
		Kind: stale.KindWarning, Device: store.Device{Label: "laptop"}, Family: 4,
		Remaining: 72 * time.Hour,
	})
	if strings.Contains(body, "is no longer in the feed") {
		t.Errorf("warning claims the device is ALREADY out of the feed:\n%s", body)
	}
	if !strings.Contains(body, "will drop out of the feed") {
		t.Errorf("warning does not say the device will (future) drop out of the feed:\n%s", body)
	}
}

// Past tense versus future tense IS "what is gone": a removal that still
// reads as a pending warning ("will be removed") would tell an owner the
// address is still safe when it is already gone. Bare Contains("removed")
// cannot tell "has been removed" from "will be removed" -- "removed" is a
// substring of both -- so this asserts the exact past-tense clause and
// asserts the future-tense clause is ABSENT.
func TestRenderOwnerBody_RemovalSaysWhatIsGone(t *testing.T) {
	body := stale.RenderOwnerBody(stale.Notice{
		Kind: stale.KindRemoved, Device: store.Device{Label: "laptop"}, Family: 4,
	})
	if !strings.Contains(body, "has been removed") {
		t.Errorf("removal body does not say the address HAS BEEN removed (past tense):\n%s", body)
	}
	if strings.Contains(body, "will be removed") {
		t.Errorf("removal body still reads as a pending warning (future tense):\n%s", body)
	}
	if !strings.Contains(body, "IPv4") {
		t.Errorf("removal body does not name the removed family:\n%s", body)
	}
}
