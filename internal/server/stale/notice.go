package stale

import (
	"fmt"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// Kind distinguishes a warning from the removal that follows it.
type Kind int

// KindWarning and KindRemoved are the only two Kind values: a rung warning
// that the address is still in the feed but at risk, and the removal that
// follows once it is gone.
const (
	KindWarning Kind = iota
	KindRemoved
)

// Audience is who a notice is for (D13).
type Audience int

// AudienceOwner and AudienceAdmin are the only two Audience values (D13).
const (
	AudienceOwner Audience = iota
	AudienceAdmin
)

// Notice is one staleness message about one device's one address family. It is
// the single source of the message's content; a channel renders it for its
// medium and adds nothing.
//
// Family is singular: with per-family warning levels a notice concerns exactly
// one family, and Surviving is what lets it say "IPv6 will be removed in 3
// days; IPv4 remains."
type Notice struct {
	Kind      Kind
	Rung      int // 1..4 for warnings, 0 for removal
	Device    store.Device
	Owner     store.User
	Family    int // 4 or 6
	ExpiresAt int64
	Remaining time.Duration
	Surviving []int
}

// RecipientsFor is the single source of who hears what (D13): the owner hears
// every rung and the removal; admins hear rungs 3 and 4 and the removal.
//
// Every caller asks HERE. An inline `if rung >= 3` anywhere else is a second
// copy of this table, and two copies of one rule drift.
func RecipientsFor(kind Kind, rung int) []Audience {
	if kind == KindRemoved || rung >= 3 {
		return []Audience{AudienceOwner, AudienceAdmin}
	}
	return []Audience{AudienceOwner}
}

// familyName renders 4 and 6 the way a human reads them.
func familyName(f int) string {
	if f == 6 {
		return "IPv6"
	}
	return "IPv4"
}

// OwnerSubject and RenderOwnerBody are the owner's message: the family at
// risk, the device, how long is left -- and, when the other family survives,
// that it does, because "your device is being removed" and "one of its two
// addresses is" are different messages.
//
// Plain fmt, not text/template: a handful of short messages with plain
// string branching and one join loop do not earn a template engine.
func OwnerSubject(n Notice) string {
	if n.Kind == KindRemoved {
		return fmt.Sprintf("%s address removed from the gateway feed: %s",
			familyName(n.Family), n.Device.Label)
	}
	return fmt.Sprintf("%s address expires in %s: %s",
		familyName(n.Family), humanDays(n.Remaining), n.Device.Label)
}

// RenderOwnerBody renders the owner message body; see OwnerSubject for the
// full rationale shared by both.
func RenderOwnerBody(n Notice) string {
	var b strings.Builder
	fam := familyName(n.Family)
	if n.Kind == KindRemoved {
		fmt.Fprintf(&b, "The %s address for your device %q has been removed from the gateway "+
			"feed because the device stopped reporting it.\n\n", fam, n.Device.Label)
	} else {
		fmt.Fprintf(&b, "The %s address for your device %q will be removed from the gateway "+
			"feed in %s unless the device reports it again.\n\n",
			fam, n.Device.Label, humanDays(n.Remaining))
	}
	if len(n.Surviving) == 0 {
		if n.Kind == KindRemoved {
			b.WriteString("This was its last address, so the device is no longer in the feed.\n")
		} else {
			b.WriteString("This is its last address, so the device will drop out of the feed entirely " +
				"unless it reports again in time.\n")
		}
	} else {
		names := make([]string, 0, len(n.Surviving))
		for _, f := range n.Surviving {
			names = append(names, familyName(f))
		}
		fmt.Fprintf(&b, "Its %s address is unaffected and remains in the feed.\n",
			strings.Join(names, " and "))
	}
	b.WriteString("\nIf the device is still in use, check that its client is running and reporting.\n")
	return b.String()
}

// AdminDigestSubject and RenderAdminDigestBody render ONE digest content per
// sweep tick, listing every device that crossed rung 3 or 4 or lost an
// address, delivered once to each admin (D16; see dispatch.go's
// SendAdminDigest for the one-digest-per-admin delivery).
func AdminDigestSubject(ns []Notice) string {
	return fmt.Sprintf("Gateway feed: %d device address(es) expiring or removed", len(ns))
}

// RenderAdminDigestBody renders the admin digest body; see AdminDigestSubject
// for the full rationale shared by both.
func RenderAdminDigestBody(ns []Notice) string {
	var b strings.Builder
	b.WriteString("The following device addresses are close to removal from the gateway feed, " +
		"or have just been removed:\n\n")
	for _, n := range ns {
		if n.Kind == KindRemoved {
			fmt.Fprintf(&b, "  REMOVED   %-4s  %s (%s)\n",
				familyName(n.Family), n.Device.Label, n.Owner.Email)
			continue
		}
		fmt.Fprintf(&b, "  %-9s %-4s  %s (%s)\n",
			humanDays(n.Remaining), familyName(n.Family), n.Device.Label, n.Owner.Email)
	}
	return b.String()
}

// humanDays renders a Duration the way these notices read: "3 days", "1 day",
// "under a day". Days only -- the windows are measured in weeks, and an
// hours-and-minutes rendering would imply a precision the policy lacks.
func humanDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days < 1:
		return "under a day"
	case days == 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", days)
	}
}
