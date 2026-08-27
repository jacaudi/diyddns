package store

// IPChangeEvent describes a device address change. It lives here rather than in
// internal/server/service so that internal/server/notify can consume it without
// importing service — service imports notify (for the destination policy), and
// the reverse direction would be an import cycle. Verified: `go build` reports
// "import cycle not allowed" if notify imports service.
//
// Address fields are "" for "this family is absent", which the payload renderer
// maps to JSON null — the distinction the wire contract makes load-bearing.
type IPChangeEvent struct {
	EventID    int64  // ip_history row id; the payload's "id"
	OccurredAt int64  // the ip_history row's observed_at, not enqueue time
	Device     Device // Label/Hostname/OS/ClientVersion/UserID
	PrevIPv4   string
	PrevIPv6   string
	CurrIPv4   string
	CurrIPv6   string
}

// Changed reports which families moved, in the payload's "changed" order.
// Derived rather than stored so it cannot disagree with the addresses beside it.
func (e IPChangeEvent) Changed() []string {
	var out []string
	if e.PrevIPv4 != e.CurrIPv4 {
		out = append(out, "ipv4")
	}
	if e.PrevIPv6 != e.CurrIPv6 {
		out = append(out, "ipv6")
	}
	return out
}
