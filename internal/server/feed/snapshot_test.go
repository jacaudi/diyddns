package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// fixtureDevices covers: two devices sharing an IPv4 (dedupe), an IPv6-only
// device with no last_seen (nullable scan), and a 4-in-6 mapped IPv4 that
// must render and sort as an IPv4 /32. Ordered by id, as ListFeed returns.
func fixtureDevices() []store.FeedDevice {
	const seen = 1755153174 // 2025-08-14T06:32:54Z
	return []store.FeedDevice{
		{ID: "dev-a", Label: "router", IPv4: "203.0.113.9", IPv6: "2001:db8::1", LastSeenAt: seen},
		{ID: "dev-b", Label: "nas", IPv4: "203.0.113.9", IPv6: "", LastSeenAt: seen},
		{ID: "dev-c", Label: "v6only", IPv4: "", IPv6: "2001:db8::1", LastSeenAt: 0},
		{ID: "dev-d", Label: "mapped", IPv4: "::ffff:198.51.100.7", IPv6: "", LastSeenAt: seen},
	}
}

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

func TestRender_MatchesGolden(t *testing.T) {
	snap, err := Render(fixtureDevices())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := golden(t, "feed.txt"); string(snap.Text) != string(want) {
		t.Errorf("text document:\n got: %q\nwant: %q", snap.Text, want)
	}
	if want := golden(t, "feed.json"); string(snap.JSON) != string(want) {
		t.Errorf("json document:\n got: %s\nwant: %s", snap.JSON, want)
	}
	sumText := sha256.Sum256(snap.Text)
	if want := `"` + hex.EncodeToString(sumText[:]) + `"`; snap.TextETag != want {
		t.Errorf("TextETag = %s, want the quoted SHA-256 of the text body %s", snap.TextETag, want)
	}
	sumJSON := sha256.Sum256(snap.JSON)
	if want := `"` + hex.EncodeToString(sumJSON[:]) + `"`; snap.JSONETag != want {
		t.Errorf("JSONETag = %s, want the quoted SHA-256 of the json body %s", snap.JSONETag, want)
	}
	if snap.TextETag == snap.JSONETag {
		t.Error("the two documents must not share one tag (design D8/§4.5)")
	}
}

// TestRender_EmptyFeedIsNonEmptyBody: a legitimately empty feed must still
// carry the header line so a consumer can tell it from a truncated fetch
// (design §4.3), and the JSON arrays are [] never null.
func TestRender_EmptyFeedIsNonEmptyBody(t *testing.T) {
	snap, err := Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(snap.Text) != string(golden(t, "empty.txt")) {
		t.Errorf("empty text = %q", snap.Text)
	}
	if string(snap.JSON) != string(golden(t, "empty.json")) {
		t.Errorf("empty json = %s", snap.JSON)
	}
}

// TestRender_ZonedIPv6IsStripped: a zoned address would render an invalid
// CIDR for every consumer (pass 3 n7).
func TestRender_ZonedIPv6IsStripped(t *testing.T) {
	snap, err := Render([]store.FeedDevice{{ID: "z", Label: "z", IPv6: "fe80::1%eth0"}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "# diyddns feed v1\nfe80::1/128\n"; string(snap.Text) != want {
		t.Errorf("text = %q, want %q", snap.Text, want)
	}
}

// TestRender_IsDeterministic: identical input, identical bytes and tag —
// what lets glue short-circuit on cmp/hash.
func TestRender_IsDeterministic(t *testing.T) {
	a, err := Render(fixtureDevices())
	if err != nil {
		t.Fatalf("Render (a): %v", err)
	}
	b, err := Render(fixtureDevices())
	if err != nil {
		t.Fatalf("Render (b): %v", err)
	}
	if string(a.Text) != string(b.Text) || string(a.JSON) != string(b.JSON) ||
		a.TextETag != b.TextETag || a.JSONETag != b.JSONETag {
		t.Error("two renders of the same input differ")
	}
}

// TestRender_LabelChangeMovesOnlyTheJSONTag is design D8/§4.5 in one
// assertion: the JSON document carries label and last_seen_at, the text
// document does not, so a label-only edit must move the JSON tag and leave
// the text tag alone. One shared tag would answer a JSON poller 304 forever.
func TestRender_LabelChangeMovesOnlyTheJSONTag(t *testing.T) {
	before, err := Render([]store.FeedDevice{{ID: "dev-a", Label: "router", IPv4: "203.0.113.9"}})
	if err != nil {
		t.Fatalf("Render (before): %v", err)
	}
	after, err := Render([]store.FeedDevice{{ID: "dev-a", Label: "renamed", IPv4: "203.0.113.9"}})
	if err != nil {
		t.Fatalf("Render (after): %v", err)
	}
	if before.TextETag != after.TextETag {
		t.Errorf("text tag changed on a label-only edit: %s -> %s", before.TextETag, after.TextETag)
	}
	if before.JSONETag == after.JSONETag {
		t.Errorf("json tag unchanged on a label-only edit: %s", after.JSONETag)
	}
}

// TestRender_SkipsUnparseableAddress: a corrupt stored address must not
// take the whole feed down; it is dropped from cidrs (and left null in the
// device entry) rather than turned into a 500.
func TestRender_SkipsUnparseableAddress(t *testing.T) {
	snap, err := Render([]store.FeedDevice{{ID: "bad", Label: "bad", IPv4: "not-an-ip", IPv6: "2001:db8::9"}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "# diyddns feed v1\n2001:db8::9/128\n"; string(snap.Text) != want {
		t.Errorf("text = %q, want %q", snap.Text, want)
	}
}
