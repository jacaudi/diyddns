package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// Version is the feed document version (design §4.4). Adding fields is safe;
// changing their meaning is not. Separate from notify's payloadVersion: they
// version different documents.
const Version = 1

// headerLine is the text document's first line. It is always present, so a
// legitimately empty feed is a non-empty body distinguishable from a
// truncated fetch, and it names the document for a human reading it.
const headerLine = "# diyddns feed v1\n"

// Snapshot is one rendering of the feed: both documents, each with the strong
// ETag of ITS OWN exact body bytes (design D8/§4.5). Two tags, not one: the
// JSON document also carries label and last_seen_at, so a label edit or an
// address-preserving check-in changes the JSON body while the text body is
// unchanged — one shared tag would answer 304 with stale JSON.
// Deterministic for a given input — equal content, equal bytes, equal tags —
// which is what lets glue short-circuit on cmp/hash.
type Snapshot struct {
	Text     []byte
	JSON     []byte
	TextETag string
	JSONETag string
}

// strongETag is the design's validator: a strong entity tag, the quoted
// lowercase hex SHA-256 of the exact bytes the route writes.
func strongETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

type jsonDevice struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	IPv4       *string `json:"ipv4"`
	IPv6       *string `json:"ipv6"`
	LastSeenAt *string `json:"last_seen_at"`
}

type jsonDoc struct {
	Version int          `json:"version"`
	CIDRs   []string     `json:"cidrs"`
	Devices []jsonDevice `json:"devices"`
}

func nullable(a netip.Addr, ok bool) *string {
	if !ok {
		return nil
	}
	s := a.String()
	return &s
}

// Render builds both documents from the member devices (already ordered by
// id, as store.ListFeed returns them). A corrupt stored address is dropped
// rather than failing the whole feed: a 500 would make a consumer keep a
// stale list for one bad row. The dedup itself (sorted, IPv4 before IPv6,
// two devices behind one NAT sharing an address) is store.DedupeAddrs -- the
// same core the admin IP-list endpoint uses over the SAME feed-membership
// query (store.ListFeed), so the two audiences squash and scope addresses
// identically (#150).
func Render(devices []store.FeedDevice) (Snapshot, error) {
	rawAddrs := make([]netip.Addr, 0, 2*len(devices))
	jdevs := make([]jsonDevice, 0, len(devices))
	for _, d := range devices {
		v4, ok4 := store.ParseAddr(d.IPv4)
		v6, ok6 := store.ParseAddr(d.IPv6)
		if ok4 {
			rawAddrs = append(rawAddrs, v4)
		}
		if ok6 {
			rawAddrs = append(rawAddrs, v6)
		}
		var seen *string
		if d.LastSeenAt != 0 {
			s := time.Unix(d.LastSeenAt, 0).UTC().Format(time.RFC3339)
			seen = &s
		}
		jdevs = append(jdevs, jsonDevice{
			ID: d.ID, Label: d.Label,
			IPv4: nullable(v4, ok4), IPv6: nullable(v6, ok6),
			LastSeenAt: seen,
		})
	}
	addrs := store.DedupeAddrs(rawAddrs)

	cidrs := make([]string, 0, len(addrs))
	var text bytes.Buffer
	text.WriteString(headerLine)
	for _, a := range addrs {
		c := store.CIDRString(a)
		cidrs = append(cidrs, c)
		text.WriteString(c)
		text.WriteByte('\n')
	}

	j, err := json.Marshal(jsonDoc{Version: Version, CIDRs: cidrs, Devices: jdevs})
	if err != nil {
		return Snapshot{}, fmt.Errorf("feed: render json: %w", err)
	}
	j = append(j, '\n')

	return Snapshot{
		Text:     text.Bytes(),
		JSON:     j,
		TextETag: strongETag(text.Bytes()),
		JSONETag: strongETag(j),
	}, nil
}
