package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// recordingCloser records CloseToken calls, so revoke tests can assert the
// hub is told which token died.
type recordingCloser struct {
	mu     sync.Mutex
	closed []string
}

func (r *recordingCloser) CloseToken(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, id)
}

// recordingDeviceNotifier captures membership events without any I/O.
type recordingDeviceNotifier struct {
	added, removed []store.Device
}

func (r *recordingDeviceNotifier) DeviceAdded(_ context.Context, d store.Device) {
	r.added = append(r.added, d)
}

func (r *recordingDeviceNotifier) DeviceRemoved(_ context.Context, d store.Device) {
	r.removed = append(r.removed, d)
}

func TestInFeed(t *testing.T) {
	tests := []struct {
		name string
		d    store.Device
		u    store.User
		want bool
	}{
		{"enabled with v4", store.Device{CurrentIPv4: "1.2.3.4"}, store.User{}, true},
		{"enabled with v6 only", store.Device{CurrentIPv6: "2001:db8::1"}, store.User{}, true},
		{"no address", store.Device{}, store.User{}, false},
		{"device disabled", store.Device{CurrentIPv4: "1.2.3.4", Disabled: true}, store.User{}, false},
		{"owner disabled", store.Device{CurrentIPv4: "1.2.3.4"}, store.User{Disabled: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := inFeed(tc.d, tc.u); got != tc.want {
				t.Errorf("inFeed = %v, want %v", got, tc.want)
			}
		})
	}
}

// seedUserWithDisabled creates and returns a user with a fresh email and the
// given disabled flag. Distinct from seedUser (enrollment_test.go), whose
// four-arg signature takes neither the disabled flag nor per-family
// addresses -- needed here so TestFeedMembership_SQLAndGoAgree's fixture
// rows can vary owner-disabled independently of device-disabled.
func seedUserWithDisabled(t *testing.T, ctx context.Context, st *store.Store, disabled bool) store.User {
	t.Helper()
	u, err := st.Users().Create(ctx, store.User{Email: store.NewID() + "@example.com", Role: "user", Disabled: disabled})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// seedDeviceWith creates and returns a device with the given label, per-family
// addresses and disabled flag. Distinct from seedDevice (checkin_test.go),
// whose four-arg signature takes neither the disabled flag nor per-family
// addresses.
func seedDeviceWith(t *testing.T, ctx context.Context, st *store.Store, userID, label, v4, v6 string, disabled bool) store.Device {
	t.Helper()
	d, err := st.Devices().Create(ctx, store.Device{
		UserID: userID, Label: label, SecretHash: "h",
		CurrentIPv4: v4, CurrentIPv6: v6, Disabled: disabled,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d
}

// #106 D18 states the membership predicate ONCE and both halves implement it:
// service.inFeed and store's listFeedQuery. No other test runs both over the
// SAME rows -- TestInFeed and TestDevices_ListFeed have separate fixtures in
// separate packages -- so the two can drift silently.
//
// #127 changes neither half. That is precisely the property worth pinning:
// clearing the address rather than flagging it works only because both halves
// already treat an absent address as absent.
func TestFeedMembership_SQLAndGoAgree(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()

	type row struct {
		label                     string
		v4, v6                    string
		devDisabled, userDisabled bool
	}
	rows := []row{
		{"dual", "1.2.3.4", "2001:db8::1", false, false},
		{"v4 only", "1.2.3.4", "", false, false},
		{"v6 only", "", "2001:db8::1", false, false},
		{"no address", "", "", false, false},
		{"device disabled", "1.2.3.4", "", true, false},
		{"owner disabled", "1.2.3.4", "", false, true},
		{"no address and disabled", "", "", true, true},
	}

	want := map[string]bool{}
	for _, r := range rows {
		u := seedUserWithDisabled(t, ctx, st, r.userDisabled)
		d := seedDeviceWith(t, ctx, st, u.ID, r.label, r.v4, r.v6, r.devDisabled)
		// The Go half, evaluated on the row AS READ -- inFeed's documented rule.
		want[r.label] = inFeed(d, u)
	}

	feed, err := st.Devices().ListFeed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inSQL := map[string]bool{}
	for _, f := range feed {
		inSQL[f.Label] = true
	}
	for _, r := range rows {
		if inSQL[r.label] != want[r.label] {
			t.Errorf("%q: listFeedQuery says %v, inFeed says %v -- D18 requires they agree",
				r.label, inSQL[r.label], want[r.label])
		}
	}
}

func TestFeedService_MintAuthenticateRevoke(t *testing.T) {
	st := openTestStore(t)
	admin := seedUser(t, st, "admin@x", "admin")
	closer := &recordingCloser{}
	svc := NewFeedService(st, closer, NewAuditWriter(st))
	ctx := t.Context()

	tok, plaintext, err := svc.MintToken(ctx, admin.ID, "envoy")
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if !strings.HasPrefix(plaintext, FeedTokenPrefix) || len(plaintext) < len(FeedTokenPrefix)+40 {
		t.Errorf("plaintext = %q, want the ddf_ prefix and ~43 base64url chars", plaintext)
	}
	if tok.Label != "envoy" || tok.CreatedBy != admin.ID || tok.TokenHash == "" || tok.TokenHash == plaintext {
		t.Errorf("minted token = %+v; the hash must be stored, never the plaintext", tok)
	}

	got, err := svc.Authenticate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != tok.ID {
		t.Errorf("Authenticate returned token %s, want %s", got.ID, tok.ID)
	}

	if _, err := svc.Authenticate(ctx, "not-a-token"); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("Authenticate(no prefix) err = %v, want ErrTokenMalformed", err)
	}
	if _, err := svc.Authenticate(ctx, FeedTokenPrefix+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Authenticate(unknown) err = %v, want store.ErrNotFound", err)
	}

	if _, _, err := svc.MintToken(ctx, admin.ID, "envoy"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("MintToken(duplicate label) err = %v, want store.ErrConflict", err)
	}

	if err := svc.RevokeToken(ctx, admin.ID, tok.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if len(closer.closed) != 1 || closer.closed[0] != tok.ID {
		t.Errorf("CloseToken calls = %v, want [%s]", closer.closed, tok.ID)
	}
	if _, err := svc.Authenticate(ctx, plaintext); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Authenticate after revoke err = %v, want store.ErrNotFound", err)
	}
	if err := svc.RevokeToken(ctx, admin.ID, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeToken(again) err = %v, want store.ErrNotFound", err)
	}

	for _, ev := range []string{"feed.token_created", "feed.token_revoked"} {
		page, err := st.AuditLog().ListPaginated(ctx, store.AuditFilter{EventType: ev}, "", 10)
		if err != nil {
			t.Fatalf("ListPaginated(%s): %v", ev, err)
		}
		if len(page.Rows) != 1 || page.Rows[0].TargetID != tok.ID || page.Rows[0].ActorUserID != admin.ID {
			t.Errorf("%s audit rows = %+v, want one row targeting %s by %s", ev, page.Rows, tok.ID, admin.ID)
		}
	}
}

// TestFeedService_LastUsedIsThrottled: Authenticate writes last_used_at at
// most once per 60 s per token, so a 5-second poller does not turn every
// read into a write on the single SQLite connection.
func TestFeedService_LastUsedIsThrottled(t *testing.T) {
	st := openTestStore(t)
	admin := seedUser(t, st, "admin@x", "admin")
	svc := NewFeedService(st, &recordingCloser{}, discardAudit{})
	ctx := t.Context()

	tok, plaintext, err := svc.MintToken(ctx, admin.ID, "t")
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	clock := int64(1_000_000)
	svc.now = func() int64 { return clock }

	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	first, err := st.FeedTokens().GetByHash(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if first.LastUsedAt != clock {
		t.Fatalf("last_used_at = %d after first use, want %d", first.LastUsedAt, clock)
	}

	clock += 30
	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	second, _ := st.FeedTokens().GetByHash(ctx, tok.TokenHash)
	if second.LastUsedAt != first.LastUsedAt {
		t.Errorf("last_used_at moved to %d after 30 s, want the write throttled", second.LastUsedAt)
	}

	clock += 31
	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	third, _ := st.FeedTokens().GetByHash(ctx, tok.TokenHash)
	if third.LastUsedAt != clock {
		t.Errorf("last_used_at = %d after 61 s, want %d", third.LastUsedAt, clock)
	}
}
