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
