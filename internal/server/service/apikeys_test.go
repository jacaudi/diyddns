package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestAPIKeyService_MintKey_RejectsEmptyLabel(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "keyuser1@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	for _, label := range []string{"", "   "} {
		if _, _, err := svc.MintKey(ctx, usr.ID, label); !errors.Is(err, ErrInvalidKeyLabel) {
			t.Errorf("MintKey(%q) err = %v, want ErrInvalidKeyLabel", label, err)
		}
	}

	keys, err := st.APIKeys().List(ctx, usr.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List = %+v, want no rows after two rejected mints", keys)
	}
}

func TestAPIKeyService_MintKey_TrimsLabel(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "keyuser2@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	key, plaintext, err := svc.MintKey(ctx, usr.ID, "  laptop  ")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if key.Label != "laptop" {
		t.Errorf("stored label = %q, want %q (trimmed)", key.Label, "laptop")
	}
	if plaintext == "" {
		t.Fatal("MintKey returned an empty plaintext")
	}
	if !hasAPIKeyPrefix(plaintext) {
		t.Errorf("plaintext = %q, want it to start with %q", plaintext, APIKeyPrefix)
	}
	if key.AdminScope {
		t.Error("MintKey set AdminScope=true; #149 must never set it to anything but false")
	}
}

// hasAPIKeyPrefix is a tiny local helper so this test doesn't import strings
// just for one prefix check the production code already does via
// strings.HasPrefix in Authenticate.
func hasAPIKeyPrefix(s string) bool {
	return len(s) >= len(APIKeyPrefix) && s[:len(APIKeyPrefix)] == APIKeyPrefix
}

func TestAPIKeyService_MintKey_DuplicateLabelSameUserConflicts(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "keyuser3@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	if _, _, err := svc.MintKey(ctx, usr.ID, "laptop"); err != nil {
		t.Fatalf("first MintKey: %v", err)
	}
	if _, _, err := svc.MintKey(ctx, usr.ID, "laptop"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second MintKey(same label) err = %v, want store.ErrConflict", err)
	}
}

func TestAPIKeyService_ListKeys_ScopedToOwner(t *testing.T) {
	st := openTestStore(t)
	alice := seedUser(t, st, "alice-keys@x", "user")
	bob := seedUser(t, st, "bob-keys@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	if _, _, err := svc.MintKey(ctx, alice.ID, "alice-key"); err != nil {
		t.Fatalf("mint alice: %v", err)
	}
	if _, _, err := svc.MintKey(ctx, bob.ID, "bob-key"); err != nil {
		t.Fatalf("mint bob: %v", err)
	}

	aliceKeys, err := svc.ListKeys(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListKeys(alice): %v", err)
	}
	if len(aliceKeys) != 1 || aliceKeys[0].Label != "alice-key" {
		t.Errorf("ListKeys(alice) = %+v, want exactly alice's one key", aliceKeys)
	}
}

// TestAPIKeyService_RevokeKey_OwnershipAsNotFound: revoking a key you don't
// own reports ErrNotFound, identical to DeviceService's ownership pattern
// (design D8) -- a foreign key is indistinguishable from a nonexistent one.
func TestAPIKeyService_RevokeKey_OwnershipAsNotFound(t *testing.T) {
	st := openTestStore(t)
	alice := seedUser(t, st, "alice-revoke@x", "user")
	bob := seedUser(t, st, "bob-revoke@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	key, _, err := svc.MintKey(ctx, alice.ID, "alice-only")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if err := svc.RevokeKey(ctx, bob.ID, key.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeKey(wrong owner) err = %v, want store.ErrNotFound", err)
	}

	// Still there for the real owner.
	keys, err := svc.ListKeys(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListKeys(alice) after a foreign revoke attempt = %+v, want the key still present", keys)
	}

	if err := svc.RevokeKey(ctx, alice.ID, key.ID); err != nil {
		t.Fatalf("RevokeKey(real owner): %v", err)
	}
	keys, err = svc.ListKeys(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListKeys after revoke: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys(alice) after real revoke = %+v, want none", keys)
	}
}

func TestAPIKeyService_Authenticate_RoundTrip(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "auth-roundtrip@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	_, plaintext, err := svc.MintKey(ctx, usr.ID, "k")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	got, err := svc.Authenticate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.UserID != usr.ID {
		t.Errorf("Authenticate resolved UserID = %q, want %q", got.UserID, usr.ID)
	}

	if _, err := svc.Authenticate(ctx, "dak_not-a-real-key"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Authenticate(unknown) err = %v, want store.ErrNotFound", err)
	}
	if _, err := svc.Authenticate(ctx, "not-even-the-right-prefix"); !errors.Is(err, ErrKeyMalformed) {
		t.Errorf("Authenticate(wrong prefix) err = %v, want ErrKeyMalformed", err)
	}
}

// TestAPIKeyService_LastUsedIsThrottled mirrors
// TestFeedService_LastUsedIsThrottled exactly: Authenticate writes
// last_used_at at most once per lastUsedThrottle seconds per key.
func TestAPIKeyService_LastUsedIsThrottled(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "throttle@x", "user")
	svc := NewAPIKeyService(st, discardAudit{})
	ctx := t.Context()

	_, plaintext, err := svc.MintKey(ctx, usr.ID, "k")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	base := int64(1_700_000_000)
	svc.now = func() int64 { return base }
	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate #1: %v", err)
	}
	row, err := st.APIKeys().GetByHash(ctx, hashForTest(plaintext))
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if row.LastUsedAt != base {
		t.Fatalf("last_used_at after first auth = %d, want %d", row.LastUsedAt, base)
	}

	svc.now = func() int64 { return base + 1 } // well inside the 60s throttle window
	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate #2: %v", err)
	}
	row, err = st.APIKeys().GetByHash(ctx, hashForTest(plaintext))
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if row.LastUsedAt != base {
		t.Errorf("last_used_at after second (throttled) auth = %d, want still %d", row.LastUsedAt, base)
	}

	svc.now = func() int64 { return base + lastUsedThrottle }
	if _, err := svc.Authenticate(ctx, plaintext); err != nil {
		t.Fatalf("Authenticate #3: %v", err)
	}
	row, err = st.APIKeys().GetByHash(ctx, hashForTest(plaintext))
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if row.LastUsedAt != base+lastUsedThrottle {
		t.Errorf("last_used_at after third auth (past throttle window) = %d, want %d", row.LastUsedAt, base+lastUsedThrottle)
	}
}

// TestAPIKeyService_MintKey_AuditsCreation and
// TestAPIKeyService_RevokeKey_AuditsRevocation pin design D8's audit
// requirement (fixed by the design-gate review, S1): a recording AuditSink
// double, mirroring recordingCloser's style in feed_test.go.
type recordingAudit struct{ entries []store.AuditEntry }

func (r *recordingAudit) Log(_ context.Context, e store.AuditEntry) { r.entries = append(r.entries, e) }

func TestAPIKeyService_MintKey_AuditsCreation(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "audit-mint@x", "user")
	audit := &recordingAudit{}
	svc := NewAPIKeyService(st, audit)
	ctx := t.Context()

	key, _, err := svc.MintKey(ctx, usr.ID, "audited-key")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %+v, want exactly one", audit.entries)
	}
	e := audit.entries[0]
	if e.EventType != "api_key.created" || e.ActorUserID != usr.ID || e.TargetType != "api_key" || e.TargetID != key.ID {
		t.Errorf("audit entry = %+v, want EventType api_key.created, ActorUserID %s, TargetType api_key, TargetID %s",
			e, usr.ID, key.ID)
	}
}

func TestAPIKeyService_RevokeKey_AuditsRevocation(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "audit-revoke@x", "user")
	audit := &recordingAudit{}
	svc := NewAPIKeyService(st, audit)
	ctx := t.Context()

	key, _, err := svc.MintKey(ctx, usr.ID, "k")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	audit.entries = nil // discard the mint entry; this test is about revoke

	if err := svc.RevokeKey(ctx, usr.ID, key.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %+v, want exactly one", audit.entries)
	}
	e := audit.entries[0]
	if e.EventType != "api_key.revoked" || e.ActorUserID != usr.ID || e.TargetType != "api_key" || e.TargetID != key.ID {
		t.Errorf("audit entry = %+v, want EventType api_key.revoked, ActorUserID %s, TargetType api_key, TargetID %s",
			e, usr.ID, key.ID)
	}
}

// hashForTest re-derives the hash the way Authenticate does, so tests can
// look a minted key up by hash without exporting HashToken's use here.
func hashForTest(plaintext string) string { return auth.HashToken(plaintext) }
