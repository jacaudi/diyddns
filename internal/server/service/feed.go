package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// DeviceNotifier is fired after an admin or user action changes a device's
// feed membership (design #106 §7.1). Like Notifier it is enqueue-only and
// must never fail the calling request; the fan-out in internal/server
// satisfies it structurally. Declared here at its consumers (DeviceService
// and AdminService), never imported from notify or feed.
type DeviceNotifier interface {
	DeviceAdded(ctx context.Context, d store.Device)
	DeviceRemoved(ctx context.Context, d store.Device)
}

// NopDeviceNotifier is wired when neither the webhook nor the feed is
// enabled, so the seams never nil-check.
type NopDeviceNotifier struct{}

// DeviceAdded does nothing.
func (NopDeviceNotifier) DeviceAdded(context.Context, store.Device) {}

// DeviceRemoved does nothing.
func (NopDeviceNotifier) DeviceRemoved(context.Context, store.Device) {}

// inFeed is the Go half of the membership predicate (design D18); the SQL
// half is store's listFeedQuery. A device is in the gateway feed iff it is
// enabled, its owner is enabled, and it has at least one address. Every seam
// evaluates this on the rows AS READ BEFORE the mutating write, and again on
// that snapshot with the one changed field set to its intended value — never
// on a re-read after the write.
func inFeed(d store.Device, u store.User) bool {
	return !d.Disabled && !u.Disabled && (d.CurrentIPv4 != "" || d.CurrentIPv6 != "")
}

// emitMembership calls the notifier for a membership flip and swallows a
// panic from it, the way CheckinService.fireNotify does: a broken hook must
// not turn an admin action into a 500. before/after are inFeed on the
// pre-write snapshot and on the intended post-write state.
func emitMembership(ctx context.Context, n DeviceNotifier, d store.Device, before, after bool) {
	defer func() { _ = recover() }()
	switch {
	case !before && after:
		n.DeviceAdded(ctx, d)
	case before && !after:
		n.DeviceRemoved(ctx, d)
	}
}

// FeedTokenPrefix re-exports store.FeedTokenPrefix for callers in this
// package's orbit (tests, the web UI); the constant is owned by store.
const FeedTokenPrefix = store.FeedTokenPrefix

// ErrTokenMalformed is returned by Authenticate for a value that cannot be a
// feed token at all (wrong prefix). Distinct from store.ErrNotFound so the
// middleware can log "malformed" vs "unknown_token".
var ErrTokenMalformed = errors.New("service: malformed feed token")

// lastUsedThrottle is how often Authenticate writes last_used_at per token.
const lastUsedThrottle = 60

// TokenCloser closes every live stream authenticated with a token. Satisfied
// by *feed.Hub; declared here at the consumer.
type TokenCloser interface {
	CloseToken(tokenID string)
}

// FeedService owns feed-token state: minting, listing, revoking, and the
// lookup + last-used throttle the feed middleware authenticates through
// (design #106 §3). One owner, so revoke can evict the throttle entry and
// close live sockets in the same call.
type FeedService struct {
	st     *store.Store
	closer TokenCloser
	audit  AuditSink
	now    func() int64 // seam for the throttle tests

	mu        sync.Mutex
	lastTouch map[string]int64 // token id -> unix seconds of the last last_used_at write
}

// NewFeedService constructs a FeedService.
func NewFeedService(st *store.Store, closer TokenCloser, audit AuditSink) *FeedService {
	return &FeedService{st: st, closer: closer, audit: audit, now: store.NowUnix, lastTouch: make(map[string]int64)}
}

// ListTokens returns every live token, oldest first.
func (s *FeedService) ListTokens(ctx context.Context) ([]store.FeedToken, error) {
	toks, err := s.st.FeedTokens().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListTokens: %w", err)
	}
	return toks, nil
}

// MintToken creates a token and returns its plaintext exactly once. The
// plaintext is FeedTokenPrefix + 32 random bytes (base64url); only its
// SHA-256 hash is stored (auth.HashToken — hashed, not sealed: the server
// never needs the plaintext back). Returns store.ErrConflict on a duplicate
// label.
func (s *FeedService) MintToken(ctx context.Context, actorID, label string) (store.FeedToken, string, error) {
	rnd, err := auth.RandToken(32)
	if err != nil {
		return store.FeedToken{}, "", fmt.Errorf("service.MintToken: %w", err)
	}
	plaintext := FeedTokenPrefix + rnd
	tok := store.FeedToken{
		ID:        store.NewID(),
		Label:     label,
		TokenHash: auth.HashToken(plaintext),
		CreatedBy: actorID,
		CreatedAt: s.now(),
	}
	if err := s.st.FeedTokens().Create(ctx, tok); err != nil {
		return store.FeedToken{}, "", fmt.Errorf("service.MintToken: %w", err)
	}
	details, _ := json.Marshal(map[string]string{"label": label})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "feed.token_created",
		TargetType: "feed_token", TargetID: tok.ID, DetailsJSON: string(details),
	})
	return tok, plaintext, nil
}

// RevokeToken deletes the token, evicts its throttle entry, and closes any
// live stream authenticated with it. Returns store.ErrNotFound if it does not
// exist.
func (s *FeedService) RevokeToken(ctx context.Context, actorID, id string) error {
	if err := s.st.FeedTokens().Delete(ctx, id); err != nil {
		return fmt.Errorf("service.RevokeToken: %w", err)
	}
	s.mu.Lock()
	delete(s.lastTouch, id)
	s.mu.Unlock()
	s.closer.CloseToken(id)
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "feed.token_revoked",
		TargetType: "feed_token", TargetID: id,
	})
	return nil
}

// Authenticate resolves a presented plaintext to its live token. It returns
// ErrTokenMalformed for a value without the prefix, store.ErrNotFound for an
// unknown or revoked token, and any other error unchanged (the middleware
// maps these to its reason vocabulary). On success it stamps last_used_at at
// most once per lastUsedThrottle seconds per token; a stamp failure is
// swallowed — it must never fail a feed read.
func (s *FeedService) Authenticate(ctx context.Context, plaintext string) (store.FeedToken, error) {
	if !strings.HasPrefix(plaintext, FeedTokenPrefix) {
		return store.FeedToken{}, ErrTokenMalformed
	}
	tok, err := s.st.FeedTokens().GetByHash(ctx, auth.HashToken(plaintext))
	if err != nil {
		return store.FeedToken{}, err
	}

	now := s.now()
	s.mu.Lock()
	due := now-s.lastTouch[tok.ID] >= lastUsedThrottle
	if due {
		s.lastTouch[tok.ID] = now
	}
	s.mu.Unlock()
	if due {
		_ = s.st.FeedTokens().TouchLastUsed(ctx, tok.ID, now)
		tok.LastUsedAt = now
	}
	return tok, nil
}
