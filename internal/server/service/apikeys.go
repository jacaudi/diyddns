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

// APIKeyPrefix re-exports store.APIKeyPrefix for callers in this package's
// orbit (tests, the web UI, the REST layer); the constant is owned by store.
const APIKeyPrefix = store.APIKeyPrefix

// ErrKeyMalformed is returned by Authenticate for a value that cannot be an
// API key at all (wrong prefix). Distinct from store.ErrNotFound so the
// middleware can log "malformed" vs "unknown_key" (design D5).
var ErrKeyMalformed = errors.New("service: malformed API key")

// ErrInvalidKeyLabel is returned by MintKey when the label is empty after
// trimming surrounding whitespace. A distinct sentinel from feed.go's
// ErrInvalidLabel (not a reuse): the message must name "API key", not "feed
// token" -- two instances of the same validation shape is the Rule-of-Three
// tolerance, not a DRY violation, since the two error MESSAGES are genuinely
// different user-facing text for two different credential types.
var ErrInvalidKeyLabel = errors.New("service: API key label must not be empty")

// APIKeyService owns API-key state: minting, listing, revoking, and the
// lookup + last-used throttle the new key-auth middleware authenticates
// through (design #149). Mirrors FeedService's shape exactly, minus
// TokenCloser -- an API key has no live stream to close on revoke.
type APIKeyService struct {
	st    *store.Store
	audit AuditSink
	now   func() int64 // seam for the throttle tests

	mu        sync.Mutex
	lastTouch map[string]int64 // key id -> unix seconds of the last last_used_at write
}

// NewAPIKeyService constructs an APIKeyService.
func NewAPIKeyService(st *store.Store, audit AuditSink) *APIKeyService {
	return &APIKeyService{st: st, audit: audit, now: store.NowUnix, lastTouch: make(map[string]int64)}
}

// MintKey creates a key and returns its plaintext exactly once. label is
// trimmed of surrounding whitespace; MintKey returns ErrInvalidKeyLabel if
// that leaves it empty. The plaintext is APIKeyPrefix + 32 random bytes
// (base64url); only its SHA-256 hash is stored (auth.HashToken). AdminScope
// is ALWAYS false here -- #149's write-path guarantee (design D2/S6): no
// parameter or input path in this function can set it otherwise. Returns
// store.ErrConflict on a duplicate (user, label) pair.
func (s *APIKeyService) MintKey(ctx context.Context, userID, label string) (store.APIKey, string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return store.APIKey{}, "", fmt.Errorf("service.MintKey: %w", ErrInvalidKeyLabel)
	}

	rnd, err := auth.RandToken(32)
	if err != nil {
		return store.APIKey{}, "", fmt.Errorf("service.MintKey: %w", err)
	}
	plaintext := APIKeyPrefix + rnd
	key := store.APIKey{
		ID:        store.NewID(),
		UserID:    userID,
		Label:     label,
		KeyHash:   auth.HashToken(plaintext),
		CreatedAt: s.now(),
	}
	if err := s.st.APIKeys().Create(ctx, key); err != nil {
		return store.APIKey{}, "", fmt.Errorf("service.MintKey: %w", err)
	}
	details, _ := json.Marshal(map[string]string{"label": label})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "api_key.created",
		TargetType: "api_key", TargetID: key.ID, DetailsJSON: string(details),
	})
	return key, plaintext, nil
}

// ListKeys returns every live key owned by userID, oldest first.
func (s *APIKeyService) ListKeys(ctx context.Context, userID string) ([]store.APIKey, error) {
	keys, err := s.st.APIKeys().List(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.ListKeys: %w", err)
	}
	return keys, nil
}

// ownedKey fetches id and confirms it belongs to userID, returning
// store.ErrNotFound if it does not exist or is owned by someone else --
// mirrors DeviceService.ownedDevice exactly (design D8).
func (s *APIKeyService) ownedKey(ctx context.Context, userID, id string) (store.APIKey, error) {
	key, err := s.st.APIKeys().GetByID(ctx, id)
	if err != nil {
		return store.APIKey{}, err
	}
	if key.UserID != userID {
		return store.APIKey{}, store.ErrNotFound
	}
	return key, nil
}

// RevokeKey deletes the key after confirming userID owns it. Returns
// store.ErrNotFound if it does not exist or belongs to someone else --
// ownership-as-404, same as every other owned-resource service in this
// codebase.
func (s *APIKeyService) RevokeKey(ctx context.Context, userID, id string) error {
	key, err := s.ownedKey(ctx, userID, id)
	if err != nil {
		return fmt.Errorf("service.RevokeKey: %w", err)
	}
	if err := s.st.APIKeys().Delete(ctx, key.ID); err != nil {
		return fmt.Errorf("service.RevokeKey: %w", err)
	}
	s.mu.Lock()
	delete(s.lastTouch, key.ID)
	s.mu.Unlock()
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "api_key.revoked",
		TargetType: "api_key", TargetID: key.ID,
	})
	return nil
}

// Authenticate resolves a presented plaintext to its live key. It returns
// ErrKeyMalformed for a value without the prefix, store.ErrNotFound for an
// unknown or revoked key, and any other error unchanged (the middleware maps
// these to its reason vocabulary, design D5). On success it stamps
// last_used_at at most once per lastUsedThrottle seconds per key; a stamp
// failure is swallowed -- it must never fail an authenticated request.
//
// Throttle-map lifetime, noted per design D3: api_keys uses ON DELETE
// CASCADE, so a deleted user's key rows vanish with no RevokeKey call, and
// lastTouch accumulates a stale entry per such key. Bounded (one small map
// entry, cleared on process restart) and explicitly not worth more
// mechanism than that.
func (s *APIKeyService) Authenticate(ctx context.Context, plaintext string) (store.APIKey, error) {
	if !strings.HasPrefix(plaintext, APIKeyPrefix) {
		return store.APIKey{}, ErrKeyMalformed
	}
	key, err := s.st.APIKeys().GetByHash(ctx, auth.HashToken(plaintext))
	if err != nil {
		return store.APIKey{}, err
	}

	now := s.now()
	s.mu.Lock()
	due := now-s.lastTouch[key.ID] >= lastUsedThrottle
	if due {
		s.lastTouch[key.ID] = now
	}
	s.mu.Unlock()
	if due {
		_ = s.st.APIKeys().TouchLastUsed(ctx, key.ID, now)
		key.LastUsedAt = now
	}
	return key, nil
}

// UserForKey resolves the owning user of an already-authenticated key.
// Consumed by Task 3's key-auth middleware after Authenticate succeeds, so
// it does not re-validate ownership -- the caller already holds a
// store.APIKey it trusts.
func (s *APIKeyService) UserForKey(ctx context.Context, key store.APIKey) (store.User, error) {
	usr, err := s.st.Users().GetByID(ctx, key.UserID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UserForKey: %w", err)
	}
	return usr, nil
}
