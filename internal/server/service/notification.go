package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// NotificationService provides owner-scoped management of a user's
// notification endpoints, plus the two user-initiated delivery routes
// (Test, Redeliver) that share the outbound-attempt budget defined by
// notify.UserBudgetCount/notify.UserBudgetWindow (design §10.3). An
// endpoint owned by a different user is always reported as
// store.ErrNotFound, so callers cannot distinguish "not yours" from
// "doesn't exist".
type NotificationService struct {
	st         *store.Store
	sealKey    []byte
	maxPerUser int
	allowed    []netip.Prefix
	audit      AuditSink
}

// NewNotificationService constructs a NotificationService. sealKey is the
// 32-byte AEAD key used to seal a newly-generated endpoint secret (see
// auth.SealSecret); maxPerUser bounds how many endpoints one user may
// create; allowed is the operator's private-CIDR allow-list (see
// notify.ParseAllowed); audit records lifecycle and security events.
func NewNotificationService(st *store.Store, sealKey []byte, maxPerUser int, allowed []netip.Prefix, audit AuditSink) *NotificationService {
	return &NotificationService{st: st, sealKey: sealKey, maxPerUser: maxPerUser, allowed: allowed, audit: audit}
}

// List returns all notification endpoints belonging to userID.
func (s *NotificationService) List(ctx context.Context, userID string) ([]store.NotificationEndpoint, error) {
	eps, err := s.st.NotificationEndpoints().ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.List: %w", err)
	}
	return eps, nil
}

// Get returns the endpoint identified by id, but only if it belongs to userID.
func (s *NotificationService) Get(ctx context.Context, userID, id string) (store.NotificationEndpoint, error) {
	ep, err := s.ownedEndpoint(ctx, userID, id)
	if err != nil {
		return store.NotificationEndpoint{}, fmt.Errorf("service.Get: %w", err)
	}
	return ep, nil
}

// ownedEndpoint fetches id and confirms it belongs to userID, returning
// store.ErrNotFound if it does not exist or is owned by someone else. The
// counterpart to DeviceService.ownedDevice.
func (s *NotificationService) ownedEndpoint(ctx context.Context, userID, id string) (store.NotificationEndpoint, error) {
	ep, err := s.st.NotificationEndpoints().GetOwned(ctx, userID, id)
	if err != nil {
		return store.NotificationEndpoint{}, err
	}
	return ep, nil
}

// Create validates rawURL, mints and seals a fresh signing secret, and
// inserts a new endpoint owned by userID. The returned string is the
// plaintext secret, base64-encoded for display — it is shown to the caller
// exactly once and is never persisted or logged in the clear.
//
// Validation performs no DNS: a scheme other than http/https is rejected,
// and — only when the host is an IP literal — notify.Permit is applied
// directly. A hostname is accepted without resolution. Resolving here would
// make endpoint creation a third route onto server-side name resolution
// that the attempt budget cannot cover (a rejected create writes no
// delivery row to count), and its own rejection wording would rebuild the
// dns-vs-blocked oracle design §5.8 closes.
func (s *NotificationService) Create(ctx context.Context, userID, label, rawURL string) (store.NotificationEndpoint, string, error) {
	if err := validateTarget(rawURL, s.allowed); err != nil {
		details, _ := json.Marshal(map[string]string{"url": rawURL, "reason": err.Error()})
		s.audit.Log(ctx, store.AuditEntry{
			ActorUserID: userID, EventType: "notification.target_rejected",
			TargetType: "notification_endpoint", DetailsJSON: string(details),
		})
		return store.NotificationEndpoint{}, "", fmt.Errorf("service.Create: %w", err)
	}

	secret, err := auth.GenerateSecret()
	if err != nil {
		return store.NotificationEndpoint{}, "", fmt.Errorf("service.Create: %w", err)
	}
	sealed, err := auth.SealSecret(s.sealKey, secret)
	if err != nil {
		return store.NotificationEndpoint{}, "", fmt.Errorf("service.Create: %w", err)
	}

	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		UserID:       userID,
		Label:        label,
		URL:          rawURL,
		SecretSealed: sealed,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.st.NotificationEndpoints().Create(ctx, ep, s.maxPerUser); err != nil {
		return store.NotificationEndpoint{}, "", fmt.Errorf("service.Create: %w", err)
	}

	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "notification.endpoint_created",
		TargetType: "notification_endpoint", TargetID: ep.ID,
	})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "notification.secret_revealed",
		TargetType: "notification_endpoint", TargetID: ep.ID,
	})
	return ep, base64.StdEncoding.EncodeToString(secret), nil
}

// validateTarget rejects a scheme that is neither http nor https, and —
// only when the host is an IP literal — applies notify.Permit directly. A
// hostname is accepted without any resolution attempt.
func validateTarget(rawURL string, allowed []netip.Prefix) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("notify: parse target url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", notify.ErrDenied, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", notify.ErrDenied)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP literal: a hostname, accepted without DNS resolution.
		return nil
	}
	return notify.Permit(u.Scheme, addr, allowed)
}

// SetEnabled toggles an endpoint's enabled flag.
func (s *NotificationService) SetEnabled(ctx context.Context, userID, id string, enabled bool) error {
	if _, err := s.ownedEndpoint(ctx, userID, id); err != nil {
		return fmt.Errorf("service.SetEnabled: %w", err)
	}
	if err := s.st.NotificationEndpoints().SetEnabled(ctx, userID, id, enabled); err != nil {
		return fmt.Errorf("service.SetEnabled: %w", err)
	}
	event := "notification.endpoint_disabled"
	if enabled {
		event = "notification.endpoint_enabled"
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: event, TargetType: "notification_endpoint", TargetID: id,
	})
	return nil
}

// Delete removes an endpoint (its deliveries cascade per the schema FK).
func (s *NotificationService) Delete(ctx context.Context, userID, id string) error {
	if _, err := s.ownedEndpoint(ctx, userID, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	if err := s.st.NotificationEndpoints().Delete(ctx, userID, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "notification.endpoint_deleted",
		TargetType: "notification_endpoint", TargetID: id,
	})
	return nil
}

// Test enqueues one endpoint.test attempt against id, debiting the shared
// outbound-attempt budget (design §10.3). ok=false with err=nil means
// refused, for any reason: the endpoint is not owned by userID, does not
// exist, is disabled, or the budget is exhausted. The ownership, enabled,
// and budget predicates are all carried by the single atomic INSERT this
// wraps — a preceding ownership check here would reopen the check-then-write
// race the design forbids, so this method deliberately does not call
// ownedEndpoint first.
func (s *NotificationService) Test(ctx context.Context, userID, id string) (bool, error) {
	now := store.NowUnix()
	payload, err := notify.RenderTest(now)
	if err != nil {
		return false, fmt.Errorf("service.Test: render payload: %w", err)
	}
	windowStart := now - int64(notify.UserBudgetWindow/time.Second)
	ok, err := s.st.NotificationDeliveries().InsertUserTest(ctx, id, userID, payload, now, windowStart, notify.UserBudgetCount)
	if err != nil {
		return false, fmt.Errorf("service.Test: %w", err)
	}
	if !ok {
		return false, nil
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "notification.test_sent",
		TargetType: "notification_endpoint", TargetID: id,
	})
	return true, nil
}

// Redeliver inserts a copy of the terminal delivery identified by
// deliveryID, debiting the same shared outbound-attempt budget as Test
// (design §10.3, §9.4). ok=false with err=nil means refused, for any
// reason: deliveryID does not exist, its endpoint is not owned by userID or
// is disabled, the source row is not terminal, or the budget is exhausted.
// Like Test, this deliberately does not call ownedEndpoint first — the
// ownership, terminal-status, enabled, and budget predicates are all
// carried by the single atomic INSERT this wraps.
func (s *NotificationService) Redeliver(ctx context.Context, userID string, deliveryID int64) (bool, error) {
	now := store.NowUnix()
	windowStart := now - int64(notify.UserBudgetWindow/time.Second)
	ok, err := s.st.NotificationDeliveries().InsertRedelivery(ctx, deliveryID, userID, now, windowStart, notify.UserBudgetCount)
	if err != nil {
		return false, fmt.Errorf("service.Redeliver: %w", err)
	}
	if !ok {
		return false, nil
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "notification.redelivered",
		TargetType: "notification_delivery", TargetID: strconv.FormatInt(deliveryID, 10),
	})
	return true, nil
}

// Deliveries returns up to limit deliveries for endpointID, most recent
// first, but only if endpointID belongs to userID.
func (s *NotificationService) Deliveries(ctx context.Context, userID, endpointID string, limit int) ([]store.NotificationDelivery, error) {
	if _, err := s.ownedEndpoint(ctx, userID, endpointID); err != nil {
		return nil, fmt.Errorf("service.Deliveries: %w", err)
	}
	rows, err := s.st.NotificationDeliveries().ListByEndpoint(ctx, endpointID, limit)
	if err != nil {
		return nil, fmt.Errorf("service.Deliveries: %w", err)
	}
	return rows, nil
}
