package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// NotificationService manages the server-global, admin-configured notification
// endpoints (#106: users cannot configure the outbound service) and the two
// on-demand delivery routes, Test and Redeliver. actorID on the mutating
// methods is the admin performing the action, recorded as the audit actor.
type NotificationService struct {
	st      *store.Store
	sealKey []byte
	allowed []netip.Prefix
	audit   AuditSink
}

// NewNotificationService constructs a NotificationService. sealKey is the
// 32-byte AEAD key used to seal a newly-generated endpoint secret (see
// auth.SealSecret); allowed is the operator's private-CIDR allow-list (see
// notify.ParseAllowed); audit records lifecycle and security events.
func NewNotificationService(st *store.Store, sealKey []byte, allowed []netip.Prefix, audit AuditSink) *NotificationService {
	return &NotificationService{st: st, sealKey: sealKey, allowed: allowed, audit: audit}
}

// List returns every notification endpoint.
func (s *NotificationService) List(ctx context.Context) ([]store.NotificationEndpoint, error) {
	eps, err := s.st.NotificationEndpoints().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.List: %w", err)
	}
	return eps, nil
}

// Get returns the endpoint identified by id, or store.ErrNotFound.
func (s *NotificationService) Get(ctx context.Context, id string) (store.NotificationEndpoint, error) {
	ep, err := s.st.NotificationEndpoints().Get(ctx, id)
	if err != nil {
		return store.NotificationEndpoint{}, fmt.Errorf("service.Get: %w", err)
	}
	return ep, nil
}

// Create validates rawURL, mints and seals a fresh signing secret, and
// inserts a new endpoint. The returned string is the plaintext secret,
// base64-encoded for display — it is shown to the caller exactly once and is
// never persisted or logged in the clear.
//
// Validation performs no DNS: a scheme other than http/https is rejected,
// and — only when the host is an IP literal — notify.Permit is applied
// directly. A hostname is accepted without resolution; the dial-time guard
// polices the address actually reached on every attempt.
func (s *NotificationService) Create(ctx context.Context, actorID, label, rawURL string) (store.NotificationEndpoint, string, error) {
	if err := validateTarget(rawURL, s.allowed); err != nil {
		details, _ := json.Marshal(map[string]string{"url": rawURL, "reason": err.Error()})
		s.audit.Log(ctx, store.AuditEntry{
			ActorUserID: actorID, EventType: "notification.target_rejected",
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
		Label:        label,
		URL:          rawURL,
		SecretSealed: sealed,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.st.NotificationEndpoints().Create(ctx, ep); err != nil {
		return store.NotificationEndpoint{}, "", fmt.Errorf("service.Create: %w", err)
	}

	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "notification.endpoint_created",
		TargetType: "notification_endpoint", TargetID: ep.ID,
	})
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "notification.secret_revealed",
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
func (s *NotificationService) SetEnabled(ctx context.Context, actorID, id string, enabled bool) error {
	if err := s.st.NotificationEndpoints().SetEnabled(ctx, id, enabled); err != nil {
		return fmt.Errorf("service.SetEnabled: %w", err)
	}
	event := "notification.endpoint_disabled"
	if enabled {
		event = "notification.endpoint_enabled"
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: event, TargetType: "notification_endpoint", TargetID: id,
	})
	return nil
}

// Delete removes an endpoint (its deliveries cascade per the schema FK).
func (s *NotificationService) Delete(ctx context.Context, actorID, id string) error {
	if err := s.st.NotificationEndpoints().Delete(ctx, id); err != nil {
		return fmt.Errorf("service.Delete: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "notification.endpoint_deleted",
		TargetType: "notification_endpoint", TargetID: id,
	})
	return nil
}

// Test enqueues one endpoint.test attempt against id. ok=false with err=nil
// means refused: the endpoint does not exist or is disabled. The enabled
// predicate is carried by the single atomic INSERT this wraps, so there is
// deliberately no preceding read.
func (s *NotificationService) Test(ctx context.Context, actorID, id string) (bool, error) {
	now := store.NowUnix()
	payload, err := notify.RenderTest(now)
	if err != nil {
		return false, fmt.Errorf("service.Test: render payload: %w", err)
	}
	ok, err := s.st.NotificationDeliveries().InsertUserTest(ctx, id, payload, now)
	if err != nil {
		return false, fmt.Errorf("service.Test: %w", err)
	}
	if !ok {
		return false, nil
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "notification.test_sent",
		TargetType: "notification_endpoint", TargetID: id,
	})
	return true, nil
}

// Redeliver inserts a copy of the terminal delivery identified by deliveryID.
// ok=false with err=nil means refused: deliveryID does not exist, its
// endpoint is disabled, or the source row is not terminal. All three
// predicates are carried by the single atomic INSERT this wraps.
func (s *NotificationService) Redeliver(ctx context.Context, actorID string, deliveryID int64) (bool, error) {
	ok, err := s.st.NotificationDeliveries().InsertRedelivery(ctx, deliveryID, store.NowUnix())
	if err != nil {
		return false, fmt.Errorf("service.Redeliver: %w", err)
	}
	if !ok {
		return false, nil
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "notification.redelivered",
		TargetType: "notification_delivery", TargetID: strconv.FormatInt(deliveryID, 10),
	})
	return true, nil
}

// Deliveries returns up to limit deliveries for endpointID, most recent first.
func (s *NotificationService) Deliveries(ctx context.Context, endpointID string, limit int) ([]store.NotificationDelivery, error) {
	rows, err := s.st.NotificationDeliveries().ListByEndpoint(ctx, endpointID, limit)
	if err != nil {
		return nil, fmt.Errorf("service.Deliveries: %w", err)
	}
	return rows, nil
}
