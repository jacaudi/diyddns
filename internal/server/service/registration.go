package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/store"
)

// RegistrationStatus says whether an account can sign in yet and, if not,
// what kind of registration link it has outstanding (#177). It is derived
// from live state on every read, never stored (design D3).
type RegistrationStatus string

const (
	// RegistrationRegistered means the account has a passkey or a linked
	// OIDC identity, so it can sign in.
	RegistrationRegistered RegistrationStatus = "registered"
	// RegistrationInvited means no credential yet, and a live "invite" grant.
	RegistrationInvited RegistrationStatus = "invited"
	// RegistrationRecoveryPending means no credential, and a live "recovery"
	// grant (an admin revoked every passkey and issued a recovery link).
	RegistrationRecoveryPending RegistrationStatus = "recovery_pending"
	// RegistrationLinkExpired means no credential and no live grant; the
	// admin must send a new registration link.
	RegistrationLinkExpired RegistrationStatus = "link_expired"
)

// Registration is one account's registration status. LinkExpiresAt is the
// unix second the outstanding link stops working, set only for invited and
// recovery_pending (design D14): a registered account's live self-service
// recovery link is not an admin concern.
type Registration struct {
	Status        RegistrationStatus
	LinkExpiresAt int64
}

// IsRegistered is the single definition of "this account can sign in"
// (design D15). The status derivation, ReissueInvite's guard and every web
// UI gate read it, so they can never disagree.
func IsRegistered(u store.User, credCount int) bool {
	return credCount > 0 || u.OIDCSubject != ""
}

// deriveRegistration maps one account's facts to its status: registered wins;
// otherwise the live grant's reason decides; no live grant is link_expired.
func deriveRegistration(u store.User, credCount int, live store.LiveGrant, hasLive bool) Registration {
	switch {
	case IsRegistered(u, credCount):
		return Registration{Status: RegistrationRegistered}
	case !hasLive:
		return Registration{Status: RegistrationLinkExpired}
	case live.Reason == "recovery":
		return Registration{Status: RegistrationRecoveryPending, LinkExpiresAt: live.ExpiresAt}
	default:
		return Registration{Status: RegistrationInvited, LinkExpiresAt: live.ExpiresAt}
	}
}

// RegistrationStatuses derives the registration status of every user in
// users, with two aggregate queries regardless of how many users there are
// (design D5). It returns an entry for EVERY user passed in, so a caller can
// never read a zero-value Registration: huma does not validate response
// bodies, so this guarantee is what keeps the API's registration_status
// inside its enum. Callers pass the users they already hold, and the now they
// will render remaining time against.
func (s *AdminService) RegistrationStatuses(ctx context.Context, users []store.User, now int64) (map[string]Registration, error) {
	counts, err := s.st.WebAuthnCredentials().CountAllByUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.RegistrationStatuses: %w", err)
	}
	live, err := s.st.AccountRecovery().LiveByUser(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("service.RegistrationStatuses: %w", err)
	}
	out := make(map[string]Registration, len(users))
	for _, u := range users {
		g, ok := live[u.ID]
		out[u.ID] = deriveRegistration(u, counts[u.ID], g, ok)
	}
	return out, nil
}
