package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	// Aliased: this file has a parameter named `email`, and revive's
	// import-shadowing rule (enabled repo-wide, and NOT excluded for any file)
	// fails on an unaliased import of the same name.
	emailpkg "github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// Guard sentinels — mapped to HTTP 409/422 by the API layer.
var (
	// ErrLastAdmin is returned when an operation would leave zero enabled admins.
	ErrLastAdmin = errors.New("service: cannot remove the last admin")
	// ErrSelfLockout is returned when an admin tries to disable, delete, or
	// demote themselves.
	ErrSelfLockout = errors.New("service: cannot disable or delete your own account")
	// ErrInvalidRole is returned for a role outside {admin, user}.
	ErrInvalidRole = errors.New("service: invalid role")
	// ErrInvalidEmail is returned when an email address fails RFC parsing, is
	// not 7-bit ASCII, or is not already in bare canonical addr-spec form (a
	// display name or surrounding whitespace).
	ErrInvalidEmail = errors.New("service: invalid email address")
	// ErrOwnerMissing is returned by GetDevice when a device row's owner row
	// does not exist. The users→devices foreign key cascades, so this is a
	// fault, and it deliberately does NOT satisfy errors.Is(err,
	// store.ErrNotFound): the web handler must not answer "that device does
	// not exist" about a device that demonstrably does (#132 D18).
	ErrOwnerMissing = errors.New("service: device owner row is missing")
)

// UpdateUserParams is the partial-update input to UpdateUser. A nil field is
// left unchanged.
type UpdateUserParams struct {
	Role     *string
	Disabled *bool
}

// AdminService implements admin-only user management (with lockout guards),
// plus cross-user device reads, the one admin device mutation (#132), and
// audit reads.
type AdminService struct {
	deviceMutator // st, audit, notify — shared with DeviceService (#132 D8)
	grants        *GrantService
	mailer        emailpkg.Mailer
	log           *slog.Logger
}

// NewAdminService constructs an AdminService. grants drives CreateUserInvite's
// registration-grant issuance (design D15); it may be nil if WebAuthn is not
// configured, in which case CreateUserInvite returns ErrWebAuthnUnavailable.
// notify is told, per device, when a user's disable/enable/delete moves that
// user's devices out of or into the gateway feed (#106). mailer carries the
// owner notice for SetDeviceEnabled (#132 D10) and may be nil, which is
// treated as disabled; log must not be nil.
func NewAdminService(st *store.Store, audit AuditSink, grants *GrantService, notify DeviceNotifier, mailer emailpkg.Mailer, log *slog.Logger) *AdminService {
	return &AdminService{
		deviceMutator: deviceMutator{st: st, audit: audit, notify: notify},
		grants:        grants,
		mailer:        mailer,
		log:           log,
	}
}

func validRole(r string) bool { return r == "admin" || r == "user" }

// enabledAdminCount returns how many enabled admins exist, and whether target
// is currently one of them.
func (s *AdminService) enabledAdminCount(ctx context.Context, targetID string) (count int, targetIsEnabledAdmin bool, err error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return 0, false, err
	}
	for _, u := range users {
		if u.IsEnabledAdmin() {
			count++
			if u.ID == targetID {
				targetIsEnabledAdmin = true
			}
		}
	}
	return count, targetIsEnabledAdmin, nil
}

// ListUsers returns all users ordered by email.
func (s *AdminService) ListUsers(ctx context.Context) ([]store.User, error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListUsers: %w", err)
	}
	return users, nil
}

// CreateUserInvite creates a credential-less local user (no password, no
// passkey) and mints a registration-grant invite link for it (design D15).
// The link drives GrantService's redeem flow, where the invited user
// registers their first passkey. The invite is also emailed to the new user
// when the mailer is enabled.
//
// The returned Delivery is advisory: a nil error means the link is valid and
// the caller MUST present it, whatever Delivery reports. A delivery failure is
// never this function's error, because the on-screen link is the only fallback
// a deployment without SMTP has.
func (s *AdminService) CreateUserInvite(ctx context.Context, actorID, email, role string) (store.User, string, Delivery, error) {
	if !validRole(role) {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", ErrInvalidRole)
	}
	// Normalize as well as validate. mail.ParseAddress accepts
	// "Bob <bob@example.test>", and discarding the parse result stored that raw
	// string, which then went out as RCPT TO:<Bob <bob@example.test>>. It is
	// pure ASCII, so the charset half of this check does not catch it.
	normalized, err := emailpkg.NormalizeAddress(email)
	if err != nil {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", ErrInvalidEmail)
	}
	email = normalized
	// s.grants itself may be non-nil while its passkeys dependency is (design
	// server.go leaves PasskeyService nil when hide_local_login_ui tolerates
	// an unresolved RP) — checking only s.grants == nil would let a dead
	// invite link (404s at redeem, register routes gated off
	// deps.Passkey != nil) slip through, so this checks both.
	if s.grants == nil || s.grants.passkeys == nil {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", ErrWebAuthnUnavailable)
	}

	// D20 (#131): GetByEmail and the UNIQUE index are exact and case-sensitive,
	// so without this an admin could create Bob@x.test beside bob@x.test --
	// two accounts on one mailbox. exceptID is EMPTY: an invite creates a row,
	// so no row is exempt, and passing actorID here would let an admin invite
	// a case-variant of their own address.
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", err)
	}
	if addressHeld(users, email, "", store.NowUnix()) {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", store.ErrConflict)
	}

	u, err := s.st.Users().Create(ctx, store.User{Email: email, Role: role})
	if err != nil {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", err) // ErrConflict flows up
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.created", TargetType: "user", TargetID: u.ID})

	link, d, err := s.grants.IssueInvite(ctx, actorID, u)
	if err != nil {
		return store.User{}, "", Delivery{}, fmt.Errorf("service.CreateUserInvite: %w", err)
	}
	return u, link, d, nil
}

// UpdateUser applies a partial update (role / disabled) with lockout
// guards. Disabling a user also revokes their active sessions.
func (s *AdminService) UpdateUser(ctx context.Context, actorID, targetID string, p UpdateUserParams) (store.User, error) {
	u, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err) // ErrNotFound flows up
	}

	if err := s.guardUpdateUser(ctx, actorID, targetID, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}

	if err := s.applyRole(ctx, actorID, targetID, u, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}
	if err := s.applyDisabled(ctx, actorID, targetID, u, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}

	updated, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}
	return updated, nil
}

// guardUpdateUser applies UpdateUser's lockout/validity guards: invalid
// role, self-demote, demoting/disabling the last enabled admin, and
// self-disable. u is the target's pre-update row (read by the caller).
func (s *AdminService) guardUpdateUser(ctx context.Context, actorID, targetID string, p UpdateUserParams) error {
	if p.Role != nil {
		if !validRole(*p.Role) {
			return ErrInvalidRole
		}
		if *p.Role != "admin" {
			// Self-demote is blocked unconditionally — regardless of how many
			// other admins exist — before the last-admin guard even runs.
			if targetID == actorID {
				return ErrSelfLockout
			}
			if err := s.guardLastAdmin(ctx, targetID); err != nil {
				return err
			}
		}
	}
	if p.Disabled != nil && *p.Disabled {
		if targetID == actorID {
			return ErrSelfLockout
		}
		if err := s.guardLastAdmin(ctx, targetID); err != nil {
			return err
		}
	}
	return nil
}

// applyRole writes the role change via Update (which writes all mutable
// columns) and audits it. u is the target's pre-update row, mutated in place
// before the write.
func (s *AdminService) applyRole(ctx context.Context, actorID, targetID string, u store.User, p UpdateUserParams) error {
	if p.Role == nil {
		return nil
	}
	u.Role = *p.Role
	if err := s.st.Users().Update(ctx, u); err != nil {
		return err
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.role_change", TargetType: "user", TargetID: targetID})
	return nil
}

// applyDisabled writes the disabled flag via SetDisabled and, on disable,
// revokes the target's active sessions (auditing session.revoked only if any
// were actually deleted). It then emits device.added / device.removed for
// every device of the target whose feed membership flipped.
//
// u is the target's PRE-WRITE row, handed in by UpdateUser. Do not re-read
// the user here: after the write the row already carries the new flag, so
// "before" would be computed wrong and every removed event would vanish
// (design #106 §7.2). The device list is read BEFORE SetDisabled, too: the
// membership seam must never leave the primary write applied (user disabled,
// sessions revoked) while reporting the request as failed (design D13) — a
// failure here now aborts cleanly before anything is written.
func (s *AdminService) applyDisabled(ctx context.Context, actorID, targetID string, u store.User, p UpdateUserParams) error {
	if p.Disabled == nil {
		return nil
	}
	devices, err := s.st.Devices().ListByUser(ctx, targetID)
	if err != nil {
		return err
	}
	if err := s.st.Users().SetDisabled(ctx, targetID, *p.Disabled); err != nil {
		return err
	}
	event := "user.enabled"
	if *p.Disabled {
		event = "user.disabled"
		n, err := s.st.Sessions().DeleteByUser(ctx, targetID)
		if err != nil {
			return err
		}
		if n > 0 {
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "session.revoked", TargetType: "user", TargetID: targetID})
		}
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: event, TargetType: "user", TargetID: targetID})

	after := u
	after.Disabled = *p.Disabled
	for _, d := range devices {
		emitMembership(ctx, s.notify, d, inFeed(d, u), inFeed(d, after))
	}
	return nil
}

// DeleteUser deletes a user (cascading sessions + devices + codes via FK), with
// last-admin and self-lockout guards. The target's devices are listed BEFORE
// the delete — the cascade destroys them — and device.removed is emitted for
// each one that was a feed member.
func (s *AdminService) DeleteUser(ctx context.Context, actorID, targetID string) error {
	if targetID == actorID {
		return fmt.Errorf("service.DeleteUser: %w", ErrSelfLockout)
	}
	if err := s.guardLastAdmin(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err)
	}
	u, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err) // ErrNotFound flows up
	}
	devices, err := s.st.Devices().ListByUser(ctx, targetID)
	if err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err)
	}
	if err := s.st.Users().Delete(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.deleted", TargetType: "user", TargetID: targetID})
	for _, d := range devices {
		emitMembership(ctx, s.notify, d, inFeed(d, u), false)
	}
	return nil
}

// guardLastAdmin returns ErrLastAdmin if targetID is currently the only enabled
// admin (so removing/demoting/disabling it would lock everyone out).
func (s *AdminService) guardLastAdmin(ctx context.Context, targetID string) error {
	count, targetIsEnabledAdmin, err := s.enabledAdminCount(ctx, targetID)
	if err != nil {
		return err
	}
	if targetIsEnabledAdmin && count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// ListAllDevices returns every device across all users (admin view).
func (s *AdminService) ListAllDevices(ctx context.Context) ([]store.Device, error) {
	devices, err := s.st.Devices().ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListAllDevices: %w", err)
	}
	return devices, nil
}

// ListAllDevicesWithExpiry is ListAllDevices's counterpart for the admin
// list, unscoped: it also returns each device's last-recorded address per
// family, for the rows a sweep has cleared. Two statements, the second
// issued only after ListAll's cursor is closed -- see
// DeviceService.ListWithExpiry for the same argument.
func (s *AdminService) ListAllDevicesWithExpiry(ctx context.Context) ([]store.Device, map[string]store.LatestAddress, error) {
	devices, err := s.st.Devices().ListAll(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("service.ListAllDevicesWithExpiry: %w", err)
	}
	latest, err := latestAddresses(ctx, s.st, devices)
	if err != nil {
		return nil, nil, fmt.Errorf("service.ListAllDevicesWithExpiry: %w", err)
	}
	return devices, latest, nil
}

// ListAudit returns a cursor-paginated page of audit-log entries.
func (s *AdminService) ListAudit(ctx context.Context, f store.AuditFilter, cursor string, limit int) (store.AuditPage, error) {
	page, err := s.st.AuditLog().ListPaginated(ctx, f, cursor, limit)
	if err != nil {
		return store.AuditPage{}, fmt.Errorf("service.ListAudit: %w", err)
	}
	return page, nil
}

// GetDevice returns any device by id together with its owner. Unscoped by
// construction: this service is the admin-only surface, and the route
// middleware, not this method, is what decides who may call it (#132 D5).
// Returns store.ErrNotFound for an unknown device id and ErrOwnerMissing for
// a device whose owner row is gone; the second names both ids for the log.
//
// Two statements, the second issued only after the first's row is scanned,
// which is what makes this safe on a pool of exactly one connection (see
// DeviceService.ListWithExpiry).
func (s *AdminService) GetDevice(ctx context.Context, id string) (store.Device, store.User, error) {
	dev, err := s.st.Devices().GetByID(ctx, id)
	if err != nil {
		return store.Device{}, store.User{}, fmt.Errorf("service.GetDevice: %w", err) // ErrNotFound flows up
	}
	owner, err := s.st.Users().GetByID(ctx, dev.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Device{}, store.User{}, fmt.Errorf("service.GetDevice: device %s owner %s: %w", id, dev.UserID, ErrOwnerMissing)
		}
		return store.Device{}, store.User{}, fmt.Errorf("service.GetDevice: %w", err)
	}
	return dev, owner, nil
}

// SetDeviceEnabled flips the disabled flag of ANY device on behalf of an
// admin (#132 D4, D7). actor is the admin's session: its UserID is the audit
// actor and its IP the audit source, following #137. The device's owner is
// resolved here and is the party the audit row's details and the owner
// notice name. This is the only admin mutation of a device: rename, secret
// rotation and deletion stay with the owner (#132 D3).
//
// Idempotent (#132 D11): when the device already holds the requested state
// nothing is written, audited or mailed — a double-submit must not send the
// owner a second unsolicited notice.
func (s *AdminService) SetDeviceEnabled(ctx context.Context, actor store.Session, id string, disabled bool) (store.Device, error) {
	dev, owner, err := s.GetDevice(ctx, id)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetDeviceEnabled: %w", err)
	}
	if dev.Disabled == disabled {
		return dev, nil
	}
	event := "device.enabled_by_admin"
	if disabled {
		event = "device.disabled_by_admin"
	}
	details, _ := json.Marshal(map[string]string{"owner_user_id": owner.ID})
	updated, err := s.flipDisabled(ctx, dev, owner, disabled, store.AuditEntry{
		ActorUserID: actor.UserID, EventType: event, TargetType: "device", TargetID: id,
		DetailsJSON: string(details), IP: actor.IP,
	})
	if err != nil {
		return store.Device{}, fmt.Errorf("service.SetDeviceEnabled: %w", err)
	}
	s.notifyOwner(ctx, actor, owner, dev, disabled)
	return updated, nil
}

// notifyOwner mails the device's owner that an admin changed its state. It
// mirrors GrantService.deliver (grants.go): a nil or disabled mailer sends
// nothing; cancellation is stripped so a closed browser tab does not abort
// the send; the send is bounded by adminDeliveryTimeout; a failure is logged
// and audited as email.send_failed against the owner — with the device in the
// details so the row can be told from an invite or recovery failure — and is
// never returned. The disable is the durable record; the mail is a courtesy
// (#132 D10, D17). The send is synchronous in the admin's request, exactly as
// the invite and recovery sends are.
//
// Deliberately a second copy of deliver's shape rather than a shared helper:
// deliver returns a Delivery the invite page renders and its timeout is a
// struct field a test shrinks; see the #132 design §7 for why extraction
// waits for a third caller.
func (s *AdminService) notifyOwner(ctx context.Context, actor store.Session, owner store.User, dev store.Device, disabled bool) {
	if s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	subject, body := emailpkg.DeviceStateChangedByAdminBody(dev.Label, dev.ID, disabled)
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), adminDeliveryTimeout)
	defer cancel()
	if err := s.mailer.Send(sendCtx, owner.Email, subject, body); err != nil {
		s.log.ErrorContext(ctx, "device state notice delivery failed",
			"error", err, "user_id", owner.ID, "device_id", dev.ID)
		details, _ := json.Marshal(map[string]string{"device_id": dev.ID})
		// The same context discipline as GrantService.auditSendFailure: never
		// the send's context (it may be the thing that just expired) and never
		// the raw request context (it may already be canceled).
		auditCtx, cancelAudit := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
		defer cancelAudit()
		s.audit.Log(auditCtx, store.AuditEntry{
			ActorUserID: actor.UserID, EventType: EventEmailSendFailed,
			TargetType: "user", TargetID: owner.ID, DetailsJSON: string(details), IP: actor.IP,
		})
	}
}
