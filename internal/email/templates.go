package email

import (
	"strings"
	"text/template"
)

// recoveryTmpl, adminNotifyTmpl, inviteTmpl and adminRecoveryTmpl are fixed,
// package-level templates validated at init time via template.Must. Their data
// is always a single plain-string field (no user-supplied templates, no
// functions that could error), so renderTemplate's error path below is
// unreachable in practice — it exists only as a safe fallback, not a
// documented failure mode.
//
// recoveryTmpl is the SELF-SERVICE recovery body: the user asked for the link
// themselves and their passkeys still work, so it is safe to ignore. When an
// ADMIN issues the link the passkeys have already been revoked — use
// adminRecoveryTmpl (via AdminRecoveryLinkBody) instead.
var recoveryTmpl = template.Must(template.New("recovery-link").Parse(
	"A passkey recovery link was requested for your DIYDDNS account.\r\n\r\n" +
		"Use the link below to add a new passkey. It expires shortly and can only be used once.\r\n\r\n" +
		"{{.Link}}\r\n\r\n" +
		"If you did not request this, you can safely ignore this email.\r\n",
))

var adminNotifyTmpl = template.Must(template.New("admin-notify").Parse(
	"A passkey recovery link was issued for the account {{.Email}}.\r\n\r\n" +
		"No action is required unless this was unexpected.\r\n",
))

var inviteTmpl = template.Must(template.New("invite-link").Parse(
	"An account has been created for you on DIYDDNS.\r\n\r\n" +
		"Use the link below to finish setting it up by registering a passkey.\r\n" +
		"It expires shortly and can only be used once.\r\n\r\n" +
		"{{.Link}}\r\n\r\n" +
		"If you were not expecting this, contact the administrator who invited you.\r\n",
))

var adminRecoveryTmpl = template.Must(template.New("admin-recovery-link").Parse(
	"An administrator has reset the passkeys on your DIYDDNS account.\r\n\r\n" +
		"Every passkey on the account has already been revoked, so you cannot\r\n" +
		"sign in until you register a new one. Use the link below to do that;\r\n" +
		"it expires shortly and can only be used once.\r\n\r\n" +
		"{{.Link}}\r\n\r\n" +
		"If you were not expecting this, contact your administrator. Do not\r\n" +
		"disregard this message: your existing passkeys no longer work.\r\n",
))

// RecoveryLinkBody renders the subject and body of the email sent to a user
// who requested a passkey recovery link themselves. For an admin-issued
// recovery link use AdminRecoveryLinkBody.
func RecoveryLinkBody(link string) (subject, body string) {
	return renderTemplate(recoveryTmpl, "DIYDDNS passkey recovery link", struct{ Link string }{Link: link})
}

// AdminNotifyBody renders the subject and body of the email sent to
// administrators when a user's passkey recovery link is issued.
func AdminNotifyBody(userEmail string) (subject, body string) {
	return renderTemplate(adminNotifyTmpl, "DIYDDNS passkey recovery issued", struct{ Email string }{Email: userEmail})
}

// InviteLinkBody renders the subject and body of the email sent to a user an
// admin has just created an account for.
func InviteLinkBody(link string) (subject, body string) {
	return renderTemplate(inviteTmpl, "You have been invited to DIYDDNS", struct{ Link string }{Link: link})
}

// AdminRecoveryLinkBody renders the subject and body of the email sent when an
// ADMIN issues a recovery link. It deliberately does not reuse RecoveryLinkBody:
// that body says the link "was requested" and can be "safely ignored", and both
// are false here — GrantService.IssueRecovery has already revoked every passkey
// on the account, so disregarding this email leaves the user locked out.
func AdminRecoveryLinkBody(link string) (subject, body string) {
	return renderTemplate(adminRecoveryTmpl, "Your DIYDDNS passkeys were reset by an administrator", struct{ Link string }{Link: link})
}

// The four #131 bodies. Every address interpolated below has passed
// NormalizeAddress at the service boundary, so it is 7-bit ASCII and
// checkSendable's body check cannot reject the message; no body function
// ever receives a raw input (design §5.4).

var emailChangeConfirmTmpl = template.Must(template.New("email-change-confirm").Parse(
	"A request was made to change the email address on your DIYDDNS account\r\n" +
		"to this one.\r\n\r\n" +
		"Nothing changes until you open the link below. You need to be signed in\r\n" +
		"to DIYDDNS in the same browser when you open it; if you are not, sign in\r\n" +
		"first and then open the link again. It expires in one hour and can be\r\n" +
		"used once.\r\n\r\n" +
		"{{.Link}}\r\n\r\n" +
		"If you did not request this, you can ignore this email.\r\n",
))

var emailChangeNoticeTmpl = template.Must(template.New("email-change-notice").Parse(
	"A request was made to change the email address on your DIYDDNS account\r\n" +
		"to {{.NewEmail}}.\r\n\r\n" +
		"Nothing has changed yet: this address stays in charge of your account\r\n" +
		"until the new one confirms. If this was not you, sign in, open Account\r\n" +
		"and cancel the pending change, or contact your administrator.\r\n",
))

var emailChangedTmpl = template.Must(template.New("email-changed").Parse(
	"The email address on your DIYDDNS account has been changed to\r\n" +
		"{{.NewEmail}}. Sign-in and passkey recovery mail now go there.\r\n\r\n" +
		"If you did not make this change, contact your administrator immediately.\r\n",
))

var adminEmailChangedTmpl = template.Must(template.New("admin-email-changed").Parse(
	"An administrator has changed the email address on your DIYDDNS account\r\n" +
		"to {{.NewEmail}}. Sign-in and passkey recovery mail now go there.\r\n\r\n" +
		"If this was unexpected, contact your administrator.\r\n",
))

// ChangeConfirmBody renders the mail sent to a NEW address the account
// holder wants to move to. Opening the link needs their session (design D6),
// and the body says so.
func ChangeConfirmBody(link string) (subject, body string) {
	return renderTemplate(emailChangeConfirmTmpl, "Confirm your new DIYDDNS email address", struct{ Link string }{Link: link})
}

// ChangeNoticeBody renders the heads-up sent to the OLD address when a
// self-service change is requested, naming the requested address and the two
// ways to react.
func ChangeNoticeBody(newEmail string) (subject, body string) {
	return renderTemplate(emailChangeNoticeTmpl, "A DIYDDNS email address change was requested", struct{ NewEmail string }{NewEmail: newEmail})
}

// ChangedBody renders the notice sent to the OLD address once a change
// the account holder made (self-service confirm, or their IdP) has taken
// effect. For an admin-made change use AdminChangedBody: this body's
// closing line assumes the reader could have made the change themselves.
func ChangedBody(newEmail string) (subject, body string) {
	return renderTemplate(emailChangedTmpl, "Your DIYDDNS email address was changed", struct{ NewEmail string }{NewEmail: newEmail})
}

// AdminChangedBody renders the notice sent to the OLD address once an
// ADMIN has changed it. Deliberately not ChangedBody with a flag, for
// the reason AdminRecoveryLinkBody gives: the closing lines say opposite
// things.
func AdminChangedBody(newEmail string) (subject, body string) {
	return renderTemplate(adminEmailChangedTmpl, "Your DIYDDNS email address was changed by an administrator", struct{ NewEmail string }{NewEmail: newEmail})
}

// renderTemplate executes tmpl against data and returns (subject, body). If
// execution fails — which should not happen for the fixed templates and
// plain-string data above — it falls back to a subject-only body rather than
// returning an error, since the exported signatures are (subject, body
// string) with no error to propagate.
func renderTemplate(tmpl *template.Template, subject string, data any) (string, string) {
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return subject, subject
	}
	return subject, sb.String()
}
