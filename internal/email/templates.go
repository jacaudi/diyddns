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
