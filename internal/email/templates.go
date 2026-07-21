package email

import (
	"strings"
	"text/template"
)

// recoveryTmpl and adminNotifyTmpl are fixed, package-level templates
// validated at init time via template.Must. Their data is always a single
// plain-string field (no user-supplied templates, no functions that could
// error), so renderTemplate's error path below is unreachable in practice —
// it exists only as a safe fallback, not a documented failure mode.
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

// RecoveryLinkBody renders the subject and body of the email sent to a user
// who requested a passkey recovery link.
func RecoveryLinkBody(link string) (subject, body string) {
	return renderTemplate(recoveryTmpl, "DIYDDNS passkey recovery link", struct{ Link string }{Link: link})
}

// AdminNotifyBody renders the subject and body of the email sent to
// administrators when a user's passkey recovery link is issued.
func AdminNotifyBody(userEmail string) (subject, body string) {
	return renderTemplate(adminNotifyTmpl, "DIYDDNS passkey recovery issued", struct{ Email string }{Email: userEmail})
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
