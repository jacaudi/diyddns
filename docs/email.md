# Email

*Optional, off by default.*

DIYDDNS can email the registration links it issues — the passkey recovery link a
user requests themselves, and the invite and recovery links an admin issues from
the Users screen.

It is **disabled by default**, and that is a supported way to run: with email off,
an admin is shown each link once on screen and delivers it out of band. Air-gapped
and SMTP-less deployments need nothing further.

Turning it on also emails the link to the user. The link is still shown on screen
either way, and the admin is told whether delivery succeeded, so a mail failure
never costs them the link.

| Key | Env var | Notes |
|---|---|---|
| `email.enabled` | `DIYDDNS_EMAIL_ENABLED` | `false` by default |
| `email.host` | `DIYDDNS_EMAIL_HOST` | **required** when enabled |
| `email.port` | `DIYDDNS_EMAIL_PORT` | **required** when enabled — 587 starttls · 465 implicit · 25 none |
| `email.username` | `DIYDDNS_EMAIL_USERNAME` | empty skips SMTP AUTH; non-empty with `tls: none` refuses to start (see below) |
| `email.password` | `DIYDDNS_EMAIL_PASSWORD` | never logged |
| `email.from` | `DIYDDNS_EMAIL_FROM` | **required** when enabled — envelope sender |
| `email.tls` | `DIYDDNS_EMAIL_TLS` | `starttls` (default), `implicit`, or `none` |

Enabling email **requires `server.base_url`, `email.host`, `email.port` and `email.from`**; the
server refuses to start without them. Emailed links must be absolute, and the other three have no
usable default — `port` defaults to `0`. It also refuses to start with `email.username` set and
`email.tls: none` against anything other than `localhost`/`127.0.0.1`/`::1` — Go's `net/smtp`
refuses to send credentials over an unencrypted connection. Every problem is collected and
reported in a single error, so enabling email from scratch means fixing everything in one deploy
cycle instead of discovering the next missing key on each restart.

Feed expiry warnings also route through this — see [Feed](feed.md#feed-expiry).

## Changing an Account's Email Address

Users can change their own address from `/account`; administrators can change any user's
address from `/admin/users/{id}`.

**Self-service** (`/account`): the user enters a new address, and a confirmation link is
emailed to it. Nothing about the account changes until they open that link while signed in
and confirm — the old address stays authoritative until then. The old address gets a
heads-up notice when the change is requested, and a change notice once it's confirmed. A
pending change can be cancelled from `/account` at any time before confirmation.

**Admin-set** (`/admin/users/{id}`): an administrator can set a user's address directly,
effective immediately, with no confirmation step. The previous address is notified of the
change.

**OIDC-linked accounts**: a user who signs in through an external identity provider has
their stored address follow the identity provider's `email` claim at every sign-in, so
self-service change is unavailable to them. An administrator can still set the address
directly; the admin UI warns that the identity provider will replace it again at the
user's next sign-in.

Self-service change requires `email.enabled: true` — without a mailer there is nowhere to
send the confirmation link, so the form is not shown. Admin-set changes take effect
immediately regardless of `email.enabled`, since applying the change doesn't depend on
sending anything; with email disabled, the previous address simply isn't notified.

---
[← Back to README](../README.md)
