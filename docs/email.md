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

---
[← Back to README](../README.md)
