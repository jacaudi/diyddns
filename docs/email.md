# Email

*Optional, off by default.*

DIYDDNS can email the registration links it issues — the passkey recovery link a
user requests themselves, and the invite and recovery links an admin issues from
the Users screen.

It is **disabled by default**, and that is a supported way to run: with email off,
an admin is shown each link once on screen and delivers it out of band. Air-gapped
and SMTP-less deployments need nothing further.

Turning it on also emails the link to the user. The link is still shown on screen
either way, so a mail failure never costs them the link — though the delivery
status the admin is shown reflects what was known by the time the send gave up,
not necessarily the final outcome (see
[When a mail server misbehaves](#when-a-mail-server-misbehaves)).

| Key | Env var | Notes |
|---|---|---|
| `email.enabled` | `DIYDDNS_EMAIL_ENABLED` | `false` by default |
| `email.host` | `DIYDDNS_EMAIL_HOST` | **required** when enabled |
| `email.port` | `DIYDDNS_EMAIL_PORT` | **required** when enabled — 587 starttls · 465 implicit · 25 none |
| `email.username` | `DIYDDNS_EMAIL_USERNAME` | empty skips SMTP AUTH; set it together with `email.password` or not at all; with `tls: none` refuses to start (see below). No leading or trailing whitespace |
| `email.password` | `DIYDDNS_EMAIL_PASSWORD` | never logged; set it together with `email.username` or not at all. No leading or trailing whitespace |
| `email.from` | `DIYDDNS_EMAIL_FROM` | **required** when enabled — envelope sender; a bare address with a dotted domain (`diyddns@example.com`, not `diyddns@localhost`) |
| `email.tls` | `DIYDDNS_EMAIL_TLS` | `starttls` (default), `implicit`, or `none` |

Enabling email **requires `server.base_url`, `email.host`, `email.port` and `email.from`**; the
server refuses to start without them. Emailed links must be absolute, and the other three have no
usable default — `port` defaults to `0`. It also refuses to start with `email.username` set and
`email.tls: none` against anything other than `localhost`/`127.0.0.1`/`::1` — credentials are
never sent over an unencrypted connection. It likewise refuses to start if only one of
`email.username`/`email.password` is set, or if either one has leading or trailing whitespace.
Every problem is collected and
reported in a single error, so enabling email from scratch means fixing everything in one deploy
cycle instead of discovering the next missing key on each restart.

Mail is sent through the `mailto` service of [`unraid/apprise-go`](https://github.com/unraid/apprise-go).
For `tls: starttls` and `tls: implicit`, that library reads `SSL_CERT_FILE` itself, on every
platform: when the variable is set, the PEM file it names **replaces** the trust store for the SMTP
connection, and `SSL_CERT_DIR` is not consulted for SMTP at all. Leave both unset to use the
system roots. The trap: if you set `SSL_CERT_FILE` to trust an internal CA for a **webhook**
endpoint (see [Trusting an Internal CA](notifications.md#trusting-an-internal-ca)), that file becomes the **only** root for SMTP too,
and STARTTLS/implicit TLS to a public-CA mail relay fails until you append the public roots to
the same bundle.

Feed expiry warnings also route through this — see [Feed](feed.md#feed-expiry).

## Addresses the transport can't carry

Some syntactically valid recipient addresses cannot be carried by the transport as
written and are now refused before a send is even attempted, rather than being
silently accepted and attempted as they used to be. This affects an address on a
domain with no dot (`user@localhost`) and a bracketed IP literal
(`user@[192.168.1.1]`) — both parse as valid addresses, but the transport cannot
route either one as written. Use a domain with at least one dot, or accept that a
user at such an address won't receive mail from this system; the link is still
shown on screen either way.

## When a mail server misbehaves

At most 32 email sends are in flight at once. If a peer mail server accepts the
connection and then goes quiet — wedged, slow, or otherwise unresponsive — the
slot it holds stays occupied until that conversation ends. Once all 32 slots are
occupied, a new send fails immediately with a loud `ERROR`-level log rather than
queuing or blocking behind the stuck ones.

A send this system reports as failed because its deadline passed can still
complete afterward and deliver the message — including a single-use registration
link — even though the caller was already told it failed. Re-issuing the link
does not revoke the one already sent.

## Changing an Account's Email Address

Users can change their own address from `/account`; administrators can change any user's
address from `/admin/users/{id}`.

**Self-service** (`/account`): the user enters a new address, and a confirmation link is
emailed to it. Nothing about the account changes until they open that link while signed in
and confirm — the old address stays authoritative until then. The old address gets a
heads-up notice when the change is requested, and a change notice once it's confirmed. A
pending change can be cancelled from `/account` at any time before confirmation. If the new
address is one [the transport can't carry](#addresses-the-transport-cant-carry), the
confirmation send fails, the change is rolled back, and the user sees a generic
delivery-failure error rather than one naming the address as invalid.

**Admin-set** (`/admin/users/{id}`): an administrator can set a user's address directly,
effective immediately, with no confirmation step. The previous address is notified of the
change. This works even when the new address is one the transport can't carry — useful for
repairing an account stuck on an unroutable address — but the account is then stuck the same
way again until it's changed to a routable one, and the previous address's change notice
fails silently in the same case.

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
