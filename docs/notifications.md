# Notifications (Webhooks)

*Optional, off by default.*

DIYDDNS can deliver a signed webhook to endpoints an **admin** configures whenever a device
joins the feed, leaves it, or changes its public IP, plus an on-demand `endpoint.test` probe for
checking an endpoint before you trust it. This is a generic outbound notifier — it is not a DNS
publisher, and it does not replace an authoritative DNS record.

Endpoints are **server-global and admin-only**: every enabled endpoint receives every user's
device events, and only an admin can create, test, disable or delete one. Users cannot configure
the outbound service. (Endpoints created under the earlier per-user model are removed on upgrade
and must be recreated by an admin.)

It is **disabled by default**. Turning it on is also what makes `/admin/endpoints` exist as a
route at all — with notifications off, the whole route group is absent, not merely empty.

| Key | Env var | Notes |
|---|---|---|
| `notifications.enabled` | `DIYDDNS_NOTIFICATIONS_ENABLED` | `false` by default |
| `notifications.allowed_private_cidrs` | `DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS` | operator-only egress allow-list; comma-separated over env; see "Egress policy" below |
| `notifications.timeout` | `DIYDDNS_NOTIFICATIONS_TIMEOUT` | per-attempt HTTP timeout, default `10s` |
| `notifications.max_attempts` | `DIYDDNS_NOTIFICATIONS_MAX_ATTEMPTS` | delivery attempts (with doubling backoff) before giving up, default `8`, must be 1–16 |

(`notifications.max_endpoints_per_user` is gone; a config file still carrying it is ignored.)

An admin adds an endpoint from `/admin/endpoints`: a label and a target URL. The response shows
that endpoint's signing secret exactly once — copy it immediately, it cannot be shown again, and
creating another endpoint will not show it again either.

## The payload

Every delivery is one JSON object, one event. There are three device events and one rule for
all of them: **the device's allowed set is now `current`** — an all-null `current` means delete
that device. Keep state per device `id`; your allow-list is the union of every device's set.

| Type | When | `previous` | `current` | `id` |
|---|---|---|---|---|
| `device.ip_changed` | a member's address moved on check-in — **including a device's first check-in**, which is how a new device joins | the old addresses (both `null` on a first check-in) | the new addresses | the `ip_history` row id |
| `device.added` | a device with an address re-joins the feed: it, or its owner, was re-enabled | both `null` | its addresses | the feed sequence number |
| `device.removed` | a device leaves the feed: it was disabled or deleted, or its owner was | its last addresses | both `null` | the feed sequence number |

Do not key on `type` to detect a join (it can arrive as either `ip_changed` or `added`), and do
not remove an address by value: two devices behind one NAT share it, and only the per-device
union tells you when it is really gone.

Here is a `device.ip_changed` event:

```json
{
  "version": 1,
  "type": "device.ip_changed",
  "id": 4821,
  "occurred_at": "2026-08-27T14:03:11Z",
  "device": { "id": "dev_01hh2k9z3q8f7yq6y1n0f0k5xr", "label": "home-router" },
  "changed": ["ipv4"],
  "current": { "ipv4": "203.0.113.9", "ipv6": null },
  "previous": { "ipv4": "203.0.113.4", "ipv6": null }
}
```

The `device` object carries exactly `id` and `label`. A `device.removed` event has the same shape
with `current` all-null and `previous` holding the withdrawn addresses; `device.added` is the
mirror image. **`device.removed`'s all-null `current` is a withdrawal marker constructed for the
event, not proof the stored address was cleared** — disabling a device leaves its stored address
intact (see [Feed expiry](feed.md#feed-expiry) for the one case that really does clear it).

And an `endpoint.test` event, sent when you press "Test" on an endpoint — same envelope, no
device, no addresses, `id` always `0`:

```json
{
  "version": 1,
  "type": "endpoint.test",
  "id": 0,
  "occurred_at": "2026-08-27T14:05:00Z",
  "device": null,
  "changed": [],
  "current": { "ipv4": null, "ipv6": null },
  "previous": { "ipv4": null, "ipv6": null }
}
```

`changed` names exactly which address families moved in this event — it is sent as-is, not left
for you to derive from `current`/`previous`. A device that only ever reports IPv4 keeps carrying
its last-known IPv6 address in both `current.ipv6` and `previous.ipv6`, unchanged, **until it goes
unconfirmed for `feed.expire_after_days`** (see [Feed expiry](feed.md#feed-expiry)), at which point IPv6
is withdrawn: that expiry event carries `previous.ipv6` as the address that was just cleared and
`current.ipv6` as `null`, with `device.ip_changed` naming `ipv6` in `changed` — the same
"previous differs from current" shape every other change in this event uses. Only a *subsequent*
event, after the withdrawal has already happened, carries both `current.ipv6` and `previous.ipv6`
as `null`. Short of that expiry, the presence of a non-null `current.ipv6` does **not** mean IPv6
just changed. **Trust `type` and `changed`, never field presence, for "what happened."** This
matters even when *every* family goes null at once: if a device's last remaining address family
expires, the resulting `device.ip_changed` event is payload-identical to a `device.removed` event
except for `type` — branch on `type`, never on whether `current` is all-null.

An address family that has never been reported is JSON **`null`**, never `""`. Do not treat the
two as equivalent: `null` means "this device has no IPv6 (or IPv4) on record," while `""` would
be indistinguishable from "the address was explicitly cleared." Collapsing them loses that
distinction anywhere you store or diff the value.

## Dedupe on `(type, id)`, not `id` alone

Delivery is **at-least-once**: if the server crashes after a successful POST but before it
records the outcome, the same delivery — byte-identical payload — is retried after restart. A
consumer that does not dedupe will act on it twice.

`id` is the `ip_history` row id the event came from, and it is **shared across every endpoint** a
given `device.ip_changed` event fans out to and **reused on every retry** of the same delivery.
`endpoint.test` always carries `id: 0`, regardless of how many times you press "Test." **Dedupe
on the pair `(type, id)`, never on `id` alone** — an endpoint that deduped on `id` alone would
accept the very first `endpoint.test` it ever received (`id: 0`) and silently discard every test
after that, forever.

Do not treat gaps in `id` as evidence of a missed delivery: `ip_history.id` is a server-global
sequence shared by every device on the server, not a per-endpoint or per-device counter, so gaps
between the ids your endpoint sees are the normal case, not a signal of anything wrong. For
`device.added` and `device.removed` the id is the feed sequence number rather than an
`ip_history` id; it is unique per event and the same `(type, id)` rule applies.

## Verifying a delivery

Every delivery carries three headers alongside the JSON body:

| Header | Contents |
|---|---|
| `X-Diyddns-Timestamp` | decimal Unix seconds |
| `X-Diyddns-Nonce` | 16 random bytes, base64 **RawURL**-encoded |
| `X-Diyddns-Signature` | lowercase-hex HMAC-SHA256 |

To verify a delivery:

1. **Get the raw key.** The secret shown once at endpoint creation is base64 (standard encoding)
   text. Base64-**decode** it to get 32 raw bytes — **that raw byte string is the HMAC key, not
   the base64 text you were shown.** Signing with the base64 string itself is the single most
   common way to get this wrong.
2. **Hash the raw body.** Take the SHA-256 of the exact bytes your HTTP server received on the
   wire — hex-encode it. This must be the **raw received bytes**, never a re-marshalled/re-encoded
   copy of the parsed JSON: re-marshalling can reorder keys, change number formatting, or alter
   whitespace relative to what was actually signed, and is the usual way webhook signature
   verification quietly breaks.
3. **Build the canonical string**, LF-joined, exactly:

   ```
   diyddns-notify-v1
   <X-Diyddns-Timestamp value>
   <X-Diyddns-Nonce value>
   <hex body hash from step 2>
   ```

   The nonce goes in **as the base64 RawURL-encoded string from the header** — not decoded back
   to its 16 raw bytes.
4. **Compute HMAC-SHA256** of that canonical string using the raw key from step 1, hex-encode the
   result, and compare it (constant-time) against `X-Diyddns-Signature`.

Once verified, **branch on the body's `type`.** Known types today are `device.ip_changed`,
`device.added`, `device.removed` and `endpoint.test`; **ignore any type you don't recognize**
rather than erroring — a future version may add new event types, and treating an unknown type as
an error breaks forward compatibility for every existing consumer.

## `410 Gone` ends that delivery

Respond `410 Gone` and that **one delivery** stops immediately — no further retries for it,
regardless of attempts remaining. It does **not** disable the endpoint: the next event (a new IP
change, or another manual test) is still delivered to it. There is no consumer-side way to opt an
endpoint out of future deliveries in this version; only an admin can disable or delete the
endpoint. Every other non-2xx response (or no response at all — timeout, connection refused, TLS
failure) is retried with doubling backoff up to `notifications.max_attempts`.

## Egress policy (operator-only)

A notification endpoint's destination is policed at the address DIYDDNS actually dials, every
attempt — not just at the URL you typed when creating it. By default, no private or loopback
address is reachable at all, and `https://` is required for every destination except loopback,
which may also use plain `http://`.

To permit a private or loopback destination, an operator — never the user creating the
endpoint — must add its CIDR to `notifications.allowed_private_cidrs`. This is settable only via
the YAML config file or the `DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS` environment variable;
there is no UI or per-user control for it.

Two ranges need an explicit entry if you use them as a destination, because both are private by
default like any other internal range:

- **Tailscale**: its CGNAT IPv4 range `100.64.0.0/10` and its IPv6 range `fd7a:115c:a1e0::/48`
  (Tailscale's own allocation within the ULA space, not the whole `fc00::/7`).
- **NAT64**: `64:ff9b::/96`.

Permitting `64:ff9b::/96` is unusually consequential: that prefix embeds an IPv4 address in its
low 32 bits, so allowing the whole `/96` **also re-permits the cloud metadata address**
`169.254.169.254` (as `64:ff9b::a9fe:a9fe`), which is reachable from inside many cloud VMs. Prefer
narrowing the prefix to what you actually need over allowing the full `/96`. The server logs a
startup warning when a configured prefix is this broad.

## Trusting an internal CA

If a notification endpoint sits behind a certificate from an internal/private CA, set
`SSL_CERT_FILE` (a PEM bundle) or `SSL_CERT_DIR` in the server's environment so the outbound
HTTPS client trusts it. **This works on Linux — the shipped container image — but not on
macOS**: Go's certificate verifier on Darwin uses the OS's own Security framework instead of these
variables, so a self-built macOS binary needs the CA installed in the system keychain instead.

## What an admin sees on failure

A failed delivery's cause is reported on the endpoint's page as exactly one of six fixed classes:
`blocked`, `unreachable`, `tls`, `rejected`, `gone` ("Target removed (410)"), `internal`. The
resolved address and raw error go to the server log and, for a policy rejection, the audit log.

## A webhook-only consumer cannot detect a lost event

Delivery is retried until it succeeds or gives up, but the *enqueue* is best-effort: if the
database write that queues an event fails, that event is never sent and there is no later
signal that it was lost. A consumer that must never drift should also poll the [feed](feed.md),
which reads the current state directly.

---
[← Back to README](../README.md)
