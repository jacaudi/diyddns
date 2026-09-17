# Feed

*Optional, off by default.*

The feed is how a firewall, WAF, Envoy Gateway or other Kubernetes gateway consumes the current
device addresses: a bearer-token REST snapshot to poll, and a WebSocket stream for live changes.
It lists **every enabled device of every enabled user** that has an address.

| Key | Env var | Notes |
|---|---|---|
| `feed.enabled` | `DIYDDNS_FEED_ENABLED` | `false` by default; when off, none of the routes below nor `/admin/feed` exists |

## Tokens

An admin mints tokens at `/admin/feed`, one per consumer. The token is shown **once**, starts
with `ddf_`, and is stored only as a hash. Revoke it from the same page: the row is deleted and
any open stream authenticated with it is closed with code `4001`. Rotate by minting a new token,
reconfiguring the consumer, then revoking the old one.

Present it on every request as `Authorization: Bearer ddf_…`. That is the **only** accepted form:
there is no query-string or basic-auth variant (a fetcher that cannot set a header, such as
pfSense's URL table, is not supported). Browser JavaScript cannot set headers on a WebSocket
handshake; the consumers are services.

**What a token discloses:** the current public address, label and last-seen time of every enabled
device on the server, and their changes as they happen. Treat it like any other credential.

## `GET /feed/v1/devices.txt`

One CIDR per line, IPv4 as `/32` and IPv6 as `/128`, deduplicated and sorted, after a header line
that is always present (so an empty feed is still a non-empty body, distinguishable from a
truncated fetch):

```
# diyddns feed v1
203.0.113.9/32
2001:db8::1/128
```

This is the format pulled natively by OPNsense URL-table aliases, HAProxy Enterprise
`dynamic-update`, and ModSecurity `@ipMatchFromFile`, and written verbatim into HAProxy pattern
files and NGINX `include`s by a cron `curl`. Note it carries no device keying: a consumer of the
stream's deltas needs the JSON document below as its baseline.

## `GET /feed/v1/devices.json`

```json
{
  "version": 1,
  "cidrs": ["203.0.113.9/32", "2001:db8::1/128"],
  "devices": [
    { "id": "dev_…", "label": "home-router", "ipv4": "203.0.113.9", "ipv6": null,
      "last_seen_at": "2026-09-05T14:03:11Z" }
  ]
}
```

`cidrs` is byte-for-byte the text document's list, so Kubernetes glue is `jq -r '.cidrs[]'`.
`devices` carries each member's bare addresses (`null` for an absent family, never `""`). Adding
fields is compatible; changing their meaning is not (`version` would move).

## Validators

Each document carries its own strong `ETag` — the SHA-256 of *that document's* bytes, so the two
differ — plus `Last-Modified` (the time the feed last changed). Poll each URL against the tag it
gave you; a `.txt` tag never matches `.json` and vice versa. `HEAD` returns the same headers with no body. A request with a
matching `If-None-Match` gets `304`; `If-Modified-Since` is **ignored** and always answered with
the full document, because `Last-Modified` is informational — a wrong match would serve a stale
allow-list. A `304` is never sent to an unconditional request. On an internal error the response
is `500` with a body, never an empty `200`: keep your last good copy.

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" --etag-compare etag --etag-save etag \
  https://ddns.example.com/feed/v1/devices.txt -o new.lst && [ -s new.lst ] && ! cmp -s new.lst cur.lst \
  && mv new.lst cur.lst && nginx -s reload
```

## `GET /feed/v1/stream` (WebSocket)

Connect with the same header. **The stream is snapshot-then-deltas, and the consumer — not the
server — owns reconstructing current state from it.** The first frame is a snapshot, sent exactly
once at connect — the JSON document above wrapped as `{"version":1,"type":"feed.snapshot","feed":{…}}`
— and nothing resends it. Every frame after that is one incremental event, byte-identical to the
[webhook payload](notifications.md#the-payload) (`device.ip_changed`, `device.added`,
`device.removed`).

Initialise a `devices` map keyed by device `id` from the snapshot, then for every event that
follows: update that device's entry from `current` (an all-null `current` removes it from the
map), and **recompute `cidrs` as the union of every entry's non-null addresses** — never add or
remove a single address based on one event's `previous`/`current` in isolation. Two devices behind
one NAT sharing a public address is the normal case, not a corner case: if one of them is disabled
while the other still holds the address, the correct `cidrs` still contains it, because the other
device's entry still does. Branch on the event's `type`, never on whether `current` is all-null —
see [Notifications](notifications.md#the-payload) for why an all-null `current` can arrive on
either `device.ip_changed` (a device's last family expiring) or `device.removed` (the device
leaving the feed), and those two cases require different handling from your map.

The server pings every 30 s; a client that stops answering is closed. The client sends nothing
(frames under 4 KiB are ignored; larger ones close the connection with `1009`). Close codes:

| Code | Meaning | Client action |
|---|---|---|
| `1001` | server shutting down, or two pings unanswered | reconnect with backoff |
| `1009` | you sent a frame over 4 KiB | reconnect |
| `1011` | the snapshot could not be rendered | reconnect with backoff |
| `1013` | you fell 64 events behind and were cut | reconnect; the snapshot resyncs you |
| `4001` | your token was revoked | stop |

**The stream is at-most-once and non-durable.** An event that occurs while you are disconnected,
or that overflowed your buffer, is not replayed; reconnecting and taking the new snapshot as
authoritative is the recovery path. One consequence of that: a delta queued just before your
snapshot was rendered can be older than the snapshot for a device that changed twice in that
instant, so that device may briefly regress until the newer delta lands — and if *that* delta is
the one lost, until your next snapshot or poll. At most 32 streams are served at once; the 33rd
handshake gets `503`.

## Kubernetes glue

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" https://ddns.example.com/feed/v1/devices.json \
  | jq '{spec:{authorization:{rules:[{action:"Allow",principal:{clientCIDRs:.cidrs}}]}}}' \
  | kubectl patch securitypolicy allow-home --type merge -p "$(cat)"
```

## Feed expiry

An address that stops confirming itself is a stale allow-list entry, not a device you meant to
keep granting access. `feed.expire_after_days` clears an unconfirmed address from the device —
and therefore from the feed — after it has gone that many days without a check-in asserting it.

| Key | Env var | Notes |
|---|---|---|
| `feed.expire_after_days` | `DIYDDNS_FEED_EXPIRE_AFTER_DAYS` | `21` by default; `0` disables the policy; max `36500` |

**`feed.expire_after_days: 0` is the opt-out.** Deliberately on by default (unlike every
retention key in [Retention](retention.md)): a security fix nobody can discover is a fix nobody
applies. Set it to `0` to keep every enrolled device's address indefinitely, the same posture
DIYDDNS had before this policy existed.

Each address family (IPv4, IPv6) is tracked on its own clock: a device that keeps reporting IPv4
but stops asserting IPv6 loses only IPv6 on schedule and keeps IPv4 indefinitely. Before an
address is cleared, its owner is warned by email at four points along the window (roughly the
1/3, 2/3, 17/21 and 20/21 marks); every enabled admin receives a digest of each sweep's late-stage
warnings (the last two rungs) and removals — there is no opt-in or opt-out for admins, and the
first two rungs are owner-only. **Email notifications require [`email.enabled`](email.md)
— with it off, owners receive no warning before removal,** though the server logs a startup
warning saying so. A cleared address is not a ban: the device simply re-enters the feed on its
next successful check-in, with no separate readmission step.

**Disabling a device is not the same as expiry, even though both can leave a device out of the
feed.** Disabling a device leaves its stored `current_ipv4`/`current_ipv6` intact — which is why
re-enabling it restores the address immediately, with no check-in required. Expiry, by contrast,
really does clear the column; a device whose address expired needs a fresh check-in to reappear.

**On first enabling this policy against an existing database, any device already silent longer
than the window is expired on the very first sweep, with no warnings** — every rung is already in
the past for it. A deployment carrying long-dead devices will see their addresses cleared and
their owners emailed within the hour of the next hourly sweep.

---
[← Back to README](../README.md)
