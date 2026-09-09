# DIYDDNS

A self-hosted, multi-user public-IP tracker. The client agent discovers its
own public IP from a quorum of independent lookup providers and reports the
result to a central server, which stores per-device IP history in SQLite and
exposes both a JSON API and a server-rendered web UI.

The web UI is plain Go: `html/template` pages served by the standard library,
no Node, no bundler, and no client-side framework. `/login` and `/register`
handle passkey sign-in and the passkey-based first-run/invite/recovery
ceremonies; `GET /` redirects to `/devices` or `/login` depending on session
state. Signed-in screens are `/account`, the devices list and its "new
enrollment code" form, a device's detail and history pages, and — for
admins — the users list with invite/edit/recovery, the audit log, and a
read-only server-info page.

DIYDDNS is **not** an authoritative DNS server and does not push records to
third-party DNS providers. It is an IP registry: clients check in, the server
records, users browse history. It can also tell you when something
changed — an optional, generic outbound webhook, not a DNS publisher.

## Status

Early development. The design spec and implementation plans are working
documents kept outside this repository.

## Quickstart

1. `task build`
2. Copy `config.example.yaml` to `config.yaml` and generate an HMAC key:
   `head -c 32 /dev/urandom | base64`. Also set `database.path` to a writable
   local path such as `./diyddns.db` — the shipped example value is a
   production default, and the server does not create its parent directory.
3. `./bin/diyddns-server serve --config config.yaml`
4. The startup log prints `BOOTSTRAP_TOKEN=…` once. Copy it.
5. Open `/register`, enter the token **and an admin email** — the email is what
   selects first-run setup over an invite redeem — then register a passkey. This
   signs you in.
6. Mint an enrollment code at `/devices/new`.
7. `./bin/diyddns-client enroll --code <code> --server <url>`

Passkeys require a **secure context**: browse to `localhost`, or terminate TLS in
front of the server. A plain-HTTP LAN address will not work, and neither will an
IP address — `server.base_url` must be a hostname, because an IP is not a valid
WebAuthn Relying Party ID and the server refuses to start with one.

`task test:e2e` drives this whole flow end to end, including the WebAuthn
ceremony, with a virtual authenticator.

### Containers

    docker run -d --name diyddns \
      -p 8080:8080 -v diyddns-data:/data \
      -e DIYDDNS_DATABASE_PATH=/data/diyddns.db \
      -e DIYDDNS_SERVER_BASE_URL=http://localhost:8080 \
      -e DIYDDNS_AUTH_HMAC_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" \
      ghcr.io/jacaudi/diyddns/server:v0.1.0

The client stores its credentials under `$HOME/.config`, which is not persisted
in a container unless you mount it — use a volume, or pass `--credentials-file`:

    docker run --rm -v diyddns-client:/home/nonroot/.config \
      ghcr.io/jacaudi/diyddns/client:v0.1.0 enroll --code <code> --server <url>

`<url>` must be reachable **from inside the client container**, which rules out
the `http://localhost:8080` the server block above uses: inside the container
`localhost` is the container itself, so enroll fails with `dial tcp
[::1]:8080: connect: connection refused` even though that is the server's own
`base_url`. On Docker Desktop use `http://host.docker.internal:8080`. On Linux,
either put both containers on one user-defined network and use the server's
container name, or run the client with
`--add-host=host.docker.internal:host-gateway`. The web UI already does this
rewrite for you: when the server's base URL has a loopback host (localhost,
127.0.0.1, ::1), the container command it shows uses host.docker.internal.

If enroll fails, read the message before retrying. `credentials already exist`
means this host is already enrolled and your code is **not** spent — reuse it
elsewhere, or, if you replaced that device, `docker rm -f diyddns-client-run &&
docker volume rm diyddns-client` and run the same command again. `credentials:
... permission denied` means the volume has the wrong owner — this is the
client's own message; `docker: permission denied ... docker daemon socket` is
a different problem and means your user is not in the `docker` group. For the
client's message, the code may or may not have been spent, because it is
emitted both before and after the code is sent — check `/devices` first: if
the device you just named is listed the code was spent and you need a fresh
one; if it is absent the code is still good, so clear the volume with the two
commands above and run the same command again. Any other message also leaves
the code's status unclear, because the server records the device before the
client stores anything — check `/devices` the same way: if the device you
just named is listed the code was spent and you need a fresh one; if it is
absent the code is still good, so fix what the message reports and run the
same command again, without removing the volume.

## Configuration

Every setting has a `DIYDDNS_`-prefixed environment variable; see
[`config.example.yaml`](./config.example.yaml) for the full annotated set.

### Email (optional, off by default)

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

### Notifications (optional, off by default)

DIYDDNS can deliver a signed webhook to endpoints an **admin** configures whenever a device
joins the feed, leaves it, or changes its public IP, plus an on-demand `endpoint.test` probe for
checking an endpoint before you trust it. This is a generic outbound notifier — it is not a DNS
publisher, and it does not replace an authoritative DNS record (see the identity paragraph above).

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

#### The payload

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
mirror image.

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
its last-known IPv6 address in both `current.ipv6` and `previous.ipv6`, unchanged, on every future
event; the presence of a non-null `current.ipv6` does **not** mean IPv6 just changed. Trust
`changed`, never field presence, for "what happened."

An address family that has never been reported is JSON **`null`**, never `""`. Do not treat the
two as equivalent: `null` means "this device has no IPv6 (or IPv4) on record," while `""` would
be indistinguishable from "the address was explicitly cleared." Collapsing them loses that
distinction anywhere you store or diff the value.

#### Dedupe on `(type, id)`, not `id` alone

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

#### Verifying a delivery

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

#### `410 Gone` ends that delivery

Respond `410 Gone` and that **one delivery** stops immediately — no further retries for it,
regardless of attempts remaining. It does **not** disable the endpoint: the next event (a new IP
change, or another manual test) is still delivered to it. There is no consumer-side way to opt an
endpoint out of future deliveries in this version; only an admin can disable or delete the
endpoint. Every other non-2xx response (or no response at all — timeout, connection refused, TLS
failure) is retried with doubling backoff up to `notifications.max_attempts`.

#### Egress policy (operator-only)

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

#### Trusting an internal CA

If a notification endpoint sits behind a certificate from an internal/private CA, set
`SSL_CERT_FILE` (a PEM bundle) or `SSL_CERT_DIR` in the server's environment so the outbound
HTTPS client trusts it. **This works on Linux — the shipped container image — but not on
macOS**: Go's certificate verifier on Darwin uses the OS's own Security framework instead of these
variables, so a self-built macOS binary needs the CA installed in the system keychain instead.

#### What an admin sees on failure

A failed delivery's cause is reported on the endpoint's page as exactly one of six fixed classes:
`blocked`, `unreachable`, `tls`, `rejected`, `gone` ("Target removed (410)"), `internal`. The
resolved address and raw error go to the server log and, for a policy rejection, the audit log.

#### A webhook-only consumer cannot detect a lost event

Delivery is retried until it succeeds or gives up, but the *enqueue* is best-effort: if the
database write that queues an event fails, that event is never sent and there is no later
signal that it was lost. A consumer that must never drift should also poll the feed below, which
reads the current state directly.

### Feed (optional, off by default)

The feed is how a firewall, WAF, Envoy Gateway or other Kubernetes gateway consumes the current
device addresses: a bearer-token REST snapshot to poll, and a WebSocket stream for live changes.
It lists **every enabled device of every enabled user** that has an address.

| Key | Env var | Notes |
|---|---|---|
| `feed.enabled` | `DIYDDNS_FEED_ENABLED` | `false` by default; when off, none of the routes below nor `/admin/feed` exists |

#### Tokens

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

#### `GET /feed/v1/devices.txt`

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

#### `GET /feed/v1/devices.json`

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

#### Validators

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

#### `GET /feed/v1/stream` (WebSocket)

Connect with the same header. The first frame is a snapshot — the JSON document above wrapped
as `{"version":1,"type":"feed.snapshot","feed":{…}}` — then one frame per event, byte-identical
to the webhook payload (`device.ip_changed`, `device.added`, `device.removed`). Initialise each
device's allowed set from the snapshot's `ipv4`/`ipv6`, then apply deltas with the rule above.

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

#### Kubernetes glue

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" https://ddns.example.com/feed/v1/devices.json \
  | jq '{spec:{authorization:{rules:[{action:"Allow",principal:{clientCIDRs:.cidrs}}]}}}' \
  | kubectl patch securitypolicy allow-home --type merge -p "$(cat)"
```

### Retention (optional, off by default)

DIYDDNS records an `ip_history` row every time a device's public IP changes, and
an `audit_log` row for every security-relevant action. Both tables grow without
bound unless you set a retention policy.

Retention is **disabled by default**, and that is a supported way to run: a
household deployment can keep everything forever and never think about it.
Nothing is deleted from `ip_history` or `audit_log` by this policy until you
set one of these keys.

> **Note:** separately and unconditionally, DIYDDNS also deletes expired
> single-use tokens — `account_recovery_tokens` and `enrollment_codes` — once
> they expire, whether or not they were used, starting on the first hourly
> sweep after upgrade. This is **not** gated by the retention keys below. The
> audit trail is unaffected (`device.enroll.code` and
> `passkey.recovery_issued` events survive); what is lost is the token rows
> themselves, including `enrollment_codes.device_id`.

| Key | Env var | Notes |
|---|---|---|
| `retention.ip_history_days` | `DIYDDNS_RETENTION_IP_HISTORY_DAYS` | `0` (keep forever) by default; max `36500` |
| `retention.ip_history_per_device_max` | `DIYDDNS_RETENTION_IP_HISTORY_PER_DEVICE_MAX` | `0` (unlimited) by default; max `36500` |
| `retention.audit_log_days` | `DIYDDNS_RETENTION_AUDIT_LOG_DAYS` | `0` (keep forever) by default; max `36500` |
| `retention.notification_deliveries_days` | `DIYDDNS_RETENTION_NOTIFICATION_DELIVERIES_DAYS` | `0` (keep forever) by default; max `36500` |

The two `ip_history` keys combine: a row is removed if it falls outside *either*
window. **The most recent row for each device is always kept**, whatever you
set, so a device never loses its current IP.

`notification_deliveries_days` trims the delivery history shown on an endpoint's
page. **Only completed deliveries are eligible** — a delivery still waiting to
be sent or retried is never removed, however old it is, because deleting one
would silently drop work with nothing left to retry it. Enable this if you use
notifications: without it the table grows with every IP change, for every
endpoint.

**Deletion is permanent and there is no undo.** When you first enable a key, the
next sweep removes everything already outside the window — on an aged database
that can be a lot of rows. The server logs a warning at startup naming the
values in effect, records a `retention.prune` audit entry for every sweep that
deleted something, and waits a full hour after boot before its first sweep, so
there is time to notice a mistake and revert it.

The sweep runs hourly and is not configurable: retention windows are measured in
days, so an hourly sweep is already far finer than any policy you can express.

If you enable either `ip_history` retention key, consider also setting
`audit_log_days`. Every sweep that deletes something writes one
`retention.prune` audit row, and only `audit_log_days` cleans those up —
leaving it at `0` while pruning `ip_history` trades unbounded `ip_history`
growth for slow, permanent growth in `audit_log` instead.

Retention stops the database file from growing, but it does not shrink it:
SQLite reuses freed pages internally rather than returning them to the
filesystem. To reclaim the disk space after a large prune, stop the server and
run a manual `VACUUM` on the database file.

### Observability

Every log record emitted while serving a request carries a `request_id`, and the
same id is returned in the response header so a client can quote it in a bug
report. DIYDDNS honours an incoming id, which lets its logs join a reverse
proxy's for the same request.

| Key | Env var | Notes |
|---|---|---|
| `observability.request_id_header` | `DIYDDNS_OBSERVABILITY_REQUEST_ID_HEADER` | `X-Request-Id` by default. Set it to whatever your proxy stamps |

An inbound value is honoured only if it is at most 128 bytes of printable ASCII;
anything else is discarded and a fresh UUIDv7 is minted, so an untrusted client
cannot write unbounded data into the log.

The id is nonetheless **client-supplied and untrusted** unless a proxy you
control overwrites the header on the way in: any unauthenticated caller can send
every request under one id, or under an id it saw in someone else's bug report.
Treat it as a correlation aid, never as attribution.

Two kinds of header name are refused at startup: ones the server itself writes
(`Content-Length`, `Content-Type`, `Location`, ...), and ones that carry a
credential (`Cookie`, `Authorization`, `X-CSRF-Token`, the agent's
`X-Diyddns-*` signing headers) — the configured header's value is copied into
`request_id` on every record, so pointing it at `Cookie` would publish the
session cookie to the log.

## Documentation

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE) © 2026 jacaudi
