# API keys

An API key is a bearer credential for scripting against `/api/v1` — the programmatic
equivalent of a browser session, without a browser. Mint one from `/account`.

## What a key can do

A key is capped to your own account's non-admin operations, regardless of your role when you
minted it — even an admin's key cannot reach `/api/v1/admin/*`. Concretely, a key can:

- Read its own identity: `GET /api/v1/auth/me`
- Manage your own devices: mint an enrollment code, list, get, rename, enable/disable, delete,
  rotate a device's secret, and read its IP history

A key **cannot**:

- Register or remove a passkey, or manage other API keys — these mint or revoke credentials,
  and are reachable only with a live browser session, never a key, so a leaked key can never be
  used to add a new way into the account or lock you out of your existing ones.
- Change your account's email address, for the same reason (a re-pointed email can be used to
  redirect account recovery).
- Log out — a key has no session to end; end its own lifecycle instead with
  `DELETE /api/v1/account/keys/{id}`.

**A visible quirk worth knowing:** `GET /api/v1/auth/me` reports your *capped* role when called
with a key. If you're an admin and you call `/auth/me` with your API key, it reports
`"role":"user"`, not `"role":"admin"` — that's correct, not a bug: the key genuinely cannot act
as an admin, so it reports the role it actually has for this request. The same response also
returns `"csrf":""` for a key-authenticated call, since a key has no session to carry a CSRF
token in the first place — also correct, not a bug.

## Minting, using, and revoking a key

Mint one from the **API Keys** section on `/account`, or over REST:

```
POST   /api/v1/account/keys           mint — {"label": "my-script"}
GET    /api/v1/account/keys           list your own keys
DELETE /api/v1/account/keys/{id}      revoke one
```

The mint response includes the key's plaintext secret **exactly once** — copy it immediately;
it is never shown again and cannot be recovered, only replaced by minting a new one. Use it as
a bearer token:

```
curl -H "Authorization: Bearer dak_..." https://your-server/api/v1/devices
```

A key needs no CSRF token — it authenticates via a header a browser cannot forge into a
cross-site request, the same reasoning the [gateway feed's bearer token](feed.md) already relies
on.

Minting, listing, and revoking keys all require a live browser session — a key can never manage
API keys, including itself, the same way the feed's bearer token can't manage feed tokens.

## Admin-scoped keys

Not yet available. Every key today is capped to non-admin operations regardless of who mints
it. Tracked in [#167](https://github.com/jacaudi/diyddns/issues/167).

---
[← Back to README](../README.md)
