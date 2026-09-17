# DIYDDNS

A self-hosted, multi-user public-IP tracker. The client agent discovers its own
public IP from a quorum of independent lookup providers and reports it to a
central server, which stores per-device IP history in SQLite and exposes both
a JSON API and a server-rendered web UI.

DIYDDNS is **not** an authoritative DNS server and does not push records to
third-party DNS providers. It is an IP registry: clients check in, the server
records, users browse history. It can also tell you when something changed —
an optional, generic outbound webhook, not a DNS publisher.

> [!WARNING]
> **Agentically generated.** This codebase was produced through agentic,
> spec-driven development: each feature began as a written design and
> implementation spec, then a coding agent executed the plan under human
> review. Tests, code review, and CI gates apply as they would for any
> project, but the authorship pattern is not a single human contributor —
> keep that in mind when evaluating fit for your environment.

**Status:** early development. Design specs and implementation plans are
working documents kept in [`docs/`](docs/).

## Table of contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
  - [Server](#server)
  - [Client](#client)
- [How it works](#how-it-works)
- [Configuration at a glance](#configuration-at-a-glance)
- [Development](#development)
- [Documentation](#documentation)
- [Credits](#credits)
- [License](#license)

## What it does

- **Tracks public IPs across devices and users.** Each enrolled device
  periodically reports its address; the server keeps full history per device,
  browsable per user and, for admins, across everyone.
- **Passkey-first auth.** Sign-in, invites, first-run bootstrap, and account
  recovery are all WebAuthn passkey ceremonies — no passwords to leak or
  reuse. OIDC login is also supported for deployments with an existing IdP.
- **A server-rendered web UI.** Plain Go `html/template`, no Node, no
  bundler, no client-side framework — devices, history, an admin console
  (users, audit log, server info), and enrollment-code minting.
- **A gateway feed** (optional) — the current address set as a pollable REST
  document (plain text or JSON) or a live WebSocket stream, for firewalls,
  WAFs, and Kubernetes gateways to consume as an allow-list.
- **Outbound webhooks** (optional) — a signed, retried HTTP notification
  whenever a device's address changes, joins, or leaves the feed. Generic —
  not tied to any particular DNS or firewall vendor.
- **Feed expiry** — an address that stops confirming itself ages out of the
  feed on a configurable window, with owner warnings before it happens.
- **OpenTelemetry export** (optional) — traces, metrics and logs over OTLP to
  any collector that speaks the protocol.

## Quick start

### Server

1. `task build`
2. Copy `config.example.yaml` to `config.yaml` and generate an HMAC key:
   `head -c 32 /dev/urandom | base64`. Also set `database.path` to a writable
   local path such as `./diyddns.db` — the shipped example value is a
   production default, and the server does not create its parent directory.
3. `./bin/diyddns-server serve --config config.yaml`
4. The startup log prints `BOOTSTRAP_TOKEN=…` once. Copy it.
5. Open `/register`, enter the token **and an admin email** — the email is what
   selects first-run setup over an invite redeem — then register a passkey.
   This signs you in.
6. Mint an enrollment code at `/devices/new`.

Passkeys require a **secure context**: browse to `localhost`, or terminate TLS
in front of the server. A plain-HTTP LAN address will not work, and neither
will an IP address — `server.base_url` must be a hostname, because an IP is
not a valid WebAuthn Relying Party ID and the server refuses to start with one.

### Client

```sh
./bin/diyddns-client enroll --code <code> --server <url>
```

That one command spends the enrollment code, stores credentials, and starts
the client's check-in loop — it's now reporting its address on its own
schedule, no further setup. `task test:e2e` drives the whole server+client
flow end to end, including the WebAuthn ceremony, with a virtual
authenticator, so you can see the happy path run without a real browser.

Running in containers, or want a hardened production deployment (Docker
Compose with TLS, or Kubernetes)? See [Deployment](docs/deployment.md).

## How it works

```
diyddns-client ──HMAC-signed checkin──▶ diyddns-server
 (IP discovery quorum,                          │
  3 independent providers)                      ▼
                                    SQLite (devices, ip_history,
                                          audit_log)
                                                 │
                    ┌───────────────┬────────────┼────────────────┐
                    ▼               ▼            ▼                ▼
                 Web UI         Webhooks        Feed          Stale sweep
              (passkey/OIDC   (signed HTTP,  (REST poll +   (expire unconfirmed
                 sessions)     per event)     WS stream)     addresses + warn)
```

One binary per role, one SQLite file as the source of truth — nothing here
requires an external database, queue, or cache.

- **The client** does one job: ask a quorum of independent IP-discovery
  providers what your address is, and check in with the server over an
  HMAC-signed request whenever it changes (or periodically, to prove it's
  still alive). It carries no credentials beyond its own device secret and
  makes no other decisions.
- **The server** is a single process that receives check-ins, writes them to
  SQLite (the device's current address plus an append-only `ip_history`), and
  fans out from there. Every other feature reads that same store; nothing is
  cached or duplicated elsewhere.
- **The web UI** is what a human uses: sign in with a passkey (or OIDC),
  browse your devices and their history, and — if you're an admin — manage
  users, review the audit log, and see server info. No JavaScript framework;
  it's server-rendered `html/template`.
- **Webhooks and the feed** are the two ways a *machine* consumes the same
  data: webhooks push a signed event on every change, the feed serves it as a
  pollable document or a live stream. Both are optional and off by default.
  See [Notifications](docs/notifications.md) and [Feed](docs/feed.md).
- **The stale sweep** runs hourly and clears an address nobody has confirmed
  in a configurable window — the mechanism that keeps a deny-by-default
  gateway from trusting a residential IP long after its lease expired. See
  [Feed expiry](docs/feed.md#feed-expiry).

## Configuration at a glance

Everything below is off by default except feed expiry; every key also has a
`DIYDDNS_`-prefixed environment variable. Full detail — including which keys
are required together, and what refuses to start versus merely degrades — is
one click away in each doc.

| Subsystem | Default | Doc |
|---|---|---|
| Email (SMTP delivery of invite/recovery links) | off | [docs/email.md](docs/email.md) |
| Notifications (signed outbound webhooks) | off | [docs/notifications.md](docs/notifications.md) |
| Feed (REST + WebSocket gateway allow-list) | off | [docs/feed.md](docs/feed.md) |
| Feed expiry (age out unconfirmed addresses) | **on**, 21 days | [docs/feed.md#feed-expiry](docs/feed.md#feed-expiry) |
| Retention (prune `ip_history` / `audit_log`) | off (keep forever) | [docs/retention.md](docs/retention.md) |
| Observability (OTLP traces/metrics/logs) | off | [docs/observability.md](docs/observability.md) |

The full annotated key set, with every default and env var, lives in
[`config.example.yaml`](config.example.yaml).

## Development

Requires Go 1.27+.

| Command | Does |
|---|---|
| `task build` | Build both binaries into `./bin/` |
| `task test` | Unit tests, race detector on |
| `task test:e2e` | Full server+client flow, including the WebAuthn ceremony |
| `task lint` | `golangci-lint`, plus the webui's own HTML/CSS checks |

See [Contributing](CONTRIBUTING.md) for the rest of the workflow — branch
naming, commit conventions, and what CI runs on a PR.

## Documentation

**Configuration** — each optional subsystem is off by default and documented on its own:

- [Deployment](docs/deployment.md) — containers, production Docker/Compose/Kubernetes, client credential volumes
- [Email](docs/email.md) — SMTP delivery for invite/recovery links
- [Notifications](docs/notifications.md) — signed outbound webhooks, payload contract, verification
- [Feed](docs/feed.md) — the REST/WebSocket gateway feed, and its expiry policy
- [Retention](docs/retention.md) — pruning `ip_history` and `audit_log`
- [Observability](docs/observability.md) — request IDs and OpenTelemetry (OTLP) export

**Project**

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## Credits

Built on the Go standard library (`net/http`, `html/template`) — deliberately;
the web UI has no build step because there's nothing to build. On top of that:

- [go-webauthn](https://github.com/go-webauthn/webauthn) for passkeys and
  [go-oidc](https://github.com/coreos/go-oidc) for OIDC — the whole reason
  there's no password table.
- [huma](https://github.com/danielgtaylor/huma) for the JSON API and its
  generated OpenAPI schema.
- [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) — a pure-Go SQLite
  driver, so the server binary is `CGO_ENABLED=0` and links statically into
  the distroless image with no libc.
- [goose](https://github.com/pressly/goose) for schema migrations and
  [coder/websocket](https://github.com/coder/websocket) for the feed stream.
- The [OpenTelemetry Go SDK](https://github.com/open-telemetry/opentelemetry-go)
  for the optional OTLP export.

## License

[MIT](LICENSE) © 2026 jacaudi
