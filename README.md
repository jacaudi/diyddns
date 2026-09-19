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

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
  - [Server](#server)
  - [Client](#client)
- [How It Works](#how-it-works)
- [Development](#development)
- [Documentation](#documentation)
- [Credits](#credits)
- [License](#license)

---

## What It Does

- **Tracks public IPs across devices and users.**

  Each enrolled device periodically reports its address; the server keeps
  full history per device, browsable per user and, for admins, across
  everyone.

- **Passkey-first auth.**

  Sign-in, invites, first-run bootstrap, and account recovery are all
  WebAuthn passkey ceremonies — no passwords to leak or reuse. OIDC login is
  also supported for deployments with an existing IdP.

- **A server-rendered web UI.**

  Plain Go `html/template`, no Node, no bundler, no client-side framework —
  devices, history, an admin console (users, audit log, server info), and
  enrollment-code minting.

- **Email delivery for invite, recovery, and address-change links** *(optional)*

  Off by default — a link is always shown on screen regardless. Turn it on
  and the same link is also emailed, sent through
  [Apprise](https://github.com/unraid/apprise-go) over SMTP. See
  [Email](docs/email.md).

- **A gateway feed** *(optional)*

  The current address set as a pollable REST document (plain text or JSON)
  or a live WebSocket stream, for firewalls, WAFs, and Kubernetes gateways
  to consume as an allow-list.

- **Outbound webhooks** *(optional)*

  A signed, retried HTTP notification whenever a device's address changes,
  joins, or leaves the feed. Generic — not tied to any particular DNS or
  firewall vendor.

- **Feed expiry.**

  An address that stops confirming itself ages out of the feed on a
  configurable window, with owner warnings before it happens.

- **OpenTelemetry export** *(optional)*

  Traces, metrics and logs over OTLP to any collector that speaks the
  protocol.

---

## Quick Start

This is a real, TLS-terminated deployment, not a toy — the only thing missing
is your domain. Passkeys require HTTPS on the exact hostname you browse to,
so there's no lighter-weight path that actually works past `localhost`.

### Server

```yaml
# compose.yaml
services:
  diyddns:
    image: ghcr.io/jacaudi/diyddns/server:v0.4.0
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:size=16m
    security_opt:
      - no-new-privileges:true
    environment:
      DIYDDNS_DATABASE_PATH: /data/diyddns.db
      DIYDDNS_SERVER_BASE_URL: https://ddns.example.com
    env_file: .env   # DIYDDNS_AUTH_HMAC_SECRET_KEY, kept out of git
    volumes:
      - diyddns-data:/data
    labels:
      - traefik.enable=true
      - traefik.http.routers.diyddns.rule=Host(`ddns.example.com`)
      - traefik.http.routers.diyddns.entrypoints=websecure
      - traefik.http.routers.diyddns.tls.certresolver=letsencrypt
      - traefik.http.services.diyddns.loadbalancer.server.port=8080

  traefik:
    image: traefik:v3
    restart: unless-stopped
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --entrypoints.web.http.redirections.entrypoint.scheme=https
      - --certificatesresolvers.letsencrypt.acme.email=you@example.com
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-certs:/letsencrypt
    depends_on:
      - diyddns

volumes:
  diyddns-data:
  traefik-certs:
```

```
# .env — not committed
DIYDDNS_AUTH_HMAC_SECRET_KEY=<output of: head -c 32 /dev/urandom | base64>
```

1. Point `ddns.example.com` (a real domain you control) at this host's public
   IP, and set `--certificatesresolvers.letsencrypt.acme.email` to an address
   you actually read.

2. `docker compose up -d` — Traefik requests and renews the certificate
   automatically via the HTTP-01 challenge on port 80; no manual step.

3. `docker compose logs diyddns | grep BOOTSTRAP_TOKEN` — the startup log
   prints it once. Copy it.

4. Open `https://ddns.example.com/register`, enter the token **and an admin
   email** — the email is what selects first-run setup over an invite
   redeem — then register a passkey. This signs you in.

5. Mint an enrollment code at `/devices/new`.

> Prefer Caddy to Traefik, or need Kubernetes? See
> [Deployment](docs/deployment.md) for the equivalent stacks.

### Client

```sh
docker run --rm -v diyddns-client:/home/nonroot/.config \
  ghcr.io/jacaudi/diyddns/client:v0.4.0 enroll --code <code> --server https://ddns.example.com
```

That one command spends the enrollment code, stores credentials in the named
volume, and starts the client's check-in loop — it's now reporting its
address on its own schedule, no further setup.

Because the server above has a real, publicly reachable hostname, the client
container talks to it like any other host on the internet. None of Docker's
`localhost`-inside-a-container caveats apply here — they do for the
bare-minimum example in [Deployment](docs/deployment.md), which skips Traefik
entirely.

> `task test:e2e` drives the whole server+client flow end to end, including
> the WebAuthn ceremony, with a virtual authenticator, so you can see the
> happy path run without a real browser.

Building and running the binaries directly instead of containers? See
[Deployment](docs/deployment.md).

---

## How It Works

![Architecture: a diyddns client on a Raspberry Pi 5 at a friend's house checks in over the public internet to a diyddns server running in a Kubernetes cluster in someone's garage. The server writes to a single SQLite file, which fans out to the Web UI, Webhooks, the Feed, and an hourly stale-address sweep.](docs/images/architecture.svg)

*A fairly typical deployment: the client has no idea where the server lives,
only its URL and its own device secret. The server has no idea who's asking
except what that check-in proves.*

One binary per role, one SQLite file as the source of truth — nothing here
requires an external database, queue, or cache.

- **The client** does one job.

  Ask a quorum of independent IP-discovery providers what your address is,
  and check in with the server over an HMAC-signed request whenever it
  changes (or periodically, to prove it's still alive). It carries no
  credentials beyond its own device secret and makes no other decisions.

- **The server** is a single process.

  It receives check-ins, writes them to SQLite (the device's current address
  plus an append-only `ip_history`), and fans out from there. Every other
  feature reads that same store; nothing is cached or duplicated elsewhere.

- **The web UI** is what a human uses.

  Sign in with a passkey (or OIDC), browse your devices and their history,
  and — if you're an admin — manage users, review the audit log, and see
  server info. No JavaScript framework; it's server-rendered `html/template`.

- **Webhooks and the feed** are the two ways a *machine* consumes the same
  data.

  Webhooks push a signed event on every change; the feed serves it as a
  pollable document or a live stream. Both are optional and off by default.
  See [Notifications](docs/notifications.md) and [Feed](docs/feed.md).

- **The stale sweep** runs hourly.

  It clears an address nobody has confirmed in a configurable window — the
  mechanism that keeps a deny-by-default gateway from trusting a residential
  IP long after its lease expired. See [Feed Expiry](docs/feed.md#feed-expiry).

---

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

---

## Documentation

**Configuration** — each optional subsystem is off by default (except feed
expiry) and documented on its own. Every key also has a `DIYDDNS_`-prefixed
environment variable; the full annotated set lives in
[`config.example.yaml`](config.example.yaml).

| Doc | Default | Covers |
|---|---|---|
| [Deployment](docs/deployment.md) | — | Containers, production Docker/Compose/Kubernetes, client credential volumes |
| [Email](docs/email.md) | off | Invite/recovery/address-change link delivery, via Apprise over SMTP |
| [Notifications](docs/notifications.md) | off | Signed outbound webhooks, payload contract, verification |
| [Feed](docs/feed.md) | off | REST/WebSocket gateway allow-list |
| [Feed Expiry](docs/feed.md#feed-expiry) | **on**, 21 days | Ages out unconfirmed addresses |
| [Retention](docs/retention.md) | off | Pruning `ip_history` and `audit_log` |
| [Observability](docs/observability.md) | off | Request IDs and OpenTelemetry (OTLP) export |

**Project**

- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

---

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

---

## License

[MIT](LICENSE) © 2026 jacaudi
