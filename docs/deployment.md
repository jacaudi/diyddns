# Deployment

## Containers

    docker run -d --name diyddns \
      -p 8080:8080 -v diyddns-data:/data \
      -e DIYDDNS_DATABASE_PATH=/data/diyddns.db \
      -e DIYDDNS_SERVER_BASE_URL=http://localhost:8080 \
      -e DIYDDNS_AUTH_HMAC_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" \
      ghcr.io/jacaudi/diyddns/server:v0.4.0

The client stores its credentials under `$HOME/.config`, which is not persisted
in a container unless you mount it — use a volume, or pass `--credentials-file`:

    docker run --rm -v diyddns-client:/home/nonroot/.config \
      ghcr.io/jacaudi/diyddns/client:v0.4.0 enroll --code <code> --server <url>

The client rewrites `credentials.json` during [credential rotation](#credential-rotation)
by writing a new file and renaming it over the old one, so the file's
**directory** must be writable. A single-file bind mount of `credentials.json`
cannot be replaced that way and fails rotation with `secret rotation: cannot
save credentials`. Mount the directory (or a volume) instead.

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

## Building From Source (Advanced)

Skip this if you're using the containers above — it's for running the
binaries directly, with no Docker.

### Server

1. `task build`
2. Copy `config.example.yaml` to `config.yaml` and generate an HMAC key:
   `head -c 32 /dev/urandom | base64`. Also set `database.path` to a writable
   local path such as `./diyddns.db` — the shipped example value is a
   production default, and the server does not create its parent directory.
3. `./bin/diyddns-server serve --config config.yaml`
4. The startup log prints `BOOTSTRAP_TOKEN=…` once. Copy it.
5. Open `/register`, enter the token and the admin's email, then register a
   passkey. This signs you in.
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

## Production Deployment

The server holds a **single** SQLite connection and writes only to the database
file — it must never run as more than one instance against the same file, and
its main listener speaks **plain HTTP only** (the optional
[agent mTLS](#agent-mtls-optional) listener is the one TLS listener). Every
example below reflects both constraints: exactly one replica, and TLS terminated in front of it.

### Docker

```bash
docker run -d --name diyddns \
  --restart unless-stopped \
  --read-only --tmpfs /tmp:size=16m \
  --security-opt no-new-privileges \
  --memory 256m --cpus 0.5 \
  -p 8080:8080 -v diyddns-data:/data \
  -e DIYDDNS_DATABASE_PATH=/data/diyddns.db \
  -e DIYDDNS_SERVER_BASE_URL=https://ddns.example.com \
  -e DIYDDNS_AUTH_HMAC_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" \
  ghcr.io/jacaudi/diyddns/server:v0.4.0
```

- **`--read-only` is safe.** The only path the process writes is `/data` (the
  mounted volume). `--tmpfs /tmp` is defensive headroom, not something the
  code currently requires.
- **No in-image `HEALTHCHECK`.** The runtime image is
  `gcr.io/distroless/static-debian12:nonroot` and has no shell — a
  `HEALTHCHECK`/Compose `healthcheck:` directive execs a command *inside* the
  container, which distroless cannot run. `/healthz` and `/readyz` exist for
  an external checker or an orchestrator's own HTTP-level probe (Kubernetes,
  below, uses them directly).
- **Pin a real tag, not `:latest`.** `vX.Y.Z`, or better a digest
  (`@sha256:…`), so a redeploy is reproducible. `:latest` still exists if you
  want it.
- TLS is terminated by whatever sits in front — see Compose below for a
  worked example.

### Docker Compose

```yaml
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
      DIYDDNS_SERVER_TRUSTED_PROXIES: <the proxy network CIDR>   # the docker network Caddy reaches diyddns on
    env_file: .env   # DIYDDNS_AUTH_HMAC_SECRET_KEY, and anything else kept out of git
    volumes:
      - diyddns-data:/data
    expose:
      - "8080"        # not published directly — caddy terminates TLS in front of it

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    depends_on:
      - diyddns

volumes:
  diyddns-data:
  caddy-data:
```

```
# Caddyfile
ddns.example.com {
    reverse_proxy diyddns:8080
}
```

```
# .env — not committed
DIYDDNS_AUTH_HMAC_SECRET_KEY=<output of: head -c 32 /dev/urandom | base64>
```

Caddy obtains and renews the TLS certificate automatically. Swap in Traefik,
nginx, or whatever reverse proxy you already run — the only requirement is
that it forwards to `diyddns:8080` over plain HTTP and terminates TLS for
everything in front of it. Whichever proxy you pick, set
`DIYDDNS_SERVER_TRUSTED_PROXIES` to the subnet of the docker network it reaches
diyddns on (`docker network inspect <network>`). Without it the server cannot
see past the proxy: it records no address from the check-in, logs a `WARN`, and
clients in `auto` mode fall back to looking their address up. See
[Server-observed IP](#server-observed-ip).

### Kubernetes (bjw-s `app-template`)

One replica, a persistent volume for `/data`, and a Gateway API `HTTPRoute` —
the same kind of gateway the [Feed](feed.md) doc assumes when it mentions Envoy
Gateway. Swap `route:` for a plain `ingress:` block if you run classic Ingress
instead; the chart supports both.

```bash
kubectl create secret generic diyddns-secret \
  --from-literal=DIYDDNS_AUTH_HMAC_SECRET_KEY="$(head -c 32 /dev/urandom | base64)"
```

`values.yaml`:

```yaml
controllers:
  diyddns:
    replicas: 1
    strategy: Recreate   # single SQLite writer: never run two pods at once

    containers:
      app:
        image:
          repository: ghcr.io/jacaudi/diyddns/server
          tag: v0.4.0
        env:
          DIYDDNS_DATABASE_PATH: /data/diyddns.db
          DIYDDNS_SERVER_BASE_URL: https://ddns.example.com
          DIYDDNS_SERVER_TRUSTED_PROXIES: <the Envoy pod CIDRs>   # every IPv4 and IPv6 CIDR Envoy reaches diyddns from
        envFrom:
          - secretRef:
              name: diyddns-secret
        probes:
          liveness:
            enabled: true
            custom: true
            spec:
              httpGet: { path: /healthz, port: 8080 }
              periodSeconds: 30
          readiness:
            enabled: true
            custom: true
            spec:
              httpGet: { path: /readyz, port: 8080 }
              periodSeconds: 10
        resources:
          requests: { cpu: 10m, memory: 64Mi }
          limits: { memory: 256Mi }
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]

defaultPodOptions:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532       # matches the image's distroless nonroot user
    runAsGroup: 65532
    fsGroup: 65532
    fsGroupChangePolicy: OnRootMismatch
    seccompProfile:
      type: RuntimeDefault

persistence:
  data:
    storageClass: ""       # your default StorageClass
    accessMode: ReadWriteOnce
    size: 1Gi
    globalMounts:
      - path: /data

service:
  app:
    controller: diyddns
    ports:
      http:
        port: 8080

route:
  app:
    parentRefs:
      - name: internal        # your Gateway's name
        namespace: network    # and namespace
        sectionName: https
    hostnames:
      - ddns.example.com
    rules:
      - backendRefs:
          - identifier: app
            port: 8080
```

```bash
helm upgrade --install diyddns oci://ghcr.io/bjw-s-labs/helm/app-template \
  --version <pin a current app-template chart version> \
  -f values.yaml --namespace diyddns --create-namespace
```

(Or wrap the same `values.yaml` in a Flux `HelmRelease` — this is exactly the
`spec.values` block either way.)

`replicas: 1` and `strategy: Recreate` are load-bearing, not stylistic
defaults: two pods writing the same SQLite file is a correctness bug, and
`RollingUpdate` briefly runs old and new together to avoid downtime — the one
thing this app cannot tolerate. Passkeys need HTTPS on the exact hostname you
browse to (it must match `server.base_url`); terminate TLS at the
Gateway/Ingress, never on the pod — the main listener only ever speaks
plain HTTP.

## Configuration

Every setting has a `DIYDDNS_`-prefixed environment variable; see
[`config.example.yaml`](../config.example.yaml) for the full annotated set. Optional
subsystems each have their own doc — see the [README's Documentation section](../README.md#documentation).

## Server-observed IP

By default the server takes a device's public IP from the **origin address of
its check-in**: the address the connection came from, or, behind a reverse
proxy you list, the address that proxy saw. The client no longer has to ask
third-party lookup services; it keeps them as a fallback, used automatically
only when the server cannot observe a public address (see
[Client IP discovery](#client-ip-discovery)).

Out of the box this is safe. With `server.trusted_proxies` empty no proxy header
is ever read, and with `agent.proxy_protocol` false the agent listener is not
wrapped. A device whose observed address is not public (a proxy's own address, a
LAN or VPN address, any special-purpose block) records nothing, the check-in
still succeeds, and its client falls back to lookup.

The server only ever records an address that is **public**: not private, not
loopback or link-local, not `100.64.0.0/10`, not zoned, and not in any IANA
special-purpose block or transition prefix (for example `64:ff9b::/96`, `2002::/16`).

### Main port behind a proxy

The main listener speaks plain HTTP behind your TLS terminator, so the peer the
server sees is the proxy. Tell the server which proxies to believe:

| Key | Env | Default |
|---|---|---|
| `server.trusted_proxies` | `DIYDDNS_SERVER_TRUSTED_PROXIES`, comma-separated | `[]` |

Entries are CIDR prefixes or bare IPs (a bare IP is a /32 or /128), trimmed of
whitespace. An entry that does not parse stops startup. A `/0` prefix (it trusts
every peer, so any client could forge its address) and a 4-in-6 prefix such as
`::ffff:10.0.0.0/104` (it never matches; write the IPv4 form) are each logged as
a `WARN` at startup. Peers on a dual-stack listener that arrive as
`::ffff:10.0.0.5` match a plain `10.0.0.0/8` entry.

How the server picks the origin address:

1. A peer **not** in `trusted_proxies`: the peer's own address. Any
   `X-Forwarded-For` it sends is ignored.
2. A peer in `trusted_proxies`: `X-Forwarded-For` is read from right to left
   (every header line, comma-split), skipping entries that are themselves
   trusted. The first untrusted entry that parses is the origin.
3. A malformed entry (including one carrying a port, such as `1.1.1.1:443`), an
   empty header or one made only of trusted entries: **no observation**. The
   trusted proxy's own address is never recorded in its place.

Pick the CIDR of the network the proxy reaches diyddns on: the docker network
in the Compose examples above, or the **Envoy pods' CIDR** on Kubernetes
(usually the whole pod CIDR). Caddy and Traefik both set `X-Forwarded-For` by
default; check yours does.

On a dual-stack cluster, `trusted_proxies` must list **every** CIDR Envoy can
reach diyddns from, both IPv4 and IPv6. A prefix never matches an address of the
other family, so a list with only IPv4 CIDRs makes Envoy, when it arrives over
IPv6, an untrusted peer, and Envoy's own address is recorded as the device's
IPv6 address.

**Kubernetes with Envoy Gateway.** Set
`DIYDDNS_SERVER_TRUSTED_PROXIES` to the pod CIDR in the `env:` block of the
values above. Two things keep `X-Forwarded-For` honest:

- Add a `NetworkPolicy` so only the Envoy pods can reach diyddns on port 8080.
  Any other pod inside `trusted_proxies` could forge the header.
- Leave Envoy's defaults alone. Envoy Gateway appends the real client address
  to `X-Forwarded-For` (`use_remote_address` on). **Never set
  `ClientTrafficPolicy.spec.clientIPDetection.xForwardedFor.disableXForwardedForAppend`**,
  and note that **any** `clientIPDetection` block flips `use_remote_address`
  off, after which Envoy no longer appends the connecting address.

### Agent port

Check-ins on the [agent port](#agent-mtls-optional) arrive over a passthrough
`TLSRoute`, so Envoy cannot add a header; it passes the origin address in a
PROXY protocol v2 header instead. Four things have to line up:

1. `agent.proxy_protocol: true` (`DIYDDNS_AGENT_PROXY_PROTOCOL`, default
   `false`). It is independent of `trusted_proxies` but reads that list.
2. `server.trusted_proxies` covering the Envoy pods, every IPv4 and IPv6 CIDR
   they can connect from (a prefix never matches the other family; see
   [Main port behind a proxy](#main-port-behind-a-proxy)). With
   `agent.proxy_protocol: true`, a peer **inside** the list MUST send the PROXY
   header: one that starts with TLS instead fails on its first read, and one
   that sends nothing times out after go-proxyproto's 10 s header timeout. A
   peer **outside** the list has any PROXY header it sends read and discarded,
   so a device that connects directly cannot claim another address.
3. A passthrough `TLSRoute` for the agent hostname.
4. A `BackendTrafficPolicy` asking Envoy to send PROXY v2 to the backend:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: diyddns-agent
spec:
  parentRefs:
    - name: external          # your Gateway's name
      sectionName: agent-tls  # a TLS listener in Passthrough mode
  hostnames:
    - ddns.example.com
  rules:
    - backendRefs:
        - name: diyddns       # the Service exposing the agent port
          port: 8443
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: diyddns-agent
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: TLSRoute
      name: diyddns-agent
  proxyProtocol:
    version: V2
```

Without the `BackendTrafficPolicy`, Envoy connects without a header, the server
requires one, and the connection fails on its first read. It shows up as TLS
handshake errors from the agent listener, logged at `Info` by the agent
server's `ErrorLog`. If agent check-ins fail and nothing else explains it, look
there first.

### Client IP discovery

`run.ip_discovery` (env `DIYDDNS_RUN_IP_DISCOVERY`) on the client; any other
value refuses to start:

```yaml
# client config.yaml
run:
  ip_discovery: auto   # auto | always | never
```

| Value | What the client does |
|---|---|
| `auto` (default) | Sends each enabled family's check-in with no address, one family at a time (IPv4 first), so the server records what it sees. For a family the server cannot observe (an old server, capabilities not yet fetched, the family's connection could not be made, or the server answered `ip_source: none` for it), the client looks that one family up, reports it, and asks the server again about an hour later. A `WARN` explains the fallback, at most once a day per family. |
| `always` | The previous behaviour: look every family up (quorum of providers), and send one check-in carrying every address. The server records what is reported. |
| `never` | Never contact a lookup service. If the server records no address for a family, the client logs a `WARN` (once a day) to set `run.ip_discovery` to `auto` or `always`. Against a server that does not support observed IPs it logs an `ERROR` once a day: `server does not support observed IPs and run.ip_discovery is never; nothing is being recorded`. |

`run.providers_v4` and `run.providers_v6` still apply: in `auto` only as the
fallback, in `never` not at all (the client warns at startup if you set them).

The check-in response says where each family's address came from:
`ip_source: {"ipv4": "reported|observed|none", "ipv6": ...}`. The server also
advertises `observed_ip: true` in its capabilities; a client that does not see
it assumes an old server and looks up. A server logs one `INFO` line per
check-in with `device_id`, `peer`, `observed`, `ipv4_source` and `ipv6_source`.

Credential rotation adds three more fields to the same exchange. The server
advertises `rotation: true` in its capabilities. A client that sees it sends
`"capabilities": ["rotation"]` in its check-in request (it omits the field
otherwise, because the server rejects unknown request fields with a 422), which
tells the server the device can rotate. The check-in response always carries
`rotation: {"secret": bool, "cert": bool}`, the tracks an admin has asked this
device to rotate; an old client ignores it. See
[Credential rotation](#credential-rotation).

If a client reports an address (`always`, or an `auto` fallback), the
reported address wins and the observed one is ignored. A reported address that
is not public is dropped (never replaced by the observed one), the family's
`ip_source` is `none`, and the server logs a `WARN` (`check-in reported a
non-public address; dropped`) at most once an hour per device and address
family.

### Private paths

The server records only a public address, so a device that reaches it over a
path with no public address records nothing there and, in `auto`, looks it up:

- **Split-horizon DNS**: the LAN resolver answers the proxy's LAN address, so the
  device connects from a private address.
- **Hairpin NAT**: the device reaches its own public address from inside the
  network and arrives from the router's internal address.
- **VPN and Tailscale**: the server sees the VPN or tailnet address (`100.64.0.0/10`
  for Tailscale), which is not public.
- **`HTTPS_PROXY` / `HTTP_PROXY`**: the client honours them, so its connection
  goes to the proxy and the server observes the **proxy's** address. A proxy on a
  private address records nothing and `auto` looks up; a proxy on a public
  address is recorded as the device (see the threat model below).
- **NAT64**: a device on an IPv6-only network reaches an IPv4-only server
  through a translator, so the server sees the translator's address, not the
  device's. The `64:ff9b::/96` prefix itself is never recorded. If the
  translator's address is public the server records it, so such a device
  should use `always`.

In each case the server logs `check-in had no public origin address` (a `WARN`,
at most once an hour per device) with `device_id`, `peer`, `observed` and a
`hint`: `server.trusted_proxies` may not cover your proxy, or the device
reaches the server over a private path (LAN/VPN). Under `never` nothing is
recorded for that family until the path changes or you switch to `auto`.

### IPv6

The server can only observe an IPv6 address when the device reaches it over
IPv6: the server (or its proxy) must be reachable on IPv6 and the hostname must
have an `AAAA` record. A dual-stack device checks in once per family. When the
server is reachable over IPv4 only, the IPv6 connection cannot be made, so the
client skips it and looks its IPv6 address up (in `auto`; `always` always looks
up) and the device still records both families.

### Threat model

Integrity moves. A reported address is covered by the check-in's HMAC
signature; an observed one rests on an **unsigned header** (`X-Forwarded-For`, or the PROXY v2
header) on the hop between your proxy and diyddns. That is why
`trusted_proxies` must list only the proxy, and why a NetworkPolicy (or an
equivalent firewall rule) should stop anything else from reaching diyddns. It is
an acceptable move: a device that holds its secret could always report any
address it liked.

A device behind a public-addressed forward proxy is recorded as that proxy.
That is inherent to observing a connection.

### Scope

- **What `trusted_proxies` covers:** the check-in IP and the IP in audit
  entries (login, logout and the rest of the entries that used to record
  the connection's address). For audit only, when no origin can be determined the
  entry records the connection's own address.
- **Unchanged:** `X-Forwarded-Proto` is still not trusted, so behind a
  TLS-terminating proxy keep `auth.session.cookie_secure` on (the default). The RFC 7239 `Forwarded`
  header is not read; Envoy, Caddy and Traefik emit `X-Forwarded-For`.
- **Not stored:** the IP source is returned in the response and logged, not
  kept in the database. No schema changed.
- **Querying `sessions.ip` and `audit_log.ip`:** these columns now mix two
  forms. Behind a trusted proxy the value is a **bare IP** (`203.0.113.9`);
  otherwise it is the connection's `RemoteAddr`, a **`host:port`**
  (`203.0.113.9:51234`, `[2001:db8::1]:51234`). If you query by IP, match both,
  for example `ip = '203.0.113.9' OR ip LIKE '203.0.113.9:%'`.

### Upgrading

- `auto` is the new default in place of always-lookup. Old clients are
  unaffected: they keep reporting an address, which the server records as
  before (subject to the public-address check below).
- A new client against an old server notices that `observed_ip` is missing and
  falls back to lookup on its own.
- A new client behind a proxy that is not in `trusted_proxies` falls back to
  lookup, and the server logs the `WARN` above naming the fix.
- A dual-stack device now sends up to **two** check-ins per cycle, one per
  family. When both families change in the same cycle that can produce two
  `ip_history` rows and two change notifications.
- A client that reports a private or special-purpose address stops updating
  that family: the server now applies the same public-address check to reported
  addresses and drops the others.
- Addresses are now stored in canonical form. A device whose stored IP was
  written in a non-canonical form gets one extra `ip_history` row and one
  change notification on its first check-in after the upgrade.

## Agent mTLS (optional)

### What it does

By default a device proves itself with an HMAC signature over each request.
Agent mTLS adds a second factor: the server runs a **second, TLS 1.3 listener
for agent traffic** (the agent port), issues each device a client certificate
from its own CA, and checks that certificate in addition to the HMAC
signature. The device pins that CA, so it also knows it is talking to your
server.

It is opt-in and changes nothing until you set `agent.listen`. Enabling the
listener lets devices start using it; setting `agent.require_mtls` later closes
the HMAC-only check-in path on the main port, so a device that has not got a
certificate can no longer report. Capabilities, enrollment and certificate
issuance stay open on the main port, so enrollment and recovery still work
under `require_mtls`.

### Enabling

Server settings (each also has a `DIYDDNS_` variable, for example
`DIYDDNS_AGENT_LISTEN`):

| Key | Default | Meaning |
|---|---|---|
| `agent.listen` | `""` (disabled) | Agent listener address, for example `:8443` |
| `agent.public_url` | none (required when enabled) | `https://host:port`, with no path. The host becomes the serving certificate's SAN. |
| `agent.tls.dir` | directory of `database.path` | Where the CA keys and the serving certificate are kept |
| `agent.require_mtls` | `false` | Close the HMAC-only path on the main listener. Requires `agent.listen`. |

`public_url` must carry an **explicit port**. An IP address is accepted as the
host, but a Gateway API `TLSRoute` needs a DNS name (TLSRoute hostnames cannot
be IPs, and Go sends no SNI for an IP literal), so use a DNS name whenever the
agent port sits behind one.

The server refuses to start when `database.path` is in-memory or when the
recorded CA and the key files disagree. The CA state lives in `agent.tls.dir`
(the `/data` volume in the image), so keep it on the persistent volume.

The serving certificate is valid for as long as the active CA, so nothing
renews it while the server runs. The server checks it only at startup and
re-issues it there when it is missing or unreadable, when the `public_url`
host has changed, or when the active CA has changed (`ca promote-backup`,
`ca reset`).

On first start the server generates two CAs (an active one and a backup) and
logs a `WARN` that names `ca-backup.key`; see
[Agent CA backups](#agent-ca-backups) for what to do with it.

Client setting: `run.insecure_provision` (default `false`), or the
`--insecure-provision` flag on `enroll` and `run`.

**Trust assumption.** A device receives the CA bundle it will pin from the
main port. HMAC signs requests, not responses, so that bundle is only as
trustworthy as the main-port TLS: the operator's TLS terminator in front of
the main port is trusted to deliver the pin. For that reason the client
**refuses to provision over `http://`** unless `--insecure-provision` /
`run.insecure_provision` is set; with it, the client logs a `WARN` on every
provisioning.

**Risk of `--insecure-provision`.** Over `http://` the CA bundle arrives
unauthenticated. Anyone who can modify traffic between the device and the
server at provisioning time can substitute their own CA and later impersonate
the agent port. Provisioning also reopens: a device clock pushed forward makes
the client treat its certificate as expired and provision again, so an
attacker who controls both the network and the device's time source can force
that window open. Use the flag only on a trusted network.

### Kubernetes and Docker

**Kubernetes:** expose the agent port with a **passthrough** `TLSRoute` or a
`LoadBalancer` Service. Never put a terminating proxy in front of it: the
device's client certificate and its pin on the serving certificate both
require the TLS session to end at the server.

**Docker:** publish the agent port next to the main one, for example
`-p 8443:8443`, and set `DIYDDNS_AGENT_LISTEN=:8443` and
`DIYDDNS_AGENT_PUBLIC_URL=https://ddns.example.com:8443`.

### Agent CA backups

- Back up `ca.key` **with the database**. The database holds only the public
  certificates; without `ca.key` the server refuses to start.
- Keep `ca-backup.key` **offline**, separate from both the database and
  `ca.key`. It exists so that losing `ca.key` is recoverable (see
  `ca promote-backup` below), which only works if it does not share a fate
  with `ca.key`.

The server logs a `WARN` on first start, and again on every start while
`ca-backup.key` is still on disk, until you move it. The server image is
distroless: no shell, no `tar`, and it runs as UID 65532. Extract the key with
a helper container. Both procedures use only `cat` and `rm`, so they work
whether or not `tar` exists.

**Kubernetes** (an ephemeral container that shares the pod's process
namespace; `-i` without `-t` so the redirect captures raw bytes). `--target`
is the server container's name, the `containers:` key in the app-template
values above (`app`; `diyddns` is the controller, not the container). Adjust it
if your chart names the container differently:

    kubectl debug <pod> -i --image=busybox:1.37 --target=app --profile=general -- cat /proc/1/root/data/ca-backup.key > ca-backup.key
    openssl pkey -in ca-backup.key -noout
    kubectl debug <pod> -i --image=busybox:1.37 --target=app --profile=general -- rm /proc/1/root/data/ca-backup.key

**Docker:**

    docker run --rm --volumes-from <container> busybox:1.37 cat /data/ca-backup.key > ca-backup.key
    openssl pkey -in ca-backup.key -noout
    docker run --rm --volumes-from <container> busybox:1.37 rm /data/ca-backup.key

`openssl pkey` prints nothing and exits 0 when the file is a valid private
key; confirm that **before** the `rm`, and store the file offline.

### Credential rotation

An admin can ask a device to replace its secret, its certificate, or both. The
device does it on its own at its next check-in; nothing is typed into the
device. Secret rotation works with or without the agent port. Certificate
rotation needs `agent.listen`.

The new secret never travels in a response. The client generates it and sends it
to the server inside a request signed with the **old** secret; the server holds
it as pending, and promotes it the first time the device signs a request with
it. A new certificate is issued the same way as a renewal and is promoted the
first time the device presents it on the agent port. Until then the old
credential keeps working, so a lost response or a crashed client never locks the
device out.

**Admin endpoints** (session cookie of an admin, plus the `X-CSRF-Token` header,
as for the other admin writes):

| Request | Body | Response |
|---|---|---|
| `POST /api/v1/admin/devices/{id}/rotation` | `{"target": "secret" \| "cert" \| "both"}` | `200` `{"secret": {"since": <unix s>, "status": "..."}, "cert": {...}}`; a track with nothing pending is `{"since": null, "status": null}` |
| `POST /api/v1/admin/devices/rotation` | `{"target": "secret" \| "cert" \| "both"}` | `200` `{"marked": n, "awaiting_upgrade": n, "awaiting_mtls": n, "skipped_disabled": n}`, each a count of devices |
| `DELETE /api/v1/admin/devices/{id}/rotation` | none | `204`, whether or not anything was pending (`404` for an unknown device) |

A `target` outside the three values is a `422`. An unknown device is a `404`. A
disabled device, or one whose owner account is disabled, is a `409`; so is
`cert` or `both` when the server has no agent listener. The fleet request marks
every enabled device and counts the disabled ones it skipped.

`status` is one of:

- `pending`: the device has been asked and will rotate at its next check-in.
- `awaiting_upgrade`: **waiting for client upgrade**. The device has not said it
  supports rotation (an older client). The request is kept and takes effect
  once it checks in with an upgraded client.
- `awaiting_mtls`: **waiting for mTLS** (certificate track only). The device's
  last check-in did not come over the agent port, so it has no certificate to
  renew yet.

`awaiting_upgrade` wins over `awaiting_mtls`, which wins over `pending`.

**In the web UI**, an admin device page has a Rotation row with **Rotate
secret**, **Rotate certificate**, **Rotate both** (the last two only when the
agent listener is on) and, while anything is pending, **Cancel rotation**. Both
device pages list each pending track with the time it was requested and any
waiting reason. The admin devices page counts them in the **Devices pending
rotation** tile.

**A pending rotation never expires.** It ends only when:

- the device completes it: the first request signed with the new secret, or the
  first presentation of the new certificate on the agent port;
- an admin cancels it;
- for the certificate track, an admin uses **Reset certificate**, or the device
  provisions a new certificate on the main port after the old one has expired;
- for the secret track, the owner uses **Rotate secret**.

A renewal on its own, or the certificate's expiry on its own, does not end it. A
certificate rotation can be completed by a renewal that was already pending when
the rotation was requested: that certificate is promoted the first time the
device presents it, and the promotion counts as the completion. A device that is
off for a month rotates when it returns.

**Restoring a database backup taken before a rotation locks out every device
rotated since.** The restored database holds the old credential and the device
holds the new one. For the secret track, re-enroll the device. For the
certificate track, use **Reset certificate** on each device.

**The client never sends a new secret over plain `http://` by default.** It
refuses to send a new secret over an `http://` hop unless `run.insecure_provision`
is set: it logs an ERROR and the rotation stays pending on the server. With the
override set it sends the secret and logs a WARN every time. The check is on the
hop the secret would take, so a device already committed to mTLS rotates over its
agent port (https) even when its configured server URL is `http://`. The
certificate track, and signing with a pending secret that already exists, are not
gated: renewal already runs on the agent port, and a signature leaks no secret.

**Cancel keeps an already-issued pending certificate.** Cancel clears the
request and any pending secret, but a certificate the server has already issued
stays valid: the device may be holding only the new certificate, and dropping
the server's record of it would lock the device out. It is promoted when the
device next presents it, and it is replaced by a later renewal or ends at
expiry.

Rotation writes `device.rotation.requested` (one row per request, including a
fleet request), `device.rotation.cancelled` (only when something was pending) and
`device.rotation.completed` audit entries. A completion is one row per track, with
the `track` (`secret` or `cert`) in its details.

**Threat model.** Rotation replaces a credential the legitimate client still
holds. It does **not** evict an attacker who already holds the current secret:
they can race the client's step of proposing a new one. To recover a compromised
device, use the owner's **Rotate secret** (which discards any pending secret) or
disable the device.

### Runbooks

**The active CA key is lost: `ca promote-backup`.** This makes the backup CA
the active one. You need the offline `ca-backup.key`. Stop the server first,
then run the command as a one-off container against the stopped container's
volume and the same environment:

    docker run --rm --volumes-from <stopped-container> --env-file <same .env> \
      -v "$PWD/ca-backup.key:/backup/ca-backup.key:ro" \
      ghcr.io/jacaudi/diyddns/server:<tag> ca promote-backup --backup-key /backup/ca-backup.key

On Kubernetes, scale the Deployment to 0 and run a Job with the same volume,
env and image, with args `["ca","promote-backup","--backup-key","/backup/ca-backup.key"]`
and the key mounted from a Secret. The command also generates a **new** backup
CA: move the newly written `ca-backup.key` offline as described above, then
start the server. Devices need no action: their pin still holds the new active
CA, so their next request gets `client_cert_rejected` and they provision again
on their own.

**Last resort: `ca reset --confirm`.** If the backup key is lost too, run
`diyddns-server ca reset --confirm` with the same one-off-container pattern
(server stopped). It discards the CA, clears every device's recorded
certificate, and renames the old key and `agent.*` files to
`*.reset-<timestamp>`; the next start generates a fresh pair. Every committed
device now fails its pin and needs `diyddns-client mtls reset`. This is
deliberately loud.

**Reset certificate** (the button on an admin device page) clears the
certificate the server has recorded for that device, so the device provisions
a new one on its next check-in.

**Lost renewal response.** This no longer locks a device out. When a renewal
response is lost in transit, the server keeps the device's old certificate
current and holds the renewed one as pending until the device presents it. The
device still has its old certificate, keeps checking in with it, and renews
again next time. Nothing to do.

**Lost device key.** A device logs `ask an admin to click "Reset certificate"`
when the server records a live certificate for it but the device no longer has
the matching key (for example `mtls.json` was deleted): the main port refuses to
issue another (409 `cert_already_issued`). Click **Reset certificate** for that
device; it recovers on its next check-in. Under `require_mtls` the device cannot
report until you do.

**`diyddns-client mtls reset`** deletes `mtls.json` (the device's key,
certificate and pinned CA) on the device. Pair it with **Reset certificate**
on the server, or the server will refuse to issue a new certificate.

### One-way doors

Two operator actions have no automatic recovery, and each needs
`diyddns-client mtls reset` on **every committed device** afterwards:

- turning the agent listener off after devices have committed to it;
- `ca reset`.

---
[← Back to README](../README.md)
