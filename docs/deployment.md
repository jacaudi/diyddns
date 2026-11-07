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
everything in front of it.

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

The server refuses to start when `database.path` is in-memory, when
`agent.tls.dir` is under the OS temp directory, or when the recorded CA and
the key files disagree. The CA state lives in `agent.tls.dir` (the `/data`
volume in the image), so keep it on the persistent volume.

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
is the name of the server container in the pod (`app` in the app-template
values above):

    kubectl debug <pod> -i --image=busybox:1.37 --target=diyddns --profile=general -- cat /proc/1/root/data/ca-backup.key > ca-backup.key
    openssl pkey -in ca-backup.key -noout
    kubectl debug <pod> -i --image=busybox:1.37 --target=diyddns --profile=general -- rm /proc/1/root/data/ca-backup.key

**Docker:**

    docker run --rm --volumes-from <container> busybox:1.37 cat /data/ca-backup.key > ca-backup.key
    openssl pkey -in ca-backup.key -noout
    docker run --rm --volumes-from <container> busybox:1.37 rm /data/ca-backup.key

`openssl pkey` prints nothing and exits 0 when the file is a valid private
key; confirm that **before** the `rm`, and store the file offline.

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

**Lost renewal response.** A device logs `ask an admin to click "Reset
certificate"`. The server recorded a renewed certificate that the device never
received (the response was lost in transit), so the agent port rejects the
device's old certificate and the main port refuses to issue another (409
`cert_already_issued`). Click **Reset certificate** for that device; it
recovers on its next check-in. Under `require_mtls` the device cannot report
until you do.

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
