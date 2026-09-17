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

## Production deployment

The server holds a **single** SQLite connection and writes only to the database
file — it must never run as more than one instance against the same file, and
it speaks **plain HTTP only** (no TLS listener). Every example below reflects
both constraints: exactly one replica, and TLS terminated in front of it.

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
Gateway/Ingress, never on the pod — the container itself only ever speaks
plain HTTP.

## Configuration

Every setting has a `DIYDDNS_`-prefixed environment variable; see
[`config.example.yaml`](../config.example.yaml) for the full annotated set. Optional
subsystems each have their own doc — see the [README's Documentation section](../README.md#documentation).

---
[← Back to README](../README.md)
