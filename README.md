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
records, users browse history.

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

If enroll fails, read the message before retrying. `credentials already exist`
means this host is already enrolled and your code is **not** spent — reuse it
elsewhere, or, if you replaced that device, `docker rm -f diyddns-client-run &&
docker volume rm diyddns-client` and run the same command again. `permission
denied` means the volume has the wrong owner; the code may or may not have been
spent, because that message is emitted both before and after the code is sent —
check `/devices` first: if the device is listed the code was spent and you
need a fresh one; if it is absent the code is still good, so clear the
volume with the two commands above and run the same command again. Any
other message means nothing was changed on the server: fix what it
reports and run the same command again, without removing the volume.

## Documentation

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE) © 2026 jacaudi
