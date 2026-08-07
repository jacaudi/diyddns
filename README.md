# DIYDDNS

A self-hosted, multi-user public-IP tracker. The client agent discovers its
own public IP from a quorum of independent lookup providers and reports the
result to a central server, which stores per-device IP history in SQLite and
exposes both an API and a web UI.

DIYDDNS is **not** an authoritative DNS server and does not push records to
third-party DNS providers. It is an IP registry: clients check in, the server
records, users browse history.

## Status

Early development. The design spec and implementation plans are working
documents kept outside this repository.

## Quickstart (placeholder)

Quickstart instructions will land alongside the first user-facing release. To
try it now, copy [config.example.yaml](config.example.yaml), generate an HMAC
key as documented there, and run `task build` followed by
`diyddns-server serve --config config.yaml`. The startup log prints a
single-use bootstrap token; claim the first admin by POSTing it to
`/api/v1/auth/bootstrap`. `scripts/smoke-test.sh` (or `task smoke`) runs that
whole path end to end.

## Documentation

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE) © 2026 jacaudi
