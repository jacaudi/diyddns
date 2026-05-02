# DIYDDNS

A self-hosted, multi-user public-IP tracker. The client agent discovers its
own public IP from a quorum of independent lookup providers and reports the
result to a central server, which stores per-device IP history in SQLite and
exposes both an API and a web UI.

DIYDDNS is **not** an authoritative DNS server and does not push records to
third-party DNS providers. It is an IP registry: clients check in, the server
records, users browse history.

## Status

Early development. See [docs/plans/](docs/plans/) for the design spec and
implementation roadmap.

## Quickstart (placeholder)

Quickstart instructions will land alongside the first user-facing release. For
now, see the design spec at
[docs/plans/2026-05-01-diyddns-design.md](docs/plans/2026-05-01-diyddns-design.md).

## Documentation

- [Design spec](docs/plans/2026-05-01-diyddns-design.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE) © 2026 jacaudi
