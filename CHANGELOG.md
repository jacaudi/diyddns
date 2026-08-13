# Changelog

## 0.1.0 (2026-08-13)


### ⚠ BREAKING CHANGES

* replace local password auth with multi-passkey WebAuthn ([#46](https://github.com/jacaudi/diyddns/issues/46))

### Features

* add version package with build-time identity ([e960db9](https://github.com/jacaudi/diyddns/commit/e960db9337afb87b581d8afe4e97927bf35d28ac))
* **auth:** Plan 04 — HMAC device auth, sessions/CSRF, bootstrap admin ([#8](https://github.com/jacaudi/diyddns/issues/8)) ([373e9b4](https://github.com/jacaudi/diyddns/commit/373e9b428141897f6cf7a369ac3c0f60c47ad4ab))
* **auth:** Plan 05 — OIDC (browser PKCE + agent device-code) ([#17](https://github.com/jacaudi/diyddns/issues/17)) ([d829309](https://github.com/jacaudi/diyddns/commit/d829309221a3c9b1429c0b44948a196d1af62587))
* **client:** add `run` public-IP reporting loop (Plan 07) ([#29](https://github.com/jacaudi/diyddns/issues/29)) ([9f87870](https://github.com/jacaudi/diyddns/commit/9f87870cc3f8c705bb1288cdcfac9ddcd005c69c))
* **client:** add enroll --code and --user enrollment modes ([#31](https://github.com/jacaudi/diyddns/issues/31)) ([537434e](https://github.com/jacaudi/diyddns/commit/537434e6a63de2cec6800269e6ace4f1155137c8))
* **client:** Plan 06 — enroll --oidc device-code client ([#20](https://github.com/jacaudi/diyddns/issues/20)) ([bcf670f](https://github.com/jacaudi/diyddns/commit/bcf670f28f1fb5fad15183963e9b32e1bc0ea302))
* **packaging:** add multi-arch server and client Dockerfiles ([#56](https://github.com/jacaudi/diyddns/issues/56)) ([645af06](https://github.com/jacaudi/diyddns/commit/645af06c7582cc4a31fa22552f29e60d59b3c94c))
* replace local password auth with multi-passkey WebAuthn ([#46](https://github.com/jacaudi/diyddns/issues/46)) ([f62f520](https://github.com/jacaudi/diyddns/commit/f62f5208c0d4761b629f4bc8424b0701f33c82b7))
* scaffold diyddns-client entrypoint with --version ([e70855a](https://github.com/jacaudi/diyddns/commit/e70855a70cee6ffe15dc1333331537d633a84c58))
* scaffold diyddns-server entrypoint with --version ([e58218b](https://github.com/jacaudi/diyddns/commit/e58218b7bea383aba73a10f2c0d83a2f558eefef))
* **server:** Plan 03 — server skeleton & OpenAPI ([#5](https://github.com/jacaudi/diyddns/issues/5)) ([677646a](https://github.com/jacaudi/diyddns/commit/677646a993109d1d8340b98d027454fea56af5e5))
* **services:** device-management + admin /api/v1 endpoints (Plan 09) ([#33](https://github.com/jacaudi/diyddns/issues/33)) ([ff5cac1](https://github.com/jacaudi/diyddns/commit/ff5cac1e603888e57782584ed3a375828e575062))
* **store:** add audit_log repository with filter and prune ([435f9af](https://github.com/jacaudi/diyddns/commit/435f9afae063f1d5a145679f2076e7f2d761a093))
* **store:** add bootstrap repository for one-time admin claim ([632266a](https://github.com/jacaudi/diyddns/commit/632266adddf275371337c14c85ce6155995acb51))
* **store:** add devices repository with IP/metadata update and rotation ([a4b43df](https://github.com/jacaudi/diyddns/commit/a4b43dfd9aec489f5fa24578133710b23ab26d6d))
* **store:** add enrollment_codes repository with single-use Consume ([966720a](https://github.com/jacaudi/diyddns/commit/966720a164c1a0648101a589a07ce30825d2f175))
* **store:** add ErrNotFound and ErrConflict sentinel errors ([253a18d](https://github.com/jacaudi/diyddns/commit/253a18d941640a9cf1af44d52ad86b4d83f9fd93))
* **store:** add goose-driven Migrate function ([64436d3](https://github.com/jacaudi/diyddns/commit/64436d39b5f0a2fca5820f4817ae749670697773))
* **store:** add initial schema migration ([68b85bd](https://github.com/jacaudi/diyddns/commit/68b85bd063d144010e2d16a650b60011180adeae))
* **store:** add ip_history repository with cursor pagination and always-keep-latest prune ([d0eea2c](https://github.com/jacaudi/diyddns/commit/d0eea2c2e065d3424be68cb6f6f2d6b650bf39c6))
* **store:** add NewID UUIDv7 generator ([6d42e61](https://github.com/jacaudi/diyddns/commit/6d42e61006e4f73e4268ecd62f1104e39c7c09ac))
* **store:** add NowUnix and UnixToTime helpers ([1d5a870](https://github.com/jacaudi/diyddns/commit/1d5a870d43871d54558321ee9829c044da75f719))
* **store:** add replay_nonces repository for HMAC replay defense ([38ef614](https://github.com/jacaudi/diyddns/commit/38ef61482ccce29c08719fcaa1ee4b793f16f4f1))
* **store:** add sessions repository with sliding TTL and prune ([16ceb6e](https://github.com/jacaudi/diyddns/commit/16ceb6e098aca76c388b41e7e164b64f9cc026e3))
* **store:** add Store type with Open/Close and migrate-on-open ([474cab2](https://github.com/jacaudi/diyddns/commit/474cab2a19b3a2fa8ce8a1c9e9dbdd3b3ef54c00))
* **store:** add users repository with CRUD and OIDC lookup ([026df3f](https://github.com/jacaudi/diyddns/commit/026df3f45345afc182adc8856cd6add84a6a98c2))
* **store:** apply WAL/FK/sync/busy_timeout pragmas per connection ([bbc1784](https://github.com/jacaudi/diyddns/commit/bbc1784a69770baabc5f568e92415f1788c37823))
* **store:** embed migrations via go:embed ([6dcf6eb](https://github.com/jacaudi/diyddns/commit/6dcf6ebcb6e14caaae63eafb2cf4140e36067093))
* **store:** SQLite persistence layer (Plan 02) ([0bb2dbd](https://github.com/jacaudi/diyddns/commit/0bb2dbde7dcd6b1bdfe0f3a48451abf626926436))
* **webui:** add the eight server-rendered web UI screens ([#50](https://github.com/jacaudi/diyddns/issues/50)) ([312b768](https://github.com/jacaudi/diyddns/commit/312b76866dc7172c101e3389f0d9f0f154cbf6de))


### Bug Fixes

* handle partial-info combinations in version.Info.String ([2071286](https://github.com/jacaudi/diyddns/commit/2071286538459893c3664307c5a64b3e15345109))
* **packaging:** make the documented quickstart and client container actually work ([#61](https://github.com/jacaudi/diyddns/issues/61)) ([6429da4](https://github.com/jacaudi/diyddns/commit/6429da4b8d0cc6ba656ac15e568dbdedceb2a4b4))
* **store:** set enrollment_codes.device_id ON DELETE SET NULL so device deletion works ([#3](https://github.com/jacaudi/diyddns/issues/3)) ([8751ae5](https://github.com/jacaudi/diyddns/commit/8751ae5771b6f6dc33c36f84a2ba53a23c2e7cf0))
* **webui:** repair the first-run passkey flow and cover the browser client ([#49](https://github.com/jacaudi/diyddns/issues/49)) ([db686bb](https://github.com/jacaudi/diyddns/commit/db686bb31489244530cad771a7911be2ca5b8f8d))

## Changelog

This file is maintained automatically by
[release-please](https://github.com/googleapis/release-please) from Conventional
Commits. Do not edit by hand.
