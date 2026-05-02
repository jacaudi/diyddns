# Contributing

Thanks for your interest in DIYDDNS.

## Before you start

- Read the design spec: [docs/plans/2026-05-01-diyddns-design.md](docs/plans/2026-05-01-diyddns-design.md).
- Open an issue describing the change you want to make before writing code,
  unless it's a small fix.

## Local development

```bash
task --list           # see available tasks
task build            # build both binaries into ./bin/
task test             # run unit + integration tests with the race detector
task lint             # run golangci-lint and ui:lint
task fmt              # format Go and UI sources
```

## Commit messages

We use **Conventional Commits**. Examples:

- `feat: add device rotate-secret endpoint`
- `fix: reject HMAC requests with stale timestamps`
- `chore: bump golangci-lint config`
- `docs: clarify enrollment-code TTL`

`feat:` and `fix:` drive minor / patch releases via semantic-release.
`feat!:` (or a `BREAKING CHANGE:` footer) drives a major release.

## Pull requests

1. Branch from `main`: `git switch -c feat/<topic>`.
2. Keep PRs focused; one logical change per PR.
3. Ensure `task lint` and `task test` pass locally.
4. Open the PR against `main`. Squash-merge is the default.
5. CI must be green and the PR template must be filled in.

## Code style

- Go: `gofmt`, `goimports`, full `golangci-lint` (see `.golangci.yml`).
- Errors: wrap with `fmt.Errorf("…: %w", err)`. The `errorlint` linter enforces this.
- Tests: stdlib `testing`, table-driven where inputs are enumerable. No third-party assertion libraries.
- TypeScript / React: `eslint` + `prettier` (configured in `ui/`).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.
