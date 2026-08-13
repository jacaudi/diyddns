# Contributing

Thanks for your interest in DIYDDNS.

## Before you start

- Open an issue describing the change you want to make before writing code,
  unless it's a small fix. The design spec and implementation plans are working
  documents kept outside this repository, so the issue thread is where design
  intent gets shared — ask there if the reasoning behind an area isn't obvious
  from the code.

## Local development

```bash
task --list           # see available tasks
task build            # build both binaries into ./bin/
task test             # run unit + integration tests with the race detector
task lint             # run golangci-lint
task go:fmt           # format Go sources
```

## Commit messages

We use **Conventional Commits**. Examples:

- `feat: add device rotate-secret endpoint`
- `fix: reject HMAC requests with stale timestamps`
- `chore: bump golangci-lint config`
- `docs: clarify enrollment-code TTL`

`feat:` and `fix:` drive minor / patch releases via
[release-please](https://github.com/googleapis/release-please), which opens a release PR
automatically; the release is cut when that PR is merged.
`feat!:` (or a `BREAKING CHANGE:` footer) drives a **minor** release pre-1.0 (this repo is
configured with `bump-minor-pre-major`); it will drive a major release once the project
reaches 1.0.0.

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

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.
