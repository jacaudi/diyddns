# DIYDDNS — Plan 01: Scaffolding & CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Pair:** [docs/plans/2026-05-01-diyddns-design.md](2026-05-01-diyddns-design.md)
**Scope:** Plan 01 of 8 — see design Section 13 / decomposition surfaced 2026-05-01.

**Goal:** Stand up the empty Go monorepo with all repo-level files (LICENSE, README,
.gitignore, .editorconfig, code-of-conduct, security policy, contributing guide,
Taskfile, golangci-lint config, .github/ wiring to `jacaudi/github-actions`,
dependabot, CodeQL) so that subsequent plans can drop code into a fully-tooled
repository whose CI pipelines run on every PR and `main` push.

**Architecture:** Single Go module rooted at `github.com/jacaudi/diyddns`. Two
binaries (`cmd/diyddns-server`, `cmd/diyddns-client`) start as minimal `--version`
skeletons that print build metadata. Repo-level config files are concrete
(MIT LICENSE, full lint config, `.gitignore` covering Go + Node + IDE, full
GitHub workflow files referencing the user's shared reusable-workflow repo).
End state: `task lint` passes; `task build` produces both binaries; CI green on
the first PR.

**Tech Stack:** Go (stable, minimum 1.25 in `go.mod`), `go-task/task` for build
orchestration, `golangci-lint`, `jacaudi/github-actions` reusable workflows for
PR/main/release pipelines, `pressly/goose` (referenced; consumed in Plan 02),
GitHub Actions native runners.

---

> **For Claude:** REQUIRED EXECUTION WORKFLOW (follow in order):
>
> 1. `superpowers:using-git-worktrees` — Isolate work in a dedicated worktree
> 2. `superpowers:subagent-driven-development` — Dispatch a fresh subagent per task
> 3. `superpowers:test-driven-development` — All subagents use TDD where applicable
>    (scaffolding-heavy tasks substitute "tool runs cleanly" smoke checks for unit tests)
> 4. `superpowers:verification-before-completion` — Verify each task's smoke check passes
> 5. `superpowers:requesting-code-review` — Code review after each task (built in)
> 6. After all tasks: comprehensive code review on full diff from branch point (automatic)
> 7. `superpowers:finishing-a-development-branch` — Complete the branch
>
> Skills carry their own model and effort settings. Do not override them.

---

## Conventions

- **Go module path:** `github.com/jacaudi/diyddns`
- **GitHub username/owner:** `jacaudi`
- **Copyright holder:** `jacaudi`
- **Go minimum version in `go.mod`:** `1.25` (CI tracks `stable` via shared workflow's `GO_VERSION` variable)
- **Commit messages:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `build:`, `ci:`); the `chore:` and `build:`/`ci:` prefixes dominate this plan.
- **All paths are relative to repo root.**
- **Test discipline:** scaffolding tasks have no traditional unit tests. Each task ends with a **smoke verification step** that confirms the change actually works (the tool consuming the file runs cleanly, the build succeeds, the workflow YAML lints, etc.). This is the substitute for "run the failing test" in TDD-style steps.

---

## File Structure (end state of Plan 01)

```
diyddns/
├── .editorconfig                 (new)
├── .gitignore                    (new)
├── .golangci.yml                 (new)
├── CHANGELOG.md                  (new — empty seed for semantic-release)
├── CODE_OF_CONDUCT.md            (new)
├── CONTRIBUTING.md               (new)
├── LICENSE                       (new — MIT)
├── README.md                     (new — skeleton)
├── SECURITY.md                   (new)
├── Taskfile.yml                  (new)
├── go.mod                        (new)
├── go.sum                        (new — empty/no deps yet)
├── cmd/
│   ├── diyddns-server/main.go    (new — skeleton)
│   └── diyddns-client/main.go    (new — skeleton)
├── internal/
│   └── version/version.go        (new — version metadata package)
├── docs/
│   └── plans/                    (already exists)
└── .github/
    ├── CODEOWNERS                (new)
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md         (new)
    │   ├── feature_request.md    (new)
    │   └── config.yml            (new)
    ├── PULL_REQUEST_TEMPLATE.md  (new)
    ├── dependabot.yml            (new)
    └── workflows/
        ├── ci.yml                (new — main pipeline, semantic-release)
        ├── codeql.yml            (new)
        ├── pr.yml                (new — PR pipeline)
        └── release.yml           (new — tag pipeline)
```

The following directories are created as empty (with `.gitkeep`) to signal
upcoming-plan structure but contain no Go files yet:

```
internal/auth/           internal/server/api/         internal/server/middleware/
internal/server/service/ internal/store/              internal/client/poller/
internal/client/ipdiscovery/  internal/client/enroll/ internal/config/
internal/shared/         migrations/                  packaging/systemd/
packaging/docker/        packaging/launchd/           packaging/proxy/
ui/                      docs/openapi/
```

---

## Tasks

### Task 1: Initialize Go module and first commit

**Files:**
- Create: `go.mod`

**Steps:**

- [ ] **Step 1: Verify clean repo state**

Run:
```bash
git status -sb && git log --oneline 2>&1 | head -5
```
Expected: branch `main` (or whatever default), zero commits or only plan-doc commits, no untracked code yet.

- [ ] **Step 2: Initialize the module**

Run:
```bash
go mod init github.com/jacaudi/diyddns
```
Expected: creates `go.mod` with single `module github.com/jacaudi/diyddns` line plus `go` directive.

- [ ] **Step 3: Pin Go directive to 1.25**

Edit `go.mod` so the file reads exactly:
```
module github.com/jacaudi/diyddns

go 1.25
```

- [ ] **Step 4: Smoke verify**

Run:
```bash
go mod tidy && go build ./... 2>&1 | tee /tmp/diyddns-init-build.log
```
Expected: `go mod tidy` exits 0; `go build ./...` exits 0 with no output (no Go files yet, build is a no-op).

- [ ] **Step 5: Commit**

```bash
git add go.mod
git commit -m "build: initialize go module"
```

---

### Task 2: Create empty directory skeleton

**Files:**
- Create: `internal/auth/.gitkeep`, `internal/server/api/.gitkeep`, `internal/server/middleware/.gitkeep`, `internal/server/service/.gitkeep`, `internal/store/.gitkeep`, `internal/client/poller/.gitkeep`, `internal/client/ipdiscovery/.gitkeep`, `internal/client/enroll/.gitkeep`, `internal/config/.gitkeep`, `internal/shared/.gitkeep`, `migrations/.gitkeep`, `packaging/systemd/.gitkeep`, `packaging/docker/.gitkeep`, `packaging/launchd/.gitkeep`, `packaging/proxy/.gitkeep`, `ui/.gitkeep`, `docs/openapi/.gitkeep`

**Steps:**

- [ ] **Step 1: Create directories with placeholders**

Run:
```bash
mkdir -p \
  internal/auth internal/server/api internal/server/middleware internal/server/service \
  internal/store internal/client/poller internal/client/ipdiscovery internal/client/enroll \
  internal/config internal/shared \
  migrations \
  packaging/systemd packaging/docker packaging/launchd packaging/proxy \
  ui \
  docs/openapi

for d in internal/auth internal/server/api internal/server/middleware internal/server/service \
         internal/store internal/client/poller internal/client/ipdiscovery internal/client/enroll \
         internal/config internal/shared \
         migrations \
         packaging/systemd packaging/docker packaging/launchd packaging/proxy \
         ui \
         docs/openapi; do
  touch "$d/.gitkeep"
done
```

- [ ] **Step 2: Smoke verify**

Run:
```bash
git status -s | wc -l
```
Expected: 17 (one new `.gitkeep` per directory).

- [ ] **Step 3: Commit**

```bash
git add internal migrations packaging ui docs/openapi
git commit -m "chore: scaffold empty directory layout"
```

---

### Task 3: Create `.gitignore`

**Files:**
- Create: `.gitignore`

**Steps:**

- [ ] **Step 1: Write file**

Create `.gitignore` with this exact content:

```gitignore
# Build outputs
/bin/
/dist/
/ui/dist/
/docs/openapi/*.json

# Go
*.test
*.out
coverage.txt
coverage.html

# Node / Vite
node_modules/
.npm/
.pnp.*
.yarn-integrity

# Environment
.env
.env.*
!.env.example

# IDE / OS
.idea/
.vscode/*
!.vscode/extensions.json
!.vscode/settings.shared.json
.DS_Store
Thumbs.db

# Local-only secrets
*.pem
*.key
!testdata/**/*.pem
!testdata/**/*.key

# Goose state file when developing
sqlite3
*.db
*.db-journal
*.db-wal
*.db-shm
```

- [ ] **Step 2: Smoke verify (placeholder is honored)**

Run:
```bash
touch foo.db && git status -s foo.db
```
Expected: no output (file ignored). Then:
```bash
rm foo.db
```

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: add gitignore"
```

---

### Task 4: Create `.editorconfig`

**Files:**
- Create: `.editorconfig`

**Steps:**

- [ ] **Step 1: Write file**

Create `.editorconfig` with this exact content:

```editorconfig
# https://editorconfig.org
root = true

[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 2
insert_final_newline = true
trim_trailing_whitespace = true

[*.go]
indent_style = tab
indent_size = 4

[Makefile]
indent_style = tab

[*.md]
trim_trailing_whitespace = false

[*.{yml,yaml,json,toml}]
indent_size = 2

[*.{ts,tsx,js,jsx,css}]
indent_size = 2
```

- [ ] **Step 2: Commit**

```bash
git add .editorconfig
git commit -m "chore: add editorconfig"
```

---

### Task 5: Create `LICENSE` (MIT)

**Files:**
- Create: `LICENSE`

**Steps:**

- [ ] **Step 1: Write the standard MIT text**

Create `LICENSE` with this exact content:

```
MIT License

Copyright (c) 2026 jacaudi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Commit**

```bash
git add LICENSE
git commit -m "docs: add MIT license"
```

---

### Task 6: Create `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)

**Files:**
- Create: `CODE_OF_CONDUCT.md`

**Steps:**

- [ ] **Step 1: Write file**

Create `CODE_OF_CONDUCT.md` with the verbatim text of Contributor Covenant 2.1
from <https://www.contributor-covenant.org/version/2/1/code_of_conduct/>.
Replace the `[INSERT CONTACT METHOD]` placeholder with `[@jacaudi](https://github.com/jacaudi) directly via GitHub`.

For brevity in this plan, the executing agent should fetch the verbatim Covenant
2.1 markdown and substitute the contact method. Do **not** paraphrase or modify
any clause.

- [ ] **Step 2: Smoke verify**

Run:
```bash
grep -c "Contributor Covenant" CODE_OF_CONDUCT.md
grep -c "@jacaudi" CODE_OF_CONDUCT.md
```
Expected: both ≥ 1.

- [ ] **Step 3: Commit**

```bash
git add CODE_OF_CONDUCT.md
git commit -m "docs: add Contributor Covenant 2.1 code of conduct"
```

---

### Task 7: Create `SECURITY.md`

**Files:**
- Create: `SECURITY.md`

**Steps:**

- [ ] **Step 1: Write file**

Create `SECURITY.md` with this exact content:

```markdown
# Security Policy

## Supported Versions

DIYDDNS is in early development. Only the latest tagged release receives
security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
<https://github.com/jacaudi/diyddns/security/advisories/new>

If GitHub Security Advisories is unavailable, contact
[@jacaudi](https://github.com/jacaudi) directly via GitHub.

You will receive an acknowledgement within 72 hours. We aim to issue a fix
or mitigation within 30 days for high-severity issues; lower-severity issues
are addressed on a best-effort basis.

## Scope

In scope:
- The `diyddns-server` and `diyddns-client` binaries.
- The web UI served by the server.
- Authentication, session, HMAC, and OIDC handling.
- The HTTP/JSON API and OpenAPI surface.

Out of scope:
- Third-party DNS providers, OIDC providers, and reverse proxies.
- Operator misconfiguration that doesn't reflect a defect in DIYDDNS itself.
- Bugs in the IP-discovery providers' upstream services.
```

- [ ] **Step 2: Commit**

```bash
git add SECURITY.md
git commit -m "docs: add security policy"
```

---

### Task 8: Create `CONTRIBUTING.md`

**Files:**
- Create: `CONTRIBUTING.md`

**Steps:**

- [ ] **Step 1: Write file**

Create `CONTRIBUTING.md` with this exact content:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add contributing guide"
```

---

### Task 9: Create initial `CHANGELOG.md`

**Files:**
- Create: `CHANGELOG.md`

**Steps:**

- [ ] **Step 1: Write seed file**

Create `CHANGELOG.md` with this exact content:

```markdown
# Changelog

This file is maintained automatically by
[semantic-release](https://github.com/semantic-release/semantic-release)
based on Conventional Commits. Do not edit by hand.
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: seed CHANGELOG for semantic-release"
```

---

### Task 10: Create `README.md` skeleton

**Files:**
- Create: `README.md`

**Steps:**

- [ ] **Step 1: Write file**

Create `README.md` with this exact content:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README skeleton"
```

---

### Task 11: Create `internal/version` package

**Files:**
- Create: `internal/version/version.go`
- Create: `internal/version/version_test.go`
- Delete: `internal/shared/.gitkeep` is **not** removed; this is a separate package.

**Steps:**

- [ ] **Step 1: Write the failing test**

Create `internal/version/version_test.go` with this exact content:

```go
package version

import (
	"strings"
	"testing"
)

func TestStringFormat(t *testing.T) {
	cases := []struct {
		name    string
		v       Info
		want    string
	}{
		{"all-set", Info{Version: "1.2.3", Commit: "abcdef0", Date: "2026-05-01"}, "1.2.3 (abcdef0, 2026-05-01)"},
		{"only-version", Info{Version: "v0.0.0-dev"}, "v0.0.0-dev"},
		{"empty", Info{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			got := tc.v.String()
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCurrentReturnsNonEmpty(t *testing.T) {
	got := Current().String()
	if strings.TrimSpace(got) == "" {
		t.Fatal("Current().String() should never be empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/version/...
```
Expected: FAIL with `package version: no Go files` or `undefined: Info`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/version/version.go` with this exact content:

```go
// Package version exposes build-time identity for diyddns binaries.
//
// Variables Version, Commit, and Date are intended to be overridden via
// -ldflags "-X github.com/jacaudi/diyddns/internal/version.Version=... ..."
// at build time. Defaults make development builds identifiable.
package version

import "fmt"

var (
	// Version is the semver tag, e.g. "1.2.3", or "v0.0.0-dev" for development.
	Version = "v0.0.0-dev"
	// Commit is the short git SHA. Empty in development.
	Commit = ""
	// Date is the build date in RFC 3339. Empty in development.
	Date = ""
)

// Info is a snapshot of the build identity.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Current returns the build's identity from package-level vars.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

// String renders an Info for human display.
//   - all three fields set:    "VERSION (COMMIT, DATE)"
//   - only Version set:        "VERSION"
//   - all empty:               "unknown"
func (i Info) String() string {
	if i.Version == "" && i.Commit == "" && i.Date == "" {
		return "unknown"
	}
	if i.Commit == "" && i.Date == "" {
		return i.Version
	}
	return fmt.Sprintf("%s (%s, %s)", i.Version, i.Commit, i.Date)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./internal/version/... -v
```
Expected: `PASS` with both `TestStringFormat` and `TestCurrentReturnsNonEmpty` green.

- [ ] **Step 5: Commit**

```bash
git add internal/version
git commit -m "feat: add version package with build-time identity"
```

---

### Task 12: Create `cmd/diyddns-server/main.go` skeleton

**Files:**
- Create: `cmd/diyddns-server/main.go`
- Delete: `cmd/diyddns-server/.gitkeep` (does not exist; the directory is created here)

**Steps:**

- [ ] **Step 1: Write skeleton**

Create `cmd/diyddns-server/main.go` with this exact content:

```go
// Command diyddns-server is the DIYDDNS HTTP server.
//
// This file is a Plan 01 scaffold: it exposes only --version and a no-op run
// path. Plan 03 (Server skeleton & OpenAPI) replaces the run path with the
// real HTTP server.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jacaudi/diyddns/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("diyddns-server", version.Current().String())
		return
	}

	fmt.Fprintln(os.Stderr, "diyddns-server: not yet implemented (Plan 01 scaffold)")
	os.Exit(2)
}
```

- [ ] **Step 2: Smoke verify build & --version**

Run:
```bash
go build -o /tmp/diyddns-server ./cmd/diyddns-server
/tmp/diyddns-server --version
/tmp/diyddns-server ; echo "exit=$?"
rm /tmp/diyddns-server
```
Expected:
1. Build succeeds.
2. First invocation prints `diyddns-server v0.0.0-dev` and exits 0.
3. Second invocation prints the "not yet implemented" message and reports `exit=2`.

- [ ] **Step 3: Commit**

```bash
git add cmd/diyddns-server
git commit -m "feat: scaffold diyddns-server entrypoint with --version"
```

---

### Task 13: Create `cmd/diyddns-client/main.go` skeleton

**Files:**
- Create: `cmd/diyddns-client/main.go`

**Steps:**

- [ ] **Step 1: Write skeleton**

Create `cmd/diyddns-client/main.go` with this exact content:

```go
// Command diyddns-client is the DIYDDNS reporting agent.
//
// This file is a Plan 01 scaffold: it exposes only --version. Plan 06
// (Client) replaces the run path with the real polling loop and enrollment.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jacaudi/diyddns/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("diyddns-client", version.Current().String())
		return
	}

	fmt.Fprintln(os.Stderr, "diyddns-client: not yet implemented (Plan 01 scaffold)")
	os.Exit(2)
}
```

- [ ] **Step 2: Smoke verify build & --version**

Run:
```bash
go build -o /tmp/diyddns-client ./cmd/diyddns-client
/tmp/diyddns-client --version
/tmp/diyddns-client ; echo "exit=$?"
rm /tmp/diyddns-client
```
Expected:
1. Build succeeds.
2. First invocation prints `diyddns-client v0.0.0-dev` and exits 0.
3. Second invocation prints the "not yet implemented" message and reports `exit=2`.

- [ ] **Step 3: Commit**

```bash
git add cmd/diyddns-client
git commit -m "feat: scaffold diyddns-client entrypoint with --version"
```

---

### Task 14: Create `Taskfile.yml`

**Files:**
- Create: `Taskfile.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `Taskfile.yml` with this exact content:

```yaml
version: "3"

vars:
  BIN_DIR: "{{.TASKFILE_DIR}}/bin"
  LDFLAGS: '-X github.com/jacaudi/diyddns/internal/version.Version={{.VERSION | default "v0.0.0-dev"}} -X github.com/jacaudi/diyddns/internal/version.Commit={{.COMMIT | default ""}} -X github.com/jacaudi/diyddns/internal/version.Date={{.DATE | default ""}}'

tasks:
  default:
    desc: List all tasks
    cmds:
      - task --list

  build:
    desc: Build both binaries into ./bin/
    deps: [build:server, build:client]

  build:server:
    desc: Build diyddns-server into ./bin/
    cmds:
      - mkdir -p {{.BIN_DIR}}
      - go build -ldflags "{{.LDFLAGS}}" -o {{.BIN_DIR}}/diyddns-server ./cmd/diyddns-server

  build:client:
    desc: Build diyddns-client into ./bin/
    cmds:
      - mkdir -p {{.BIN_DIR}}
      - go build -ldflags "{{.LDFLAGS}}" -o {{.BIN_DIR}}/diyddns-client ./cmd/diyddns-client

  test:
    desc: Run all tests with the race detector
    cmds:
      - go test ./... -race

  lint:
    desc: Run golangci-lint
    cmds:
      - golangci-lint run

  fmt:
    desc: Format Go sources
    cmds:
      - gofmt -w .
      - go run golang.org/x/tools/cmd/goimports@latest -w .

  tidy:
    desc: Run go mod tidy
    cmds:
      - go mod tidy

  clean:
    desc: Remove build artefacts
    cmds:
      - rm -rf {{.BIN_DIR}} ui/dist docs/openapi/*.json
```

> The `task ui:*`, `task openapi`, `task migrate:new`, `task db:backup`, `task release`, and `task test:net` targets land in their respective subsequent plans (07, 03/05, 02, 02, 08, 06). Plan 01 ships only the targets it can fully back.

- [ ] **Step 2: Smoke verify**

Run:
```bash
task --list
task build
ls -1 bin/
./bin/diyddns-server --version
./bin/diyddns-client --version
```
Expected:
1. `task --list` shows the targets defined above.
2. `task build` produces both binaries.
3. `ls bin/` shows `diyddns-client` and `diyddns-server`.
4. Both `--version` invocations print `v0.0.0-dev`.

- [ ] **Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "build: add Taskfile with build/test/lint/fmt targets"
```

---

### Task 15: Create `.golangci.yml`

**Files:**
- Create: `.golangci.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.golangci.yml` with this exact content:

```yaml
version: "2"

run:
  timeout: 5m
  tests: true

linters:
  default: none
  enable:
    - errcheck
    - govet
    - staticcheck
    - revive
    - gocritic
    - bodyclose
    - gosec
    - misspell
    - errorlint
    - nolintlint
    - ineffassign
    - unused
    - gocyclo
    - dupl

  settings:
    revive:
      rules:
        - name: var-naming
        - name: package-comments
        - name: exported
        - name: error-return
        - name: error-naming
        - name: indent-error-flow
        - name: unexported-return
    gocyclo:
      min-complexity: 15
    errorlint:
      asserts: true
      comparison: true
      errorf: true
    nolintlint:
      require-explanation: true
      require-specific: true
    gosec:
      excludes:
        - G104  # errcheck overlaps; covered separately

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
  exclude-rules:
    # Test files may use longer functions and embedded fixtures.
    - path: _test\.go
      linters: [gocyclo, dupl, gosec, errcheck]

formatters:
  enable:
    - gofmt
    - goimports
```

- [ ] **Step 2: Smoke verify**

Run:
```bash
golangci-lint run
```
Expected: exits 0 with no findings (Plan 01 code is intentionally tiny).

If `golangci-lint` is not installed, install it first:
```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

- [ ] **Step 3: Commit**

```bash
git add .golangci.yml
git commit -m "build: add golangci-lint configuration"
```

---

### Task 16: Sanity check the full toolchain

**Files:** none

**Steps:**

- [ ] **Step 1: Run the full local pipeline end-to-end**

Run:
```bash
task tidy
task fmt
task lint
task test
task build
./bin/diyddns-server --version
./bin/diyddns-client --version
```
Expected: every step exits 0; both binaries print their version line.

- [ ] **Step 2: If `task fmt` produced changes, commit them**

If `git status -s` shows changes:
```bash
git add -A
git commit -m "style: gofmt + goimports"
```

Otherwise skip this step.

---

### Task 17: Create `.github/dependabot.yml`

**Files:**
- Create: `.github/dependabot.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/dependabot.yml` with this exact content:

```yaml
version: 2
updates:
  - package-ecosystem: gomod
    directory: "/"
    schedule:
      interval: weekly
      day: monday
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    labels: ["dependencies", "go"]
    commit-message:
      prefix: "chore"
      include: "scope"

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
      day: monday
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    labels: ["dependencies", "github-actions"]
    commit-message:
      prefix: "chore"
      include: "scope"

  - package-ecosystem: npm
    directory: "/ui"
    schedule:
      interval: weekly
      day: monday
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    labels: ["dependencies", "ui"]
    commit-message:
      prefix: "chore"
      include: "scope"
```

- [ ] **Step 2: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: configure Dependabot for go, github-actions, and npm"
```

---

### Task 18: Create `.github/CODEOWNERS`

**Files:**
- Create: `.github/CODEOWNERS`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/CODEOWNERS` with this exact content:

```
# CODEOWNERS — required reviewers per path.
# https://docs.github.com/en/repositories/managing-your-repositories-settings-and-customizations/customizing-your-repository/about-code-owners

# Default: project owner reviews everything.
*           @jacaudi

# CI/CD wiring is sensitive — same owner, but call it out explicitly.
/.github/   @jacaudi

# Design and implementation specs.
/docs/      @jacaudi
```

- [ ] **Step 2: Commit**

```bash
git add .github/CODEOWNERS
git commit -m "ci: add CODEOWNERS"
```

---

### Task 19: Create `.github/PULL_REQUEST_TEMPLATE.md`

**Files:**
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/PULL_REQUEST_TEMPLATE.md` with this exact content:

```markdown
## What & Why

<!-- One-paragraph summary. What does this change and why is it needed? -->

## Implementation notes

<!-- Anything reviewers need to know about the approach: trade-offs, alternatives
     considered, follow-ups deferred. -->

## Test plan

- [ ] `task lint` passes locally
- [ ] `task test` passes locally
- [ ] Added/updated unit tests
- [ ] Added/updated integration tests (if applicable)
- [ ] Manual verification (describe):

<!-- Screenshots for UI changes go here. -->

## Linked issues

<!-- "Closes #123" or "Refs #123" -->

## Conventional Commit

<!-- The PR title MUST be a Conventional Commit. Examples:
     feat: add device rotate-secret endpoint
     fix: reject HMAC requests with stale timestamps
     chore(deps): bump golangci-lint
     feat!: rename /agent/v1/checkin payload field (breaking) -->
```

- [ ] **Step 2: Commit**

```bash
git add .github/PULL_REQUEST_TEMPLATE.md
git commit -m "ci: add PR template"
```

---

### Task 20: Create issue templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/bug_report.md`
- Create: `.github/ISSUE_TEMPLATE/feature_request.md`
- Create: `.github/ISSUE_TEMPLATE/config.yml`

**Steps:**

- [ ] **Step 1: Write `bug_report.md`**

Create `.github/ISSUE_TEMPLATE/bug_report.md` with this exact content:

```markdown
---
name: Bug report
about: Something isn't behaving as expected
title: "bug: "
labels: ["bug"]
assignees: []
---

## Summary

<!-- One sentence: what's broken? -->

## Reproduction

1.
2.
3.

## Expected behaviour

<!-- What you expected to happen. -->

## Actual behaviour

<!-- What actually happened. Attach logs if you have them. -->

## Environment

- diyddns-server version: <!-- output of `diyddns-server --version` -->
- diyddns-client version: <!-- output of `diyddns-client --version` -->
- OS / arch: <!-- e.g., Linux 6.8 / amd64 -->
- Deployment shape: <!-- systemd / docker / single binary / other -->
- Reverse proxy (if any): <!-- nginx / caddy / traefik / none -->

## Additional context

<!-- Anything else that helps us understand the bug. -->
```

- [ ] **Step 2: Write `feature_request.md`**

Create `.github/ISSUE_TEMPLATE/feature_request.md` with this exact content:

```markdown
---
name: Feature request
about: Suggest a new capability
title: "feat: "
labels: ["enhancement"]
assignees: []
---

## Problem

<!-- What problem are you trying to solve? Concrete scenario, please. -->

## Proposed solution

<!-- What change would solve it? -->

## Alternatives considered

<!-- Other approaches you weighed and why they don't fit. -->

## Additional context

<!-- Mockups, links, related issues. -->
```

- [ ] **Step 3: Write `config.yml`**

Create `.github/ISSUE_TEMPLATE/config.yml` with this exact content:

```yaml
blank_issues_enabled: false
contact_links:
  - name: Security vulnerability
    url: https://github.com/jacaudi/diyddns/security/advisories/new
    about: Report a vulnerability privately. Do NOT open a public issue.
  - name: Design spec
    url: https://github.com/jacaudi/diyddns/blob/main/docs/plans/2026-05-01-diyddns-design.md
    about: Read the design spec before opening a feature request.
```

- [ ] **Step 4: Commit**

```bash
git add .github/ISSUE_TEMPLATE
git commit -m "ci: add issue templates and security contact link"
```

---

### Task 21: Create `.github/workflows/codeql.yml`

**Files:**
- Create: `.github/workflows/codeql.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/workflows/codeql.yml` with this exact content:

```yaml
name: CodeQL

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: "37 7 * * 1"  # weekly Mondays 07:37 UTC

permissions:
  contents: read

jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      packages: read
      actions: read
    strategy:
      fail-fast: false
      matrix:
        language: [go, javascript-typescript]
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        if: matrix.language == 'go'
        uses: actions/setup-go@v5
        with:
          go-version: stable
          cache: true

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/codeql.yml
git commit -m "ci: add CodeQL analysis for Go and JS/TS"
```

---

### Task 22: Create `.github/workflows/pr.yml`

**Files:**
- Create: `.github/workflows/pr.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/workflows/pr.yml` with this exact content:

```yaml
name: PR

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: pr-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    name: Lint
    uses: jacaudi/github-actions/.github/workflows/component-lint.yml@main
    with:
      go: true
      yaml: true
      json: true
      shell: true

  test:
    name: Test
    uses: jacaudi/github-actions/.github/workflows/component-test.yml@main
    with:
      go: true
    secrets: inherit

  go-build-matrix:
    name: Go build matrix
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        os: [linux, darwin, windows]
        arch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
          cache: true
      - name: Cross-compile both binaries
        env:
          GOOS: ${{ matrix.os }}
          GOARCH: ${{ matrix.arch }}
          CGO_ENABLED: "0"
        run: |
          go build -o /tmp/diyddns-server ./cmd/diyddns-server
          go build -o /tmp/diyddns-client ./cmd/diyddns-client

  container-build-verify:
    name: Container build (no push)
    uses: jacaudi/github-actions/.github/workflows/component-container-build.yml@main
    with:
      push: false
      images: |
        diyddns-server:./packaging/docker/server.Dockerfile
        diyddns-client:./packaging/docker/client.Dockerfile
    secrets: inherit
    # Note: Plan 08 lands the Dockerfiles. This job will fail until then; it is
    # included now so wiring is correct, and is gated by the existence of those
    # files. To temporarily skip prior to Plan 08, set the workflow `if:` below.
    if: hashFiles('packaging/docker/server.Dockerfile', 'packaging/docker/client.Dockerfile') != ''
```

- [ ] **Step 2: Smoke verify (yamllint optional)**

Run:
```bash
test -f .github/workflows/pr.yml && echo "OK: file exists"
# If yamllint is available locally:
command -v yamllint >/dev/null && yamllint .github/workflows/pr.yml || echo "skipping yamllint"
```
Expected: `OK: file exists`. If `yamllint` is installed, it should report no issues for the file.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/pr.yml
git commit -m "ci: add PR workflow wired to jacaudi/github-actions components"
```

---

### Task 23: Create `.github/workflows/ci.yml`

**Files:**
- Create: `.github/workflows/ci.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/workflows/ci.yml` with this exact content:

```yaml
name: CI

on:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-main
  cancel-in-progress: false  # never cancel a release in flight

jobs:
  lint:
    name: Lint
    uses: jacaudi/github-actions/.github/workflows/component-lint.yml@main
    with:
      go: true
      yaml: true
      json: true
      shell: true

  test:
    name: Test
    uses: jacaudi/github-actions/.github/workflows/component-test.yml@main
    with:
      go: true
    secrets: inherit

  semantic-release:
    name: Semantic Release
    needs: [lint, test]
    uses: jacaudi/github-actions/.github/workflows/component-semantic-release.yml@main
    secrets:
      APP_ID: ${{ secrets.APP_ID }}
      APP_PRIVATE_KEY: ${{ secrets.APP_PRIVATE_KEY }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add main pipeline with semantic-release"
```

---

### Task 24: Create `.github/workflows/release.yml`

**Files:**
- Create: `.github/workflows/release.yml`

**Steps:**

- [ ] **Step 1: Write file**

Create `.github/workflows/release.yml` with this exact content:

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write
  packages: write

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

jobs:
  containers:
    name: Build & push containers
    uses: jacaudi/github-actions/.github/workflows/component-container-build.yml@main
    with:
      push: true
      images: |
        diyddns-server:./packaging/docker/server.Dockerfile
        diyddns-client:./packaging/docker/client.Dockerfile
    secrets: inherit
    if: hashFiles('packaging/docker/server.Dockerfile', 'packaging/docker/client.Dockerfile') != ''

  binaries:
    name: Cross-compile native binaries
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: linux,   arch: amd64, ext: ""    }
          - { os: linux,   arch: arm64, ext: ""    }
          - { os: darwin,  arch: amd64, ext: ""    }
          - { os: darwin,  arch: arm64, ext: ""    }
          - { os: windows, arch: amd64, ext: ".exe" }
          - { os: windows, arch: arm64, ext: ".exe" }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
          cache: true
      - name: Build
        env:
          GOOS: ${{ matrix.os }}
          GOARCH: ${{ matrix.arch }}
          CGO_ENABLED: "0"
          VERSION: ${{ github.ref_name }}
          COMMIT: ${{ github.sha }}
          DATE: ${{ github.event.head_commit.timestamp }}
        run: |
          mkdir -p dist
          LDFLAGS="-X github.com/jacaudi/diyddns/internal/version.Version=$VERSION -X github.com/jacaudi/diyddns/internal/version.Commit=${COMMIT:0:7} -X github.com/jacaudi/diyddns/internal/version.Date=$DATE"
          go build -ldflags "$LDFLAGS" -o dist/diyddns-server-${{ matrix.os }}-${{ matrix.arch }}${{ matrix.ext }} ./cmd/diyddns-server
          go build -ldflags "$LDFLAGS" -o dist/diyddns-client-${{ matrix.os }}-${{ matrix.arch }}${{ matrix.ext }} ./cmd/diyddns-client
      - name: Generate checksums
        run: |
          cd dist
          sha256sum * > SHA256SUMS-${{ matrix.os }}-${{ matrix.arch }}.txt
      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/*

  summary:
    name: Pipeline summary
    needs: [containers, binaries]
    if: always()
    uses: jacaudi/github-actions/.github/workflows/component-pipeline-summary.yml@main
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add tag release workflow with multi-arch binaries"
```

---

### Task 25: Final pipeline rehearsal

**Files:** none

**Steps:**

- [ ] **Step 1: Re-run the local toolchain**

Run:
```bash
task tidy
task fmt
task lint
task test
task build
./bin/diyddns-server --version
./bin/diyddns-client --version
```
Expected: every step exits 0; both binaries print version `v0.0.0-dev`.

- [ ] **Step 2: Validate workflow YAML syntax (optional but recommended)**

If `actionlint` is available locally:
```bash
actionlint .github/workflows/*.yml
```
Expected: no findings.

If `actionlint` is not installed, install via:
```bash
go install github.com/rhysd/actionlint/cmd/actionlint@latest
```

- [ ] **Step 3: Confirm git log is clean Conventional Commits**

Run:
```bash
git log --oneline | head -30
```
Expected: every line starts with one of `feat:`, `fix:`, `chore:`, `docs:`, `build:`, `ci:`, `style:` (or `Merge ...` for any merge commits, which there shouldn't be in this branch).

- [ ] **Step 4: If `task fmt` produced changes, commit**

```bash
git status -s
```
If anything changed:
```bash
git add -A
git commit -m "style: gofmt + goimports"
```

---

## Self-Review Checklist (already executed)

This plan was reviewed against the design spec; the following design sections are addressed by the listed tasks. Sections not listed here are explicitly deferred to later plans (02–08).

| Design section | Tasks |
|---|---|
| 2 — Architecture & repo layout | 1, 2, 11, 12, 13 |
| 2 — Tech stack (Go, cobra/viper/slog deferred to later plans; lint, taskfile here) | 14, 15 |
| 9 — Logging / Health (deferred — Plan 03) | — |
| 9 — Linting & formatting | 14, 15 |
| 9 — Taskfile (foundational targets only; UI/openapi/migrate/release-* deferred) | 14 |
| 9 — CI/Release workflows | 22, 23, 24 |
| 13 — Repo files at root | 3, 4, 5, 6, 7, 8, 9, 10 |
| 13 — `.github/` | 17, 18, 19, 20, 21 |
| 13 — Branch & PR conventions (encoded in templates and Conventional Commits) | 19, 25 |
| 13 — Versioning (semantic-release wiring) | 23 |

**Deferred (handled in later plans):**

- All `internal/*` package implementations (Plans 02–06).
- Web UI (`ui/`) — Plan 07.
- Dockerfiles, docker-compose, systemd units, launchd, proxy samples — Plan 08.
- Migration files — Plan 02.
- OpenAPI generation, Scalar — Plan 03.
- TS-types codegen, Vitest — Plan 07.

---

## Plan 01 Acceptance Criteria

When this plan is complete:

- `git log --oneline` shows ~25 commits, each a Conventional Commit message.
- `task --list` shows the documented targets.
- `task tidy && task fmt && task lint && task test && task build` exits 0 on a clean checkout.
- `./bin/diyddns-server --version` and `./bin/diyddns-client --version` both print `v0.0.0-dev`.
- The first PR opened against `main` triggers `pr.yml`, which runs lint + test + go-build-matrix successfully (the container-build-verify job is gated and will skip until Plan 08).
- A merge to `main` triggers `ci.yml`, which on first eligible commit (a `feat:` or `fix:`) creates a v0.1.0 GitHub Release via semantic-release.
- A `v*` tag triggers `release.yml`, producing native binaries attached to the GitHub Release (containers job skips until Plan 08).

Plan 02 (Storage & migrations) starts from this foundation.
