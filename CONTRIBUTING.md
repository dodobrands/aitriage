# Contributing to AITriage

Thank you for your interest in contributing to AITriage. This guide covers the
basics of setting up a development environment, running tests, and submitting
changes.

## Prerequisites

- **Go 1.26.11+** (the version in `go.mod`) — [go.dev/dl](https://go.dev/dl/)
- **A C compiler with CGO enabled** — tree-sitter requires C compilation (`CGO_ENABLED=1`)
- **Node.js 22+** — for the web frontend
- **git** — for version control and diff-based scanning tests
- **Docker** — optional; only for the container runtime and the `docker-*` targets

## Getting Started

```bash
git clone https://github.com/dodobrands/aitriage.git
cd aitriage
go mod download
make build          # Build the binary to bin/aitriage
make test           # Run the Go test suite
```

A local build reports version `dev` and uses the rolling
`ghcr.io/dodobrands/aitriage:v1` scanner image. `make build VERSION=v1.13.0`
pins one release's image instead, and `AITRIAGE_IMAGE=<image>` points the CLI
at any other image, such as one built with `make docker-build`.

## Development Workflow

### Build & Test

```bash
make build          # Build bin/aitriage (run `make sync-web` first to embed the real Web UI)
make test           # Run all Go tests with verbose output
make lint           # Run golangci-lint
make format         # Format Go sources, then the web sources
make clean          # Remove build artifacts
make help           # List every target
```

### Web Frontend

```bash
make build-web      # Build the frontend from the lockfile (npm ci + npm run build)
make sync-web       # Build frontend and sync assets into internal/server/ui/dist
cd web && npm run dev   # Start Vite dev server with HMR on :5173
cd web && npm test      # Run the Vitest unit tests
```

The dev server proxies `/api` to `http://localhost:8080`. Run a backend from
your checkout there, for example `./bin/aitriage web --runtime native`
(development mode: no container, scanners from your `PATH`).

### Docker

```bash
make docker-build              # Build the local scanner image (aitriage:latest)
make docker-tui                # Interactive TUI scan of the current directory in that image
make docker-web                # Build bin/aitriage and serve Web from that image on :8080
make docker-scan               # JSON scan of the current directory in that image
make up                        # Build the image and start only the compose `web` service
make down                      # Stop the compose services
```

Set `PROJECT=/path/to/app` to scan another directory with the `docker-*`
targets. The compose `web` service listens on `127.0.0.1:8080` and scans
projects under `SCAN_ROOT`. `docker-compose.yaml` also defines `aitriage-mcp`,
an MCP server over SSE on `127.0.0.1:9090`
(`docker compose --profile agent up -d aitriage-mcp`) that audits
`PROJECT_PATH`; set both variables in `.env` (see `.env.example`).

### Release (local snapshot)

```bash
make release        # GoReleaser snapshot build for this machine (publishes nothing)
```

Tagged releases are built by `.github/workflows/release.yml`, not by this target.

## Coding Standards

### Go

- Run `make format` before committing — it applies `go fmt`, `goimports`,
  `gofumpt`, and `gci` (if installed).
- Run `make lint` — CI enforces `golangci-lint` with a 5-minute timeout.
- Follow standard Go conventions: effective error handling, context propagation,
  and table-driven tests.
- Comments should be in English, on exported identifiers and non-obvious logic.

### Web (TypeScript / React)

- Run `cd web && npm run format` — applies Prettier + ESLint auto-fix.
- Follow the existing component structure: `pages/` for route views,
  `components/` for reusable UI, `hooks/` for custom hooks, `store/` for
  Zustand state.

### Rules

Security rules live in `rules/<category>/*.yaml`. Every YAML file under
`rules/` is embedded into the binary at build time (`rules/embed.go`) and loaded
by the engine. See [rules/README.md](rules/README.md) for the rule schema,
target modes, conditions, and guidelines for writing custom rules.

When adding or modifying a rule:

1. Add the rule to the appropriate `rules/<category>/security.yaml`.
2. Write the regex in Go RE2 syntax (no lookarounds or backreferences). An
   invalid pattern is not rejected; it silently degrades to a literal match.
3. Add a test: an engine test in `internal/engine/` or a fixture under
   `testdata/synthetic/`.
4. Update the counts in `rules/README.md`; `go test ./rules/` fails when they drift.
5. Run `./bin/aitriage scan <fixture> --stack <stack>` to verify the rule fires.
6. Map the rule to an OWASP category in the suggestion text.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(agent): add retry logic for transient 429 errors
fix(scanner): correct regex for Flask debug flag
docs(rules): document the taint-mode schema
chore(deps): bump golang.org/x/crypto
```

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `refactor:` — code change that neither fixes a bug nor adds a feature
- `test:` — adding or correcting tests
- `chore:` — tooling, deps, CI

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. **Write tests** for your changes. We do not merge features without test
   coverage.
3. **Run checks locally**:
   ```bash
   make format
   make lint
   CGO_ENABLED=1 go test -race ./...
   cd web && npm test && npm run build
   ```
4. **Commit** with conventional commit messages.
5. **Open a pull request** — fill in the PR template completely.
6. **Address review feedback** — push additional commits (do not squash until
   requested).

### CI Checks

GitHub Actions runs on pushes and pull requests to `main`:

- Web UI: `npm ci`, `npm audit --audit-level=high`, `npm test`, `npm run build`
- `go build` with `CGO_ENABLED=1`, installer checks (`scripts/install_test.sh`)
- `go vet`, `govulncheck`, `golangci-lint`
- `go test -race -coverprofile`
- GoReleaser config validation (`goreleaser check`)
- Windows (preview): build, vet and test, plus the PowerShell installer and
  native process tests
- Pull requests also build the Docker image and run the Action entrypoint
  (`test-action.yml`)

The jobs start only for the repository owner's GitHub account
(`github.actor_id`); for other contributors they are skipped, so run the checks
above locally before opening a pull request.

## Project Structure

```
cmd/aitriage/          CLI commands (cobra)
internal/agent/        AI triage: graph pipeline, LLM clients, prompts, MCP server, host-agent runs
internal/engine/       Rule engine, scanner orchestration, baseline, suppressions, history
internal/scanner/      AST, entropy, external, NFR, deploy, network and dependency scanners
internal/runtime/      Container runtime: scanner image selection and `docker run` arguments
internal/config/       `.aitriage.yaml` loading and LLM settings from the environment
internal/server/       Web API server, handlers, SQLite, embedded UI
internal/healthpolicy/ Security gate policy from config and CLI flags
internal/report/       Health check scoring, reporters, SBOM, artifacts
internal/telemetry/    Local usage statistics (`AITRIAGE_TELEMETRY=off` disables them)
internal/ui/tui/       Terminal UI dashboard
rules/                 Embedded security rule catalog (see rules/README.md)
web/                   React 19 + TypeScript + Vite frontend
testdata/              Synthetic fixtures and third-party vulnerable apps (git submodules)
examples/              Example GitHub Actions workflows
scripts/               Release installers and their test scripts
```

## Reporting Issues

- **Bug reports** — use the bug report issue template. Include OS, AITriage
  version (`aitriage version`), and a minimal reproduction.
- **New rules** — use the new detection rule issue template.
- **Feature requests** — describe the use case and expected behaviour.
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md). Do not open a
  public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
