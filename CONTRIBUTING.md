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

## Compatibility and versioning

AITriage follows [Semantic Versioning](https://semver.org/). A pipeline either
pins a release (`v1.14.0`) or follows a major version: the Action as `@v1` and
the `:v1` scanner image, which move to every new stable `v1` release. Following
`v1` must be safe: minor and patch releases add and fix, and they keep the
contract below. What a scan finds and how triage judges it can still change in
a minor release, always with release notes (see
[Rules, severities and verdicts](#rules-severities-and-verdicts)).

### The public contract

- CLI commands, their arguments and flags.
- Exit codes and what each one means ([README](README.md#exit-codes)).
- Configuration: `.aitriage.yaml` keys and what each one means, the documented
  `AITRIAGE_*` environment variables, and the files AITriage reads from a
  repository (`.aitriage-suppressions.json`, `.aitriage-baseline.json`,
  `.aitriageignore`, inline `aitriage-ignore` directives).
- The GitHub Action's inputs and outputs (`action.yml`).
- Machine-readable output: SARIF, `aitriage scan --format json`,
  `triage-findings.json` and `manifest.json`, including what every field means
  and the form of identifiers and paths.
- The default gate: which findings fail the gate when the configuration does
  not say.

A change is breaking when a pipeline that changed nothing fails, passes or
reads a different value because of it: a command, flag, key, input, output or
field removed or renamed; a field whose type or meaning changes; an exit code
that means something else; a default that makes the gate decide differently
for a configuration that does not set it. Adding a command, flag, key, input,
output or field is not breaking, so consumers of the JSON output must ignore
fields they do not know.

Outside the contract: the wording and layout of human-readable output
(terminal, Markdown and HTML reports, log lines), the caches under
`aitriage-reports/cache/`, and the Go packages under `internal/`. What a scan
finds and how triage judges it follows its own rule, below.

### Releases and major tags

- A breaking change ships only in a major release (`v2.0.0`).
- A minor release adds features and may change findings and verdicts (see
  [Rules, severities and verdicts](#rules-severities-and-verdicts)). A patch
  release fixes bugs.
- The floating `v1` git tag and the `:v1` image move only within their major.
  [`promote-major.yml`](.github/workflows/promote-major.yml) moves both
  together to each stable `v1.x.y` once it is published, never to a
  pre-release and never back to an older release. `v2.0.0` gets its own `v2`
  tag and image; `v1` stays on the last `v1` release.

### Deprecations and default changes

Before a flag, key, input, output or field is removed, and before a default
changes, at least one minor release must warn at runtime: on stderr, and in
the summary of `aitriage agent`, each time a run uses the deprecated item or
relies on the default that will change. The warning names the replacement, or
the explicit setting that keeps today's behaviour, and the release that makes
the change. A change of the gate default is breaking, so that release is the
next major one.

For example, `iac_findings` defaults to `report` in `v1`. Making `block` the
default changes the gate for every configuration that does not set the key, so
it ships in a major release, after `v1` minor releases have warned the runs
that rely on the default. The same holds the other way round:
`quality_findings` defaults to `block` in `v1`, the gate of every release
before the key existed, because a `report` default would let findings that
block today pass.

One exception: when a provider retires the model a default names before a
release with the warning could reach users, keeping the default would break
every run that relies on it. The default then moves in the next release
without a warning release, and the release notes say so. `v1.15.0` moves the
Anthropic and Gemini defaults this way, off `claude-sonnet-4-5` (retired
2026-11-30) and `gemini-2.5-flash` (shut down 2026-12-01). The OpenAI default
stays `gpt-4o`, whose snapshots shut down on 2027-01-14, and runs that rely on
it are warned that `v1.16.0` moves it to `gpt-6-luna`.

### The `triage-findings.json` schema version

`schema_version` increments on any incompatible change to the file: a field
removed or renamed, or a field whose type or meaning changes, such as the form
of an identifier, how paths are written or what one entry stands for. Adding a
field does not increment it. Consumers must reject a version they do not
understand. An increment is a breaking change, so it ships in a major release.

### Rules, severities and verdicts

The contract covers how the gate decides, not which findings exist. A minor
release may add, retune or retire rules, change severities, update the bundled
scanners and change how findings are triaged. That changes what a run reports,
how findings are classified and, under a gate, whether a pipeline passes. The
release notes list every such change: rules added, retired or retuned,
severity changes, scanner updates, and every change that can move verdicts.

### The verdict cache after an upgrade

The verdict cache stores each verdict under a namespace: a hash of the cache
schema version, the AITriage version, the prompt version, a digest of the
embedded rules, the provider, model and base URL, the thinking setting, the
temperature the client sends, the output language and the gate policy
(profile, `fail_on`, `minimum_score`, the `max_*` thresholds, `block_sources`,
`block_classes`, `confirmed_min_severity`,
`fp_critical_requires_high_confidence`, `iac_findings` and `quality_findings`;
`internal/agent/graph/cache.go`). The
AITriage version is the `AITRIAGE_VERSION` the scanner image is built with.
Every run inside the image (the default container runtime of `aitriage agent`,
the Web UI and the AI IDE connectors, and the GitHub Action) therefore starts
each release with an empty namespace: the first run after an upgrade triages
every finding again at full LLM cost, and its verdicts can differ from the
cached ones. A run with `--runtime native` has no `AITRIAGE_VERSION` unless
its environment sets one; its namespace changes when the prompt version, the
rules or the cache schema change. Release notes must say that the first run
after the upgrade re-triages every finding.

### Release checklist

1. Check every change against the contract. A breaking change waits for a
   major release; a deprecation or a default change needs its runtime warning
   in an earlier minor release. An incompatible change to
   `triage-findings.json` increments `schema_version`.
2. Rule changes: scan a corpus with the last release and with the candidate
   (`aitriage scan --format json`), compare the reports with
   `go run ./scripts/rulediff <base-dir> <new-dir>` and check every lost
   finding for a false negative.
3. Changes that can move verdicts (the prompts, the validation of model
   verdicts, batching or retries, the verdict cache) need a shadow run: triage
   a sample of real repositories with LLM triage, once with the last release
   and once with the candidate, with the same provider and model and an empty
   `aitriage-reports/cache/`. Compare the two sets of `triage-findings.json`:
   - `go run ./scripts/rulestats <dir>` on each set: TP, FP and NR per rule;
   - `go run ./scripts/rulestats -compare <old-dir> <new-dir>`: findings whose
     verdict flipped (TP→NR, FP→TP, ...) and findings present in one set only,
     overall and per rule;
   - `go run ./scripts/rulestats -reasons <dir>` on each set: why validation
     rejected or downgraded model verdicts.

   Explain or fix every flip away from a confirmed finding (TP→NR, TP→FP)
   and every new dismissal (NR→FP) before the release, and put the totals in
   the release notes. The reports print only rule ids and counts, so they can
   be shared.
4. Build the image from the release commit and run the publish gate of
   [`docker-publish.yml`](.github/workflows/docker-publish.yml) on it before
   pushing the tag: the scanner bundle checks, the process E2E tests against
   the candidate image, and a Trivy image scan that finds no fixable HIGH or
   CRITICAL vulnerability. Running the workflow by hand (`workflow_dispatch`)
   on the branch that holds the release commit does all three; it also pushes
   a `sha-` image tag (and `latest` from `main`), never `:v1`. A tag whose
   image fails the gate leaves a release that is never published.
5. The release notes list the contract changes (major releases only), the new
   deprecation warnings, rule, severity and scanner changes, the shadow-run
   totals, and that the first run after the upgrade re-triages every finding.

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
scripts/               Release installers and their test scripts; rulestats and rulediff (rule and triage quality reports)
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
