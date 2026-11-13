<div align="center">
  <img src="web/public/favicon.svg" width="88" height="88" alt="AITriage logo">
  <h1>AITriage</h1>
  <p><strong>Security scanners → SecureCoder AI triage → human decision → verified fixes</strong></p>
  <p>One security workflow for AI coding agents, Web, CI/CD, and the terminal.</p>

  <p>
    <a href="https://github.com/dodobrands/aitriage/releases"><img src="https://img.shields.io/github/v/release/dodobrands/aitriage?style=flat-square&color=2563eb" alt="Latest release"></a>
    <a href="https://github.com/dodobrands/aitriage/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/dodobrands/aitriage/ci.yml?branch=main&style=flat-square&label=tests" alt="Test status"></a>
    <a href="https://github.com/dodobrands/aitriage/pkgs/container/aitriage"><img src="https://img.shields.io/badge/scanners-Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker scanner bundle"></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/dodobrands/aitriage?style=flat-square" alt="MIT license"></a>
  </p>

  <p>
    <a href="#1-install-once"><strong>Install</strong></a> ·
    <a href="#2-ai-ide-codex-claude-code-cursor-antigravity-vs-code"><strong>AI IDE</strong></a> ·
    <a href="#3-web-ui"><strong>Web</strong></a> ·
    <a href="#4-cicd"><strong>CI/CD</strong></a> ·
    <a href="#5-cli"><strong>CLI</strong></a> ·
    <a href="#reports"><strong>Reports</strong></a>
  </p>
</div>

---

AITriage runs deterministic checks plus Semgrep, Trivy, Gitleaks, and Bandit. Its SecureCoder workflow then validates the findings, separates confirmed vulnerabilities from uncertain results and false positives, and prepares remediation instructions. Source code changes require a user decision.

## 1. Install once

AITriage is a system tool, not a dependency of the application being checked. Install it once on the computer; do not clone or copy AITriage into every project.

### Set up through your AI IDE

Open Codex or Claude Code and paste this request:

```text
Install the official released AITriage CLI on this computer and prepare its
complete scanner bundle. Official project: https://github.com/dodobrands/aitriage

Do not clone AITriage into my current repository and do not change its source.
If `aitriage` is missing, detect the host operating system and run exactly one
official installer:
- Native Windows PowerShell:
  `irm https://github.com/dodobrands/aitriage/releases/latest/download/install.ps1 | iex`
- macOS or Linux shell:
  `curl -fsSL https://github.com/dodobrands/aitriage/releases/latest/download/install.sh | sh`

Do not run the Unix installer on native Windows. Do not run the Windows
installer inside WSL. The installer verifies the release checksum and prepares
the complete scanner bundle. Do not download a binary from any other source.

Read the installer output. If the system executable directory needs an
administrator password but this AI IDE has no interactive terminal, the
installer safely uses `$HOME/.local/bin/aitriage`. On native Windows the
installer uses
`$env:LOCALAPPDATA\Programs\AITriage\bin\aitriage.exe` and updates User PATH.
Use the applicable exact executable path for the remaining commands when
`aitriage` is not yet on `PATH`; do not rerun the installer and do not edit
shell startup files without asking me.

Then run `aitriage version` and `aitriage setup --status --json` using the same
executable (absolute path if the current terminal has not picked up PATH yet).
If the status is not `ok`, show me its `message`, `action_url` (if present) and
`retry_command`, then stop. Never install Docker from another source.
If the status is `ok`, tell me the AITriage version, executable path, container
image, and status of every bundled scanner from that output. Do not connect a
project or run an audit yet.
```

The result is one host CLI plus one verified Docker image. The source repository is unnecessary for normal use.

### Set up manually on macOS or Linux

Requirements: macOS or Linux on x86_64 or arm64, and a running [Docker Desktop or Docker Engine](https://docs.docker.com/get-started/get-docker/).

```bash
curl -fsSL https://github.com/dodobrands/aitriage/releases/latest/download/install.sh | sh
aitriage setup --status
```

The installer downloads the matching official GitHub Release, verifies its
SHA-256 checksum, installs the CLI into `/usr/local/bin`, and runs
`aitriage setup --full`. To inspect the script before running it:

```bash
curl -fsSLO https://github.com/dodobrands/aitriage/releases/latest/download/install.sh
less install.sh
sh install.sh
```

In a non-interactive environment where the system executable directory needs
administrator approval, the installer falls back to `$HOME/.local/bin` and
prints the exact executable path. Add that directory to `PATH` for future
shells if it is not already present.

Go 1.26.11 or newer with a C compiler (tree-sitter needs CGO) remains a developer fallback:

```bash
go install github.com/dodobrands/aitriage/cmd/aitriage@latest
aitriage setup --full
```

If Docker is missing or stopped, setup exits without scanning and prints one official installation link plus the same command to retry. It does not silently install Docker or individual scanners.

### Windows (native, preview)

> **Preview.** The Windows installer, binary, container paths and MCP
> configuration are covered by the required `windows-latest` CI job. The full
> Docker Desktop + Codex/Claude Code flow has **not** been run manually on
> Windows yet. Native Windows is x86_64 only; Windows ARM64 is not yet published.

Requirements: Windows 10/11 x86_64, PowerShell 5.1 or 7, and a running
[Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)
in **Linux-container** mode. AITriage uses the same Linux scanner image as
macOS/Linux and does **not** install Docker Desktop for you.

In PowerShell (no administrator required):

```powershell
irm https://github.com/dodobrands/aitriage/releases/latest/download/install.ps1 | iex
```

Inspect-first (recommended):

```powershell
irm https://github.com/dodobrands/aitriage/releases/latest/download/install.ps1 -OutFile install.ps1
# review install.ps1, then:
$installer = [ScriptBlock]::Create((Get-Content -Raw .\install.ps1))
& $installer
```

The installer verifies the release SHA-256, installs
`%LOCALAPPDATA%\Programs\AITriage\bin\aitriage.exe` for the current user, adds it
to your **User PATH**, and runs `aitriage setup --full`. It installs only the CLI
and the official version-pinned scanner image — nothing else. Open a **new**
terminal so the PATH update applies, then:

```powershell
aitriage setup --status
```

Connect a project with the **same** commands as macOS/Linux:

```powershell
aitriage install-codex .
aitriage install-claude-code .
```

For setup through an AI IDE, use the OS-aware prompt at the beginning of this
section. It selects `install.ps1` on native Windows without manual ZIP handling
or PATH editing.

Uninstall (removes only the AITriage CLI and its User PATH entry; add
`-RemoveImage` to also remove the downloaded scanner image):

```powershell
$installer = [ScriptBlock]::Create((irm https://github.com/dodobrands/aitriage/releases/latest/download/install.ps1))
& $installer -Uninstall
```

#### WSL2 fallback

As an alternative to native Windows, use a WSL2 Linux distribution with Docker
Desktop's WSL integration enabled and run the **Linux** installer inside WSL. Do
not mix native Windows and WSL paths, binaries or MCP configs in one project:

```bash
curl -fsSL https://github.com/dodobrands/aitriage/releases/latest/download/install.sh | sh
```

### What is installed

| Part | Where | Purpose |
| :--- | :--- | :--- |
| `aitriage` CLI | system executable path | setup, project connectors, CLI, Web, MCP launcher |
| scanner image | local Docker image cache | AITriage, Semgrep, Trivy, Gitleaks, Bandit |
| scanner cache | `aitriage/scanners` in the user cache directory | reusable scanner databases; never stored in source |
| reports | `<project>/aitriage-reports/` | results and local run state for that project |

`aitriage setup --full` is safe to repeat after an upgrade. Remove only the downloaded AITriage image with `aitriage setup --remove-runtime`.

## Choose how to use it

| Interface | Use it when | AI access |
| :--- | :--- | :--- |
| [AI IDE](#2-ai-ide-codex-claude-code-cursor-antigravity-vs-code) | Codex, Claude Code, Cursor, Antigravity or VS Code should audit and help fix the open project | subscription of the AI IDE you use |
| [Web](#3-web-ui) | a person wants a local browser dashboard | provider API key for AI triage |
| [CI/CD](#4-cicd) | pushes and pull requests need an automatic gate | provider key in CI secrets |
| [CLI](#5-cli) | terminal or scripts | none for raw scan; provider key for full AI triage |

## 2. AI IDE: Codex, Claude Code, Cursor, Antigravity, VS Code

This mode uses the model included in the AI IDE's own subscription. It does not need a separate LLM API key.

> **Two activation paths.** Only Claude Code can approve the MCP server from the
> command line (`claude mcp add`), so it is live right after the connector runs
> when the `claude` CLI is on `PATH` (otherwise the connector writes `.mcp.json`
> and Claude Code asks you to approve the server).
> **Cursor, Antigravity, VS Code and Codex** have no scriptable approval: the
> connector writes the project-local config, then **you must enable the
> `aitriage` server and approve its tools in that IDE's UI** (Codex: trust the
> project) before opening a new session. Until you do, the server is not
> connected — and the agent must **not** pass off a raw `aitriage scan` as the
> audit.

### Connect the open project through your AI IDE

First finish the [one-time installation](#1-install-once). Then open the **root of the project to audit** and paste:

```text
Connect AITriage to the repository currently open in this AI IDE.

Run `aitriage setup --status --json` first. Stop if the complete scanner bundle
is not ready. Detect this client and run exactly one command from the open
repository root:
- Codex: `aitriage install-codex .`
- Claude Code: `aitriage install-claude-code .`
- Cursor: `aitriage install-cursor .`
- Antigravity: `aitriage install-antigravity .`
- VS Code (Copilot agent): `aitriage install-vscode .`
If you cannot tell which client you are, ask me instead of guessing.

Do not clone AITriage here. Preserve existing source, instructions, MCP servers,
and `.gitignore` entries. Do not audit or edit source during setup. Verify the
project-local MCP configuration and list the files changed. For Claude Code the
server is live immediately. For Codex, Cursor, Antigravity or VS Code, tell me
the exact UI step to enable the `aitriage` server and approve its tools — it is
NOT active until I do that. Then tell me to open a new task or session so the
client loads the server.
```

For Cursor, Antigravity, VS Code and Codex, enable and approve the `aitriage`
server in the IDE now (the connector prints the exact step). Then open a new
task/session in the same project. From then on, ordinary requests are enough:

```text
Audit this project with AITriage. Do not fix anything yet.
```

AITriage—not the AI IDE—supplies the SecureCoder prompts, controls the workflow, and creates the final artifacts. The agent returns each model answer to AITriage until triage completes.

When you decide to fix findings, say which ones or explicitly approve all confirmed findings:

```text
Fix the vulnerabilities AITriage confirmed. Leave uncertain findings and false
positives alone. Run the tests and verify the fixes with AITriage.
```

### Connect manually

Run the one command for your IDE from the project root:

```bash
aitriage install-codex .         # Codex        → .codex/config.toml
aitriage install-claude-code .   # Claude Code  → claude mcp add (or .mcp.json)
aitriage install-cursor .        # Cursor       → .cursor/mcp.json
aitriage install-antigravity .   # Antigravity  → .agents/mcp_config.json
aitriage install-vscode .        # VS Code      → .vscode/mcp.json
```

Every connector uses the verified container runtime by default, preserves unrelated client settings, adds `/aitriage-reports/` to `.gitignore`, writes a **project-local** config (never a global one), and confines tools to the opened root and its subdirectories. Claude Code is live immediately; for the others, enable and approve the `aitriage` server in the IDE UI as the command prints. Open a new task/session after connecting.

Windsurf is not supported as a first-class connector: it only reads a single global `~/.codeium/windsurf/mcp_config.json`, which cannot keep one project's scan-root isolated from another. Point it at `aitriage serve --runtime container --profile safe --scan-root <project>` manually if you accept that trade-off (this is the command the connectors register; `serve` alone runs natively with the full, unconfined tool profile).

Update by running the same command again. Remove only the AITriage integration with `--uninstall`:

```bash
aitriage install-codex . --uninstall
aitriage install-claude-code . --uninstall
aitriage install-cursor . --uninstall
aitriage install-antigravity . --uninstall
aitriage install-vscode . --uninstall
```

## 3. Web UI

Web provides a local dashboard for findings, evidence, reports, and run history. It uses the same verified scanner image.

### Start through your AI IDE

```text
Start AITriage Web for the repository currently open in this AI IDE.
Run `aitriage setup --status --json` and stop if the scanner bundle is not ready.
Then run `aitriage web --project . --port 8080`, wait until it responds, and
give me the local URL and the command to stop it. Do not expose it to the
network, write credentials to files, or change source code.
```

### Start manually

```bash
aitriage web --project . --port 8080
```

Open [http://localhost:8080](http://localhost:8080). Stop with `Ctrl-C`.

Web AI triage cannot use a Codex or Claude subscription. Set a supported provider key in the process environment when AI features are needed, for example:

```bash
export GEMINI_API_KEY="..."
aitriage web --project . --port 8080
```

The current Web server has no enforced login. It binds through the managed container to localhost; keep it local and do not expose it directly to the Internet.

## 4. CI/CD

CI uses the same AITriage pipeline and SecureCoder prompts, but its model is authenticated by a secret in the CI platform. A developer's local installation and subscription are not used.

### Configure through your AI IDE

```text
Add AITriage CI/CD to this repository using an official example from
https://github.com/dodobrands/aitriage/tree/main/examples/github-actions.
Preserve existing workflows. Never put a provider key in YAML or source code;
reference a GitHub Secret. Show me the workflow diff and required secret before
committing or pushing. Do not invent an organization-specific reusable workflow
URL: ask me if the approved URL is not already documented in this repository.
```

### Configure manually

Choose the closest template in [`examples/github-actions/`](examples/github-actions/):

- [`aitriage-security.yml`](examples/github-actions/aitriage-security.yml) — standard run: deterministic evidence plus the AI-triaged policy gate;
- [`aitriage-pr-gate.yml`](examples/github-actions/aitriage-pr-gate.yml) — fast deterministic pull-request gate, no provider key;
- [`aitriage-ai-advisor.yml`](examples/github-actions/aitriage-ai-advisor.yml) — non-blocking AI advisory output;
- [`aitriage-manual-html-report.yml`](examples/github-actions/aitriage-manual-html-report.yml) — manually triggered HTML report.

Copy the selected file to `.github/workflows/` and set what its header comment lists: the repository variable `AITRIAGE_ALLOWED_ACTOR_ID` (every job is skipped while it is empty) and, for the AI templates, the provider key in GitHub Secrets. Trigger it once, then verify the uploaded reports, SARIF, and post-AI gate before making the check required.

The Action's `fail-on`, `fail-score` and `health-profile` inputs set the gate of `command: scan`. `command: agent` takes its gate from `args`, as the templates do, or from `.aitriage.yaml`. The agent exits `1` when the gate fails and `2` when the audit could not complete, for example because the provider rejected the key or rate-limited the run: treat `2` as a retry, not as a finding (see [exit codes](#exit-codes)). To accept one assessed finding, such as a CVE, record it with [`aitriage ignore add`](#silencing-rules-and-findings) and commit `.aitriage-suppressions.json`; the agent applies it in CI.

For organizations, the application workflow may call one centrally managed reusable workflow. Use the exact approved repository and secret names; AITriage documentation intentionally does not guess them.

## 5. CLI

### Raw deterministic scan

```bash
aitriage scan .
```

This fast pre-scan uses built-in deterministic checks only. It requires neither Docker nor an AI key, but it is **not** a completed SecureCoder verdict.

Useful variants:

```bash
aitriage scan ./service
aitriage scan . --staged
aitriage scan . --diff origin/main
aitriage scan . --format sarif -o aitriage.sarif
```

### Full AI audit

Provide a supported provider key and run:

```bash
export GEMINI_API_KEY="..."
aitriage agent . --no-chat
```

`agent` uses the full container scanner bundle by default and runs the same SecureCoder pipeline used by CI. Without extra output flags it writes a run bundle to `aitriage-reports/` (see [Reports](#reports)). Provider variables include `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GROQ_API_KEY`; `--provider` and `--model` override the auto-detected choice. It exits `1` when a configured gate fails and `2` when the audit could not complete ([exit codes](#exit-codes)).

To use a Codex or Claude subscription instead of an API key, use the [AI IDE integration](#2-ai-ide-codex-claude-code-cursor-antigravity-vs-code).

## Reports

All project-owned output lives under one ignored directory:

```text
aitriage-reports/
├── run-.../
│   ├── summary.md            # start here
│   ├── report.md             # full SecureCoder report
│   ├── fixspec.md            # remediation instructions
│   ├── triage-findings.json  # all AI verdicts
│   ├── aitriage.sarif        # standard scanner output
│   ├── manifest.json         # state, scanner coverage, integrity metadata
│   ├── scan.json             # AI IDE runs: deterministic input to triage
│   └── audit.log             # AI IDE runs: run events
├── baselines/                # container runtime: local baseline copies
├── suppressions/             # container runtime: local dismissal copies
├── cache/                    # verdict and artifact cache
├── history/                  # deterministic scan history
└── web/                      # local Web state
```

Connectors add `/aitriage-reports/` to `.gitignore`. AITriage excludes this directory from every scanner and AI context so its own output cannot trigger another audit loop. List or remove AI IDE run bundles with `aitriage runs list .` and `aitriage runs clean .` (`--dry-run` previews; unfinished runs are kept unless you pass `--force`).

Paths in every report are relative to the project root. When several scanners report the same vulnerability class at the same `file:line`, the report shows one finding that lists every scanner as an origin; different classes on one line stay separate. Tools that read `triage-findings.json` should check `finding.origins[]`, which lists every scanner that reported the defect; `finding.source` names only the one shown (for a hardcoded secret that is Gitleaks whenever Gitleaks reported it). The summary header groups dependency CVEs by package, while the score and the gate still count each CVE. A finding's ID (`CS-<CLASS>-<6 hex>`; the full `stable_id` is in `triage-findings.json`) is derived from its class, its file and the content of the flagged line, so edits elsewhere in the file keep both the ID and the cached verdict. Dismissed findings are left out of SARIF output, because GitHub code scanning does not honour the SARIF `suppressions` property; they stay in `triage-findings.json` and in the summary counts. Dismissing any one scanner's report of a defect dismisses the merged finding.

## Scope, cost and the gate verdict

### What is in scope

AITriage audits the application you ship, not everything on disk. By default it skips
files `git` ignores and directories holding third-party or generated code
(`vendor`, `node_modules`, `dist`, `.next`, `__pycache__`, `venv`). A `build` directory is
scanned unless `git` ignores it: generated build output is ignored in practice, and a
committed one, such as Go's `build/package/Dockerfile`, is your own. The same
rules apply to every scanner: the built-in engine, the bundled Semgrep, Trivy, Gitleaks and
Bandit, the NFR and deploy checks, and the git-history secret scan, so a vendored dependency
is never reported as your vulnerability.

| Setting | Effect |
| :--- | :--- |
| `AITRIAGE_RESPECT_GITIGNORE=false` | Audit ignored files too. Use when the question is "did a secret ever reach this working tree", not "is my application vulnerable" |
| `AITRIAGE_SCAN_VENDORED=true` | Audit vendored and generated directories as if they were your own source |
| `.aitriageignore` | Per-project excludes, same syntax as `.gitignore`, always honoured |
| `ignore.paths` in `.aitriage.yaml` | Same syntax as `.gitignore`, relative to the project root, always honoured by every scanner. As in git, a pattern with a slash before its last character (`app/legacy/`) is anchored at the root; use `**/app/legacy/` for any depth |

The built-in engine used to match `ignore.paths` as substrings, so `vendor` also hid
`src/vendors/` and `.git` hid `.github/`. Such directories are scanned again; for one release
AITriage warns about each pattern that no longer hides a path and names the entry to add if it
should stay out of scope.

The two variables change what the bundled scanners and the git-history scan cover; the
built-in engine always skips ignored files and those directories. They are read by the
process that runs the scanners: set them in the GitHub Action's job environment or in your
shell. The local container launcher used by `agent` and `web` forwards them along with provider
keys, the `AITRIAGE_LLM_*` settings, `AITRIAGE_BATCH_SIZE`, `AITRIAGE_CLASSIFY_RETRIES`,
`AITRIAGE_CONCURRENCY`, `AITRIAGE_POC_BUDGET` and `AITRIAGE_GATING`.

Network findings describe the machine AITriage runs on rather than the repository, so probing
is opt-in: `aitriage agent --probe-compose` probes the services declared by the project's
Compose file, `--probe <host>` a host of your choice, and a Web scan probes only when it is
asked to. A name that does not resolve, as Compose service names in CI do not, is not a
finding. Network findings are reported, but never sent to the LLM and never counted in the
score or the gate.

Trivy reports dependency vulnerabilities and IaC misconfigurations (Terraform, Kubernetes
manifests, Dockerfiles and similar files). It applies the repository's own ignore file to both
scans: `.trivyignore`, or `.trivyignore.yaml` / `.trivyignore.yml`. Trivy reads one ignore
file per run, so when both forms exist the YAML file is used and a warning names the one
left out. The file is read from the repository root wherever AITriage runs, including the
container. `scanners.trivy.ignore_unfixed` and `scanners.trivy.severity` in `.aitriage.yaml`
narrow what Trivy reports; see the [configuration example](.aitriage.yaml.example).

### Hardcoded secrets

A hardcoded secret is never dismissed automatically: a person decides. Reports that cannot be
a live secret are kept out of that queue:

- Bandit's hardcoded-password reports (B105, B106, B107) are dropped when the string they quote
  cannot be a credential: it is empty, it is a sentence such as an error message, or it is the
  name of a token issued at run time (`csrf_token`, `X-XSRF-TOKEN`). Every other value, weak
  ones included, is still reported.

### Silencing rules and findings

| Mechanism | What it silences |
| :--- | :--- |
| `ignore.rules` in `.aitriage.yaml` | Every finding of a rule, from any source: built-in rules and heuristics, Semgrep, Trivy, Gitleaks, Bandit, NFR, deploy and network checks. A bare ID matches any source; `gitleaks:generic-api-key`, `trivy:CVE-2024-1234` or `semgrep:<check-id>` match one scanner, and `core:`, `nfr:`, `deploy:` or `network:` one of AITriage's own checks |
| An inline comment | The rules it names, at one place in the source: built-in, external-scanner and deploy findings |
| `aitriage ignore add` | Findings a person reviewed and dismissed as a false positive, accepted risk or won't-fix, recorded in `.aitriage-suppressions.json` |

A Trivy check matches in every spelling Trivy releases have used, in `ignore.rules` and in
inline comments: `KSV012`, `KSV-0012` and `AVD-KSV-0012` (with or without `trivy:`) name one
check. Advisory IDs (`CVE-…`, `GHSA-…`) and the IDs of other scanners compare as written.

Inline directives name the rules they silence. IDs compare whole, text after the list (such
as a reason) is never read as an ID, and `all` silences every rule only as an ID of its own:

```text
token = "fixture"  # aitriage-ignore: B105, gitleaks:generic-api-key (test data)
# aitriage-ignore-next-line: PY-SUBPROCESS
# aitriage-ignore-file: ENTR-12    (first 10 lines; without IDs it covers every rule)
```

`aitriage-ignore` (or `aitriage:ignore`) covers its own line and the next one;
`-next-line` covers only the next one.
A directive counts only when it opens a comment; a mention in prose, Markdown text or a string
literal (including multi-line strings such as Python docstrings, JS template literals and Go raw
strings) is ignored. Rule IDs may be separated by commas or spaces; the list ends at the first word
that does not look like a rule ID, or at `(`, so `aitriage-ignore: B105 allowed in tests` silences
only B105.

Commit `.aitriage-suppressions.json`: `aitriage agent` (in CI too), AI IDE runs and the Web UI
apply it, and a dismissed finding is not sent to the LLM. This is how to accept a specific CVE
in CI:

```bash
aitriage ignore add CVE-2024-1234 --source trivy --reason accepted-risk \
  --note "the vulnerable parser never receives user input"
```

A decision matches findings of its `--source` and rule. Without `--file` it covers them
anywhere in the project, with `--file` every one in that file, and `--evidence` makes it exact:
only the finding whose matched text it quotes (with no `--file`, only a finding that has no
file). The Web API (`POST /api/suppressions`) and the AI IDE tool refuse a decision without a
file unless `rule_wide: true` is passed, and every response states which findings the decision
covers, so one call cannot silently dismiss a rule across the whole project. Dismissing any one
scanner's report of a merged finding dismisses that defect only; it never covers a different rule's
project-level check or another container in the same manifest. Dismissals made in the Web UI or an AI IDE under the container runtime are kept in a
local copy first; see the baseline notes below.

### Why the gate can fail with nothing confirmed

A scanner finding is a hypothesis until someone confirms it. AITriage reports three states:
**confirmed**, **needs review** and **suppressed** (false positive, accepted risk, resolved).
The default policy is fail-closed: unreviewed findings block, because unreviewed is
unresolved, not proven safe. This matches how Sonar quality gates and GitHub code scanning
behave — an alert must be triaged or dismissed before it stops blocking.

That default has a known failure mode on an existing codebase: the gate judges years of
accumulated debt, and the team learns to override it. Choose deliberately:

| Setting | Meaning |
| :--- | :--- |
| `fail_on: critical` (default) | Active CRITICAL/HIGH findings block |
| `fail_on: any` | Any active finding blocks, reviewed or not |
| `fail_on: confirmed` | Only findings AI triage confirmed block; unreviewed are reported, not blocking. `confirmed_min_severity` (`--confirmed-min-severity`) limits this to confirmed findings at or above `MEDIUM`, `HIGH` or `CRITICAL`; the default `LOW` keeps every confirmed finding blocking |
| `fail_on: never` | The gate never blocks; the score is informational |
| `iac_findings: report` (default) / `block` | IaC misconfigurations from Trivy (Dockerfile, Kubernetes, Terraform). `report` triages and shows them in the summary, the report and `triage-findings.json` but keeps them out of the score and the gate, and the summary says how many; `block` (`--iac-findings block`) gates them like any other finding. A finding another check also reported (for example `DOCKER-NO-USER` and Trivy's `DS-0002`) gates either way. A later minor release makes `block` the default |
| `aitriage baseline create .` | Accept today's findings as the starting line; `aitriage scan . --baseline` then reports and gates only new findings |

Set `fail_on` under `health_check:` in `.aitriage.yaml` or with `--fail-on`. `aitriage scan`,
including the Action's default `scan` command, uses `critical`; a raw scan confirms nothing, so
`fail_on: confirmed` alone never blocks it. `aitriage agent` applies a gate only when one is
configured in `.aitriage.yaml` or passed with `--fail-on`, `--fail-score` or `--health-profile`.

Under `fail_on: confirmed` the gate is only as stable as the model's verdicts, and verdicts
differ noticeably between models on the same code. Pin one model (`llm.model` or `--model`)
and re-check a project you know before switching to another.
`fp_critical_requires_high_confidence: true` (`--fp-critical-requires-high-confidence`) keeps a
CRITICAL finding for manual review unless the model calls it a false positive with high
confidence. A false positive also needs evidence AITriage can check. A code mitigation must be
code (not a comment, a string, a configuration file or the flagged line itself), in the same file
and the same function at most 30 lines above the flagged line, name a variable or function the
flagged statement uses, and be a guard of it (an `if`, `elif` or `assert` that checks it and
exits early or encloses the flagged statement) or a re-assignment of it through a call
(`cmd = shlex.quote(cmd)`). AITriage checks this on the syntax tree for Python, Go, JavaScript
and TypeScript; in other languages a HIGH finding dismissed this way stays Needs Manual Review.
A CRITICAL finding is never dismissed by a code mitigation, and a hardcoded secret by no
evidence at all, not even in a test file: they stay Needs Manual Review until a person decides.

A baseline is a property of the project, not of the tool that created it. The shared record is
`.aitriage-baseline.json` at the repository root, used by the CLI (`aitriage baseline`), the Web
UI (SecureCoder → Baseline) and an AI IDE (`aitriage_baseline`); a Web scan can hide baselined
findings. Under the MCP safe profile only inspection is offered, because accepting findings
writes to the project.

The container runtime mounts the project read-only, so there the Web UI and the MCP tools write
baselines and dismissals to a local copy under `aitriage-reports/baselines/…` and
`aitriage-reports/suppressions/…`. Scans in the container read the project file and that copy
together, and the copy wins for the same entry. The copy is local and git-ignored, so CI and
other checkouts never see it: move its contents into `.aitriage-baseline.json` or
`.aitriage-suppressions.json` at the project root and commit that file. The host CLI
(`aitriage baseline create .`, `aitriage ignore add`) writes those files directly.

A baseline records findings from every scanner that ran when it was created: the built-in
engine, Semgrep, Trivy, Gitleaks, Bandit, and the NFR and deploy checks. Network findings are
never baselined. `aitriage baseline create` runs on the host, so it records Semgrep, Trivy,
Gitleaks and Bandit findings only where those tools are installed locally.

For a legacy codebase adopting AITriage, `aitriage baseline create .` is usually the right
first move: it keeps every finding visible in reports while the gate judges only new work.

### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | The gate passed, or no gate applies |
| `1` | The security gate failed. Usage errors and setup problems caught before the run starts (Docker not running) also exit `1` |
| `2` | `aitriage agent` could not complete the audit: no usable LLM provider, a provider failure (rejected key, rate limit, timeout) or replies that classify nothing (empty, malformed, or only rejected verdicts), a required scanner that did not run in the container, or a report that could not be written. Re-run once the cause is fixed |

A provider failure no longer discards the run. When triage is cut short, AITriage still writes
every report: `triage-findings.json` records `triage_status: failed` and the reason, the
summary, report and fix spec open with a banner, and findings left without a verdict are marked
`triage-failed`. The gate then fails with `triage_incomplete` under every `fail_on` except
`never`, so an outage cannot turn the check green. A failure in an optional stage (PoC traces,
the report or fix-spec narrative) falls back to a deterministic rendering, is noted in the
summary, and leaves the exit code to the gate.

### Controlling AI cost

Deterministic scanning, the security score, the gate verdict and every report format cost
nothing — they need no LLM at all. Only triage, PoC reasoning and the written narrative use
a provider.

| Lever | Effect |
| :--- | :--- |
| Verdict cache | A re-run of the same findings reuses stored verdicts, and the report prints the reuse percentage. On for local `agent`, Web and AI IDE runs (`aitriage-reports/cache/`); in the GitHub Action, set the `verdict-cache-dir` input |
| `AITRIAGE_GATING=on` | Send only CRITICAL/HIGH findings to the LLM. The rest get a deterministic `Needs Manual Review` — never an automatic dismissal. Set it where the scope variables above go |
| `AITRIAGE_BATCH_SIZE` | Findings per request (default 40; `llm.batch_size` in `.aitriage.yaml`). Larger batches cost fewer round trips, but weaker models drop items from long requests; a reply that cannot be parsed or misses more than a quarter of its findings is retried in halves |
| `AITRIAGE_CLASSIFY_RETRIES` | Extra passes for findings the model left without a verdict (default 2). What is still left is `Needs Manual Review (unclassified)`, counted separately in the summary together with the retries and batch size used |
| Provider choice | Cost depends on the model, and so do the verdicts (see [the gate](#why-the-gate-can-fail-with-nothing-confirmed)): pick one model deliberately and keep it pinned |

If no provider key is set, Web still scans, scores, applies the policy and generates every
report format. The AI panels report that they are offline instead of failing the run.

## Safety contract

- A full run fails closed if Docker or any required scanner cannot run.
- Every report records whether each scanner completed or was deterministically not applicable.
- The source tree is mounted read-only inside the scanner container; only `aitriage-reports/` is writable there.
- MCP tools are confined to the opened repository root and real subdirectories; traversal and symlink escapes are rejected.
- AITriage supplies the canonical SecureCoder prompts. The host agent must not replace them with an ad-hoc review.
- No source change is authorized by a scan. The user chooses whether and what to fix.

## Troubleshooting

| Problem | Action |
| :--- | :--- |
| Docker is absent or stopped | Follow the official URL printed by `aitriage setup --full`, start Docker, then repeat the same command |
| Runtime is incomplete after an upgrade | Run `aitriage setup --repair`, then `aitriage setup --status` |
| An AI IDE cannot see AITriage | Re-run the matching connector from the repository root and open a new task/session |
| Claude shows MCP approval pending | Open Claude Code in the project and approve the local `aitriage` server |
| Cursor / Antigravity / VS Code shows nothing, or the agent improvises | The connector only writes the config; enable the `aitriage` server and approve its tools in the IDE UI, then open a new session. These clients have no scriptable approval |
| A real subdirectory is rejected | Reconnect from the intended repository root; paths outside it and symlink escapes are deliberately blocked |
| The agent ran only `aitriage scan` | Ask it to use the AITriage MCP workflow; raw scan is not AI triage |
| Web AI is unavailable | Export a supported provider API key before starting Web |
| Full audit failed | Keep the error visible and repair the runtime; do not present a reduced scan as the final verdict |
| `aitriage agent` exited `2` | The audit did not complete. If `triage-findings.json` says `triage_status: failed`, its reason names the provider error (key, rate limit, timeout): re-run when the provider is available. If `manifest.json` shows a scanner as missing or failed, repair the runtime |
| Many findings are `Needs Manual Review (unclassified)` | The model returned no verdict for them. Re-run, raise `AITRIAGE_CLASSIFY_RETRIES` or lower `AITRIAGE_BATCH_SIZE` |
| Semgrep findings in a large file come and go between runs | Semgrep stops analysing a file after repeated rule timeouts, and timeouts depend on machine load. The summary names the files Semgrep analysed only partly, and `manifest.json` lists them under `scanners[].partial_files` with the reason (`timeout`, `parse_error`, `error`). If such a file is generated, exclude it with `ignore.paths` |
| A warning says an `ignore.paths` pattern no longer excludes a path | Patterns use `.gitignore` syntax now. Add the suggested entry if the path should stay out of scope |
| A dismissed finding still fails CI | Commit `.aitriage-suppressions.json`. A dismissal made in the Web UI or an AI IDE under the container runtime sits in `aitriage-reports/suppressions/…` until you move it into that file. `aitriage agent` applies the file; the raw `aitriage scan` does not |

## Project documentation

- [Configuration example](.aitriage.yaml.example)
- [Security rules](rules/README.md)
- [GitHub Actions examples](examples/github-actions/)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
