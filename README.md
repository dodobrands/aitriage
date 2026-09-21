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
    <a href="#2-ai-ide-codex-or-claude-code"><strong>AI IDE</strong></a> ·
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
If setup returns `action_required`, show me its message, official Docker URL,
and retry command, then stop. Never install Docker from another source.
If setup returns `ok`, run `aitriage setup --status --json` and tell me the
AITriage version, executable path, container image, and status of every bundled
scanner. Do not connect a project or run an audit yet.
```

The result is one host CLI plus one verified Docker image. The source repository is unnecessary for normal use.

### Set up manually on macOS or Linux

Requirements: macOS or Linux, and a running [Docker Desktop or Docker Engine](https://docs.docker.com/get-started/get-docker/).

```bash
curl -fsSL https://github.com/dodobrands/aitriage/releases/latest/download/install.sh | sh
aitriage setup --status
```

The installer downloads the matching official GitHub Release, verifies its
SHA-256 checksum, installs the CLI, and runs `aitriage setup --full`. To inspect
the script before running it:

```bash
curl -fsSLO https://github.com/dodobrands/aitriage/releases/latest/download/install.sh
less install.sh
sh install.sh
```

In a non-interactive environment where the system executable directory needs
administrator approval, the installer falls back to `$HOME/.local/bin` and
prints the exact executable path. Add that directory to `PATH` for future
shells if it is not already present.

Go 1.25.12 or newer remains a developer fallback:

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
| scanner cache | user cache directory | reusable scanner databases; never stored in source |
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
> command line (`claude mcp add`), so it is live right after the connector runs.
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
Проверь этот проект через AITriage. Пока ничего не исправляй.
```

AITriage—not the AI IDE—supplies the SecureCoder prompts, controls the workflow, and creates the final artifacts. The agent returns each model answer to AITriage until triage completes.

When you decide to fix findings, say which ones or explicitly approve all confirmed findings:

```text
Исправь подтверждённые AITriage уязвимости. Не трогай сомнительные находки и
false positives. Запусти тесты и проверь исправления через AITriage.
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

Windsurf is not supported as a first-class connector: it only reads a single global `~/.codeium/windsurf/mcp_config.json`, which cannot keep one project's scan-root isolated from another. Point it at `aitriage serve --profile safe --scan-root <project>` manually if you accept that trade-off.

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

- [`aitriage-security.yml`](examples/github-actions/aitriage-security.yml) — standard security run;
- [`aitriage-pr-gate.yml`](examples/github-actions/aitriage-pr-gate.yml) — pull-request gate;
- [`aitriage-ai-advisor.yml`](examples/github-actions/aitriage-ai-advisor.yml) — AI advisory output;
- [`aitriage-manual-html-report.yml`](examples/github-actions/aitriage-manual-html-report.yml) — manually triggered report.

Copy the selected file to `.github/workflows/`, add the referenced provider key in GitHub Secrets, and run `workflow_dispatch` once. Verify the uploaded reports, SARIF, and post-AI gate before making the check required.

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

`agent` uses the full container scanner bundle by default and runs the same SecureCoder pipeline used by CI. Provider variables include `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GROQ_API_KEY`.

To use a Codex or Claude subscription instead of an API key, use the [AI IDE integration](#2-ai-ide-codex-or-claude-code).

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
│   ├── scan.json             # deterministic input to triage
│   ├── manifest.json         # state, scanner coverage, integrity metadata
│   └── audit.log             # run events
├── history/                  # deterministic scan history
└── web/                      # local Web state
```

Connectors add `/aitriage-reports/` to `.gitignore`. AITriage excludes this directory from every scanner and AI context so its own output cannot trigger another audit loop.

## Scope, cost and the gate verdict

### What is in scope

AITriage audits the application you ship, not everything on disk. By default it skips
files `git` ignores and directories holding third-party or generated code
(`vendor`, `node_modules`, `dist`, `build`, `.next`, `__pycache__`, `venv`). The same
rules apply to the bundled Semgrep, Trivy, Gitleaks and Bandit, and to the git-history
secret scan, so a vendored dependency is never reported as your vulnerability.

| Variable | Effect |
| :--- | :--- |
| `AITRIAGE_RESPECT_GITIGNORE=false` | Audit ignored files too. Use when the question is "did a secret ever reach this working tree", not "is my application vulnerable" |
| `AITRIAGE_SCAN_VENDORED=true` | Audit vendored and generated directories as if they were your own source |
| `.aitriageignore` | Per-project excludes, same syntax as `.gitignore`, always honoured |

Network port probing is opt-in. It reports on the machine AITriage runs on rather than on
the repository, so its findings are never counted in the repository's security score.

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
| `fail_on: confirmed` | Only findings someone confirmed block; unreviewed are reported, not blocking |
| `fail_on: never` | The gate never blocks; the score is informational |
| `aitriage baseline create .` | Accept today's findings as the starting line and gate only on regressions |

A baseline is a property of the project, not of the tool that created it. It lives in
`.aitriage-baseline.json` at the repository root and is available from every surface: the CLI
(`aitriage baseline`), the Web UI (SecureCoder → Baseline) and an AI IDE (`aitriage_baseline`).
A baseline created in one is honoured by the others. Under the MCP safe profile only inspection
is offered, because accepting findings writes to the project.

Today a baseline covers the built-in engine's findings. Results from the bundled Semgrep, Trivy,
Gitleaks and Bandit are not yet baselined.

For a legacy codebase adopting AITriage, `aitriage baseline create .` is usually the right
first move: it keeps every finding visible in reports while the gate judges only new work.

### Controlling AI cost

Deterministic scanning, the security score, the gate verdict and every report format cost
nothing — they need no LLM at all. Only triage, PoC reasoning and the written narrative use
a provider.

| Lever | Effect |
| :--- | :--- |
| Verdict cache (on by default) | A re-run of the same findings reuses stored verdicts. The report prints the reuse percentage |
| `AITRIAGE_GATING=on` | Send only CRITICAL/HIGH findings to the LLM. The rest get a deterministic `Needs Manual Review` — never an automatic dismissal |
| `AITRIAGE_BATCH_SIZE` | Findings per request. Larger batches cost fewer round trips and more tokens per call |
| Provider choice | Triage is classification, not composition. A small fast model is usually the better trade here; reserve a frontier model for narrative quality |

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

## Project documentation

- [Configuration example](.aitriage.yaml.example)
- [Security rules](rules/README.md)
- [GitHub Actions examples](examples/github-actions/)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
