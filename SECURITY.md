# Security Policy

AITriage is a security product. We take the security of the tool itself, and of
the environments it runs in, seriously. Thank you for helping keep AITriage and
its users safe.

## Supported Versions

Security fixes are provided for the latest released `v1.x` line and the `main`
branch. Older tags are not patched — please upgrade to the latest release.

| Version | Supported |
| :--- | :--- |
| `v1.x` (latest) | ✅ |
| `main` | ✅ |
| Older tags | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately through one of the following channels:

- **GitHub Security Advisories** — use the *"Report a vulnerability"* button under
  the repository's [Security tab](https://github.com/dodobrands/aitriage/security/advisories/new)
  (preferred).
- If that is unavailable, open a minimal issue asking a maintainer to open a
  private advisory — **without** disclosing any technical detail.

Please include, where possible:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof of concept, affected command or endpoint).
- Affected version(s), OS, and configuration.
- Any suggested remediation.

## Our Commitment

- **Acknowledgement** within **3 business days**.
- **Initial assessment** within **10 business days**.
- We will keep you informed of remediation progress and coordinate a disclosure
  timeline with you. We aim to ship a fix before public disclosure.
- With your permission, we will credit you in the release notes and advisory.

## Scope

In scope:

- The `aitriage` CLI and Go engine (`cmd/`, `internal/`).
- The web dashboard and API server (`internal/server`, `web/`).
- The MCP server (`internal/agent/mcp`) and the project connectors that
  register it (`aitriage install-*`).
- The published Docker image, the GitHub Action (`action.yml`), and the release
  installers (`scripts/install.sh`, `scripts/install.ps1`).

Out of scope:

- Vulnerabilities in third-party scanners AITriage orchestrates
  (Semgrep, Trivy, Gitleaks, Bandit) — report those upstream.
- Findings that require a compromised host, physical access, or a
  self-inflicted misconfiguration outside AITriage's control.
- Reports generated *by* AITriage about *your own* code (those are product
  output, not vulnerabilities in AITriage).

## Handling Secrets

AITriage processes source code that may contain secrets. When filing a report,
**never include real credentials, API keys, or customer data**. Redact or use
synthetic values in any proof of concept.
