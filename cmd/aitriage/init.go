package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/spf13/cobra"
)

var (
	initCI        bool
	initPreCommit bool
	initMCP       bool
	initForce     bool
)

var initCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Initialize AITriage in a project — generates config, CI workflow, and IDE integration",
	Long: `Detects your technology stack and generates:
  • .aitriage.yaml — tuned for your stack
  • .aitriageignore — extra excludes in .gitignore syntax (minified bundles, source maps, coverage)
  • .cursor/rules/aitriage.mdc + CLAUDE.md + AGENTS.md — IDE / AI-agent integration

Optional:
  --ci          Generate GitHub Actions workflow
  --pre-commit  Install git pre-commit hook
  --mcp         Wire the safe MCP server into Codex and Claude Code (this project)`,
	Example: `  aitriage init
  aitriage init --ci --pre-commit
  aitriage init ./my-project --mcp`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().BoolVar(&initCI, "ci", false, "Generate GitHub Actions workflow (.github/workflows/aitriage.yml)")
	initCmd.Flags().BoolVar(&initPreCommit, "pre-commit", false, "Install git pre-commit hook")
	initCmd.Flags().BoolVar(&initMCP, "mcp", false, "Wire the safe MCP server into Codex and Claude Code for this project")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing files")
}

// ── Stack Detection (lightweight, no workspace needed) ───────────────────────

type detectedStack struct {
	Name       string
	Confidence int // 0-100
}

func detectStacksLightweight(projectPath string) []detectedStack {
	var stacks []detectedStack
	scores := map[string]int{}

	// Check package.json
	if data, err := os.ReadFile(filepath.Join(projectPath, "package.json")); err == nil {
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			allDeps := make(map[string]bool)
			for k := range pkg.Dependencies {
				allDeps[k] = true
			}
			for k := range pkg.DevDependencies {
				allDeps[k] = true
			}
			if allDeps["next"] {
				scores["nextjs"] += 100
			}
			if allDeps["express"] {
				scores["express"] += 100
			}
			if allDeps["react"] && !allDeps["next"] {
				scores["react"] += 80
			}
		}
	}

	// Check Python
	for _, pyfile := range []string{"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"} {
		if data, err := os.ReadFile(filepath.Join(projectPath, pyfile)); err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "fastapi") {
				scores["fastapi"] += 100
			}
			if strings.Contains(content, "django") {
				scores["django"] += 100
			}
			if strings.Contains(content, "flask") {
				scores["flask"] += 100
			}
		}
	}
	if _, err := os.Stat(filepath.Join(projectPath, "manage.py")); err == nil {
		scores["django"] += 90
	}

	// Check Go
	if _, err := os.Stat(filepath.Join(projectPath, "go.mod")); err == nil {
		scores["go"] += 100
	}

	// Check .NET
	entries, _ := os.ReadDir(projectPath)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".csproj") || strings.HasSuffix(e.Name(), ".sln") {
			scores["aspnetcore"] += 80
			break
		}
	}

	// Check Docker
	if _, err := os.Stat(filepath.Join(projectPath, "Dockerfile")); err == nil {
		scores["docker"] += 100
	}
	if _, err := os.Stat(filepath.Join(projectPath, "docker-compose.yaml")); err == nil {
		scores["docker"] += 80
	}
	if _, err := os.Stat(filepath.Join(projectPath, "docker-compose.yml")); err == nil {
		scores["docker"] += 80
	}

	for name, score := range scores {
		if score >= 50 {
			stacks = append(stacks, detectedStack{Name: name, Confidence: score})
		}
	}

	return stacks
}

// ── File Generation ──────────────────────────────────────────────────────────

func runInit(cmd *cobra.Command, args []string) error {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	cyan := "\033[38;2;0;245;255m"
	text := "\033[38;2;220;228;228m"
	green := "\033[38;2;46;204;113m"
	dim := "\033[38;2;132;148;149m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "\n%s%s  ╔═══════════════════════════════════════════╗%s\n", cyan, bold, reset)
	fmt.Fprintf(os.Stderr, "%s%s  ║       AITriage — Project Setup Wizard     ║%s\n", cyan, bold, reset)
	fmt.Fprintf(os.Stderr, "%s%s  ╚═══════════════════════════════════════════╝%s\n\n", cyan, bold, reset)

	// Step 1: Detect stacks
	fmt.Fprintf(os.Stderr, "%s  Detecting project structure...%s\n", text, reset)
	stacks := detectStacksLightweight(projectPath)

	if len(stacks) == 0 {
		fmt.Fprintf(os.Stderr, "%s  ⦿ No specific framework detected — using universal rules%s\n", dim, reset)
	} else {
		for _, s := range stacks {
			icon := "✓"
			if s.Confidence >= 100 {
				icon = "◉"
			}
			fmt.Fprintf(os.Stderr, "%s  %s Found: %s%s%s\n", green, icon, bold, s.Name, reset)
		}
	}
	fmt.Fprintln(os.Stderr)

	created := 0

	// Step 2: Generate .aitriage.yaml
	if err := writeIfNotExists(projectPath, ".aitriage.yaml", generateAitrageConfig(stacks), &created); err != nil {
		return err
	}

	// Step 3: Generate .aitriageignore
	if err := writeIfNotExists(projectPath, ".aitriageignore", generateIgnoreFile(), &created); err != nil {
		return err
	}

	// Step 4: IDE / AI-agent integration.
	// Each file is written only if absent (unless --force), so we never clobber a
	// user's existing agent instructions.
	if err := writeIfNotExists(projectPath, filepath.Join(".cursor", "rules", "aitriage.mdc"), cursorRuleMDCContent, &created); err != nil {
		return err
	}
	if err := writeIfNotExists(projectPath, "CLAUDE.md", claudeMdContent, &created); err != nil {
		return err
	}
	if err := writeIfNotExists(projectPath, "AGENTS.md", agentsMdContent, &created); err != nil {
		return err
	}

	// Step 5: CI workflow (--ci flag)
	if initCI {
		ciDir := filepath.Join(projectPath, ".github", "workflows")
		if err := os.MkdirAll(ciDir, 0755); err != nil {
			return fmt.Errorf("failed to create workflows dir: %w", err)
		}
		ciPath := filepath.Join(ciDir, "aitriage.yml")
		if err := writeIfNotExistsAbs(ciPath, generateCIWorkflow(), &created); err != nil {
			return err
		}
	}

	// Step 6: Pre-commit hook (--pre-commit flag)
	if initPreCommit {
		if err := installPreCommitHook(projectPath, &created); err != nil {
			fmt.Fprintf(os.Stderr, "  %s⚠ Pre-commit hook: %v%s\n", dim, err, reset)
		}
	}

	// Step 7: MCP integration (--mcp flag).
	// Wire the safe profile into the two mandatory clients (Codex and
	// Claude Code), scoped to this project. Claude Desktop is intentionally NOT
	// touched here — it has its own `aitriage install-mcp` command.
	//
	// --mcp explicitly requests both clients, so a failure of either is a real
	// failure: we report it and make `init` exit non-zero rather than printing a
	// green "initialized" over a broken setup.
	var mcpErrs []string
	if initMCP {
		prevUninstall := clientUninstall
		clientUninstall = false
		if err := runInstallCodex(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗ Codex MCP setup failed: %v%s\n", dim, err, reset)
			mcpErrs = append(mcpErrs, fmt.Sprintf("codex: %v", err))
		}
		if err := runInstallClaudeCode(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗ Claude Code MCP setup failed: %v%s\n", dim, err, reset)
			mcpErrs = append(mcpErrs, fmt.Sprintf("claude-code: %v", err))
		}
		clientUninstall = prevUninstall
	}

	// Summary
	if len(mcpErrs) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s%s  ⚠ AITriage init partially completed — %d files created, MCP setup FAILED%s\n", dim, bold, created, reset)
		return fmt.Errorf("MCP setup failed for %d client(s): %s", len(mcpErrs), strings.Join(mcpErrs, "; "))
	}
	fmt.Fprintf(os.Stderr, "\n%s%s  ✅ AITriage initialized — %d files created%s\n", green, bold, created, reset)
	fmt.Fprintf(os.Stderr, "%s  Run %saitriage scan .%s to start your first audit.%s\n\n", text, bold, reset, reset)

	return nil
}

func writeIfNotExists(projectPath, filename, content string, count *int) error {
	return writeIfNotExistsAbs(filepath.Join(projectPath, filename), content, count)
}

func writeIfNotExistsAbs(fullPath, content string, count *int) error {
	green := "\033[38;2;46;204;113m"
	dim := "\033[38;2;132;148;149m"
	reset := "\033[0m"

	if _, err := os.Stat(fullPath); err == nil && !initForce {
		fmt.Fprintf(os.Stderr, "  %s⦿ %s (exists, skipped)%s\n", dim, fullPath, reset)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create %s: %w", fullPath, err)
	}
	*count++
	fmt.Fprintf(os.Stderr, "  %s✓ Created %s%s\n", green, fullPath, reset)
	return nil
}

func generateAitrageConfig(stacks []detectedStack) string {
	var sb strings.Builder
	sb.WriteString("# AITriage Configuration\n")
	sb.WriteString("# Generated by: aitriage init\n")
	sb.WriteString("# Docs: https://github.com/dodobrands/aitriage (every key: .aitriage.yaml.example)\n\n")

	// Ignore section. paths starts empty on purpose: git-ignored files and
	// vendored or generated trees are already out of scope for every scanner,
	// and listing them again would keep them excluded even under
	// AITRIAGE_RESPECT_GITIGNORE=false or AITRIAGE_SCAN_VENDORED=true.
	sb.WriteString("ignore:\n")
	sb.WriteString("  # Paths every scanner skips: .gitignore syntax, relative to the project root.\n")
	sb.WriteString("  # Git-ignored files and vendored or generated directories (node_modules, vendor,\n")
	sb.WriteString("  # dist, .next, __pycache__, venv) are skipped already; list only your own.\n")
	sb.WriteString("  # Example: paths: [\"/third_party/\", \"**/*.pb.go\"]\n")
	sb.WriteString("  paths: []\n")
	sb.WriteString("  # Rule IDs dropped from every scanner. Prefix an ID to limit it to one source,\n")
	sb.WriteString("  # e.g. gitleaks:generic-api-key or trivy:CVE-2024-1234.\n")
	sb.WriteString("  # Example: rules: [ENTR-12]  # Suppress God File warnings\n")
	sb.WriteString("  rules: []\n\n")

	// LLM section
	sb.WriteString("# LLM configuration for AI-powered triage (optional)\n")
	sb.WriteString("# Set env var GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY\n")
	sb.WriteString("# Verdicts differ between models, and so does fail_on: confirmed: pin one model.\n")
	sb.WriteString("llm:\n")
	sb.WriteString("  provider: \"\"  # auto-detected from env\n")
	sb.WriteString("  model: \"\"  # empty: " + llm.DefaultGeminiModel + " (gemini), " + llm.DefaultAnthropicModel + " (anthropic), " + llm.DefaultOpenAIModel + " (openai)\n")
	sb.WriteString("  # temperature: 0  # 0 to 2, or default to send none; 0 keeps verdicts repeatable\n\n")

	// CI section
	sb.WriteString("# CI/CD settings\n")
	sb.WriteString("# Legacy compatibility: still supported when health_check is not set\n")
	sb.WriteString("strict_mode: false   # Set true to fail on ANY finding\n")
	sb.WriteString("fail_score: 0        # Fail if Health Check score < this (0 = disabled)\n\n")
	sb.WriteString("# Security policy gate for CI/CD\n")
	sb.WriteString("health_check:\n")
	sb.WriteString("  profile: baseline  # baseline | standard | strict\n")
	sb.WriteString("  fail_on: critical  # critical | any | confirmed (AI-confirmed only, agent) | never\n")
	sb.WriteString("  minimum_score: 0   # 0 = score is informational only\n")
	sb.WriteString("  max_critical: -1   # -1 = unlimited; 0 = block any active finding\n")
	sb.WriteString("  max_high: -1\n")
	sb.WriteString("  max_medium: -1\n")
	sb.WriteString("  block_sources: []  # e.g. [gitleaks]\n")
	sb.WriteString("  block_classes: []  # e.g. [hardcoded-secret]\n")
	sb.WriteString("  # quality_findings: report  # report (default): code-quality findings such as ENTR-12\n")
	sb.WriteString("  #   are reported, not scored or gating; block: scored and gating like any other\n")

	// Detected stacks comment
	if len(stacks) > 0 {
		sb.WriteString("\n# Detected stacks: ")
		names := make([]string, len(stacks))
		for i, s := range stacks {
			names[i] = s.Name
		}
		sb.WriteString(strings.Join(names, ", "))
		sb.WriteString("\n# Rules for these stacks are loaded automatically from the built-in rule engine.\n")
	}

	return sb.String()
}

// generateIgnoreFile returns the starter .aitriageignore. It lists only noise
// that nothing else excludes. Everything .gitignore excludes, and the vendored
// and generated directories, are out of scope already; copying them here would
// keep them excluded even when AITRIAGE_RESPECT_GITIGNORE=false or
// AITRIAGE_SCAN_VENDORED=true asks for them. build/ and lockfiles must stay in
// scope: a committed build/ directory is the project's own code, and Trivy
// reports dependency vulnerabilities against lockfiles such as yarn.lock or
// poetry.lock, so excluding *.lock dropped them from every report.
func generateIgnoreFile() string {
	var sb strings.Builder
	sb.WriteString("# AITriage Ignore File\n")
	sb.WriteString("# Paths every scanner skips, in .gitignore syntax relative to the project root.\n")
	sb.WriteString("# Already out of scope without listing them here: files .gitignore excludes, and\n")
	sb.WriteString("# vendored or generated directories (node_modules, vendor, dist, .next,\n")
	sb.WriteString("# __pycache__, venv). A committed build/ directory is scanned; add it below if\n")
	sb.WriteString("# it only holds build output. Do not exclude lockfiles: Trivy reports\n")
	sb.WriteString("# dependency vulnerabilities against them.\n\n")

	sb.WriteString("# Minified bundles and source maps\n")
	for _, pattern := range []string{"*.min.js", "*.min.css", "*.map"} {
		sb.WriteString(pattern + "\n")
	}
	sb.WriteString("\n# Test coverage output\n")
	sb.WriteString("coverage/\n")

	return sb.String()
}

func generateCIWorkflow() string {
	return `# AITriage Security Scan — GitHub Actions
# Generated by: aitriage init --ci
name: AITriage Security Shield

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  aitriage:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache: true

      - name: Install AITriage
        run: go install github.com/dodobrands/aitriage/cmd/aitriage@latest

      - name: Run Security Scan
        run: aitriage scan ./ --format sarif --out aitriage-results.sarif --fail-on critical

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aitriage-results.sarif
          category: aitriage
`
}

func installPreCommitHook(projectPath string, count *int) error {
	gitDir := filepath.Join(projectPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git directory)")
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return err
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	hookContent := `#!/bin/sh
# AITriage Pre-Commit Security Hook
# Generated by: aitriage init --pre-commit
# Remove this file to disable the hook.

echo "🔒 AITriage: Scanning staged changes for security issues..."
# --staged limits the scan to git-staged files, so the hook stays fast and only
# blocks on what is actually about to be committed.
aitriage scan . --staged --fail-on critical --format terminal 2>&1

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ AITriage found critical security issues in staged changes. Commit blocked."
    echo "   Run 'aitriage scan . --staged' for full details."
    echo "   Use 'git commit --no-verify' to bypass (not recommended)."
    exit 1
fi
`
	if err := writeIfNotExistsAbs(hookPath, hookContent, count); err != nil {
		return err
	}
	// Git hooks MUST be executable
	return os.Chmod(hookPath, 0755)
}

// ── IDE Integration Templates ────────────────────────────────────────────────

// cursorRuleMDCContent is a modern Cursor project rule (.cursor/rules/aitriage.mdc).
// It replaces the deprecated .cursorrules format. It carries NO MCP server block:
// Cursor reads MCP servers from .cursor/mcp.json (written by `aitriage
// install-cursor`), never from a rule file. The rule body reuses the shared
// security contract so there is a single source of truth. `alwaysApply: true`
// keeps the contract in context for every agent request.
const cursorRuleMDCContent = `---
description: AITriage security contract — use AITriage MCP tools for any security review
alwaysApply: true
---

` + agentsMdContent

const claudeMdContent = `# AITriage Security Contract

This project is protected by AITriage. When AITriage is connected as an MCP
server, use its tools (` + "`aitriage_scan`, `aitriage_secrets`, `aitriage_diff`" + `);
otherwise run the ` + "`aitriage`" + ` CLI.

## Full security review (MCP) — two commands

AITriage runs the SAME pipeline as CI (` + "`aitriage agent`" + `); you only answer its
model requests with your own session. Start with ` + "`aitriage_run_start`" + `, NOT the
raw ` + "`aitriage_scan`" + ` (untriaged pre-scan, not a verdict).

- "Проверь проект через AITriage" → intent=audit: full audit, four artifacts +
  gate, STOP at the approval gate, zero source changes.
- "Проверь и исправь подтверждённые уязвимости" → intent=audit_and_fix.

If the user names a nested project, pass its path to ` + "`aitriage_run_start`" + `.
The MCP is configured once at the repository root and allows every directory
inside that root; never ask the user to rewrite MCP config. If the full run
fails, report the failure — never fall back to raw ` + "`aitriage_scan`" + ` and present it
as the requested review.

Set intent only from the user's actual words; a red gate or existing
summary.md/fixspec.md is NOT permission to fix. Answer each request with the same
request_id via ` + "`aitriage_run_submit`" + `. For intent=audit_and_fix, AITriage
records approval before returning fix_context. If the user chooses fixes after a
completed audit, your FIRST action must be ` + "`aitriage_run_approve`" + ` with the
exact selected TP IDs—before planning or editing anything. Proceed only after it
returns status=fixing and fix_context; project drift requires a new audit. Then
open the returned ` + "`summary_path`" + ` and follow its AI Remediation Prompt / Operating Contract; fix
ONLY approved True Positives (never FP or Needs-Manual-Review), run tests, then
call ` + "`aitriage_run_verify`" + `. Verification requires a project change made
after approval. All artifacts live in ` + "`aitriage-reports/`" + `.

## When to run a scan (mandatory)

- Before implementing anything that touches authentication, payments, or
  personal/customer data — scan first to understand the current posture.
- Before every commit and push — scan the staged changes
  (` + "`aitriage scan . --staged`" + `).
- After applying a fix — re-scan to confirm the finding is gone (` + "`aitriage_diff`" + `).

## Hard rules

- Never output plaintext secrets, credentials, connection strings, or wildcard
  CORS. If a secret is detected, stop and remove it — do not commit it.
- Do NOT ignore, suppress, or downgrade any high/critical finding or secret leak
  on your own. Surface it to the human and let them decide.
- Report remediation as concrete, minimal steps ("move the key to an env var,
  rotate the leaked value") — not a general security lecture.

## Verdict format

For each finding, state: what was found → why it is dangerous → what to change →
how to re-verify.
`

// agentsMdContent is the Codex-facing security contract (AGENTS.md). Codex reads
// AGENTS.md the way Claude Code reads CLAUDE.md; the guidance is kept in sync.
const agentsMdContent = `# AITriage Security Contract

This project is protected by AITriage. Call the AITriage MCP tools
(` + "`aitriage_scan`, `aitriage_secrets`, `aitriage_diff`" + `) when connected, or run
the ` + "`aitriage`" + ` CLI otherwise.

## Full security review (MCP) — two commands

AITriage runs the SAME pipeline as CI (` + "`aitriage agent`" + `); you only answer its
model requests with your own session. Start with ` + "`aitriage_run_start`" + `, NOT the
raw ` + "`aitriage_scan`" + ` (untriaged pre-scan, not a verdict).

- "Проверь проект через AITriage" → intent=audit: full audit, four artifacts +
  gate, STOP at approval, zero source changes.
- "Проверь и исправь подтверждённые уязвимости" → intent=audit_and_fix.

If the user names a nested project, pass its path to ` + "`aitriage_run_start`" + `.
The MCP is configured once at the repository root and allows every directory
inside that root; never ask the user to rewrite MCP config. If the full run
fails, report the failure — never fall back to raw ` + "`aitriage_scan`" + ` and present it
as the requested review.

Set intent only from the user's actual words; a red gate or existing
summary.md/fixspec.md is NOT permission to fix. Answer each request with the same
request_id via ` + "`aitriage_run_submit`" + `. For intent=audit_and_fix, AITriage
records approval before returning fix_context. If the user chooses fixes after a
completed audit, your FIRST action must be ` + "`aitriage_run_approve`" + ` with the
exact selected TP IDs—before planning or editing anything. Proceed only after it
returns status=fixing and fix_context; project drift requires a new audit. Then
open the returned ` + "`summary_path`" + ` and follow its AI Remediation Prompt / Operating Contract; fix
ONLY approved True Positives (never FP or Needs-Manual-Review), run tests, then
call ` + "`aitriage_run_verify`" + `. Verification requires a project change made
after approval. All artifacts live in ` + "`aitriage-reports/`" + `.

## When to run a scan (mandatory)

- Before implementing authentication, payments, or personal/customer-data logic.
- Before every commit and push — scan staged changes
  (` + "`aitriage scan . --staged`" + `).
- After a fix — re-scan to confirm it is resolved (` + "`aitriage_diff`" + `).

## Hard rules

- Never emit plaintext secrets, credentials, connection strings, or wildcard CORS.
  If a secret is detected, stop and remove it before committing.
- Do NOT ignore, suppress, or downgrade high/critical findings or secret leaks on
  your own — surface them to the human.
- Give remediation as concrete, minimal steps, not a security lecture.

## Verdict format

what was found → why it is dangerous → what to change → how to re-verify.
`
