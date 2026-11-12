package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// This file wires the AITriage MCP server into the two mandatory AI clients for
// safe-profile installs — Codex (~/.codex/config.toml) and Claude Code (project .mcp.json).
//
// Both installers are idempotent: running them again updates the existing entry
// (install == update), and they never rewrite unrelated parts of the user's
// config. --uninstall removes only the aitriage entry.
//
// Every wiring uses the safe profile: a read-only tool set confined to
// the project directory, launched over stdio, with no remote endpoint and no
// AITriage-owned LLM token.

const (
	mcpServerName         = "aitriage"
	agentContractBegin    = "<!-- AITRIAGE:BEGIN -->"
	agentContractEnd      = "<!-- AITRIAGE:END -->"
	agentContractHeading  = "# AITriage Security Contract"
	reportsGitignoreEntry = "/aitriage-reports/"
)

var (
	clientUninstall bool
)

var installCodexCmd = &cobra.Command{
	Use:   "install-codex [project-path]",
	Short: "Install the AITriage MCP server into Codex (project-local .codex/config.toml)",
	Long: `Wire AITriage into Codex as a local stdio MCP server using the safe
profile (read-only tools, scans confined to the project directory).

Writes a project-scoped <project>/.codex/config.toml (NOT the global
~/.codex/config.toml), so each project keeps its own scan-root and one project's
server is never exposed to another. Codex loads this config only for projects
you have trusted.

Idempotent: re-running updates the existing entry. Use --uninstall to remove it.`,
	Example: `  aitriage install-codex
  aitriage install-codex ./my-project
  aitriage install-codex --uninstall`,
	RunE: runInstallCodex,
}

var installClaudeCodeCmd = &cobra.Command{
	Use:   "install-claude-code [project-path]",
	Short: "Install the AITriage MCP server into Claude Code (local scope, project-scoped)",
	Long: `Wire AITriage into Claude Code as a local stdio MCP server using the safe
profile (read-only tools, scans confined to the project directory).

Primary path: if the 'claude' CLI is on PATH, runs
'claude mcp add --scope local' so the server is recorded in your ~/.claude.json
for this project and is immediately usable (no "Pending approval").

Fallback: if the 'claude' CLI is not found, writes a project-scoped .mcp.json and
tells you the server will show as "Pending approval" until you run 'claude' in
the project and approve it. No trust/approval state is faked.

Idempotent: re-running updates the existing entry. Use --uninstall to remove it.`,
	Example: `  aitriage install-claude-code
  aitriage install-claude-code ./my-project
  aitriage install-claude-code --uninstall`,
	RunE: runInstallClaudeCode,
}

func init() {
	rootCmd.AddCommand(installCodexCmd)
	rootCmd.AddCommand(installClaudeCodeCmd)
	installCodexCmd.Flags().BoolVar(&clientUninstall, "uninstall", false, "Remove the AITriage entry instead of installing it")
	installClaudeCodeCmd.Flags().BoolVar(&clientUninstall, "uninstall", false, "Remove the AITriage entry instead of installing it")
	installCodexCmd.Flags().StringVar(&clientRuntime, "runtime", "container", "MCP server runtime: container (default, full scanner bundle) or native (development only)")
	installClaudeCodeCmd.Flags().StringVar(&clientRuntime, "runtime", "container", "MCP server runtime: container (default, full scanner bundle) or native (development only)")
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// resolveProjectRoot returns the CANONICAL absolute path of the project
// directory (args[0] or the current directory) after verifying it exists and is
// a directory.
//
// The path is resolved through filepath.EvalSymlinks so it matches the canonical
// form clients use: e.g. Codex canonicalises /var/… to /private/var/… on macOS
// and stores project trust under that canonical path. If we wrote the config or
// scan-root under the un-resolved path, Codex would treat the project as
// untrusted and ignore its .codex/config.toml entirely.
func resolveProjectRoot(args []string) (string, error) {
	p := "."
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		p = args[0]
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("project path %q is not accessible: %w", p, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("project path %q is not a directory", p)
	}
	return resolved, nil
}

// clientRuntime selects where the MCP server runs: "container" (the verified
// full scanner bundle, default) or "native" (explicit development opt-in).
var clientRuntime string

// safeProfileArgs are the `aitriage serve` arguments that launch the safe
// profile confined to scanRoot, in the selected runtime.
func safeProfileArgs(scanRoot string) []string {
	rt := clientRuntime
	if rt == "" {
		rt = "container"
	}
	return []string{"serve", "--runtime", rt, "--profile", "safe", "--scan-root", scanRoot}
}

func validateClientRuntime() error {
	if clientRuntime == "" {
		clientRuntime = "container"
	}
	if clientRuntime != "container" && clientRuntime != "native" {
		return fmt.Errorf("unsupported MCP runtime %q: use container or native", clientRuntime)
	}
	return nil
}

func aitriageBinaryPath() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine binary path: %w", err)
	}
	return bin, nil
}

// writeFilePreservingMode writes data to path. If the file already exists its
// permission bits are preserved; otherwise defaultMode is used.
func writeFilePreservingMode(path string, data []byte, defaultMode os.FileMode) error {
	mode := defaultMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func ensureGitignoreEntry(root, entry string) (bool, error) {
	path := filepath.Join(root, ".gitignore")
	existing, err := readFileOrEmpty(path)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(existing, "\n") {
		if strings.TrimSpace(line) == entry {
			return false, nil
		}
	}
	updated := strings.TrimRight(existing, "\n")
	if updated != "" {
		updated += "\n"
	}
	updated += entry + "\n"
	return true, writeFilePreservingMode(path, []byte(updated), 0o644)
}

// syncAgentContract installs or removes AITriage's managed instruction block
// without overwriting any project-owned instructions. A pre-existing unmanaged
// AITriage contract (for example, one created by `aitriage init`) is accepted as
// authoritative and is never duplicated or removed by the client installer.
func syncAgentContract(root, filename, contract string, uninstall bool) (bool, error) {
	path := filepath.Join(root, filename)
	existing, err := readFileOrEmpty(path)
	if err != nil {
		return false, err
	}
	start := strings.Index(existing, agentContractBegin)
	end := strings.Index(existing, agentContractEnd)

	if uninstall {
		if start < 0 || end < start {
			return false, nil
		}
		end += len(agentContractEnd)
		prefix := strings.TrimRight(existing[:start], "\n")
		suffix := strings.TrimLeft(existing[end:], "\n")
		updated := prefix
		if updated != "" && suffix != "" {
			updated += "\n\n"
		}
		updated += suffix
		if updated != "" {
			updated = ensureTrailingNewline(updated)
			return true, writeFilePreservingMode(path, []byte(updated), 0o644)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	}

	managed := agentContractBegin + "\n" + strings.TrimSpace(contract) + "\n" + agentContractEnd
	if start >= 0 {
		if end < start {
			return false, fmt.Errorf("%s contains an incomplete AITriage managed block", path)
		}
		end += len(agentContractEnd)
		updated := existing[:start] + managed + existing[end:]
		updated = ensureTrailingNewline(updated)
		if updated == existing {
			return false, nil
		}
		return true, writeFilePreservingMode(path, []byte(updated), 0o644)
	}
	if strings.Contains(existing, agentContractHeading) {
		return false, nil
	}
	updated := managed + "\n"
	if strings.TrimSpace(existing) != "" {
		updated = strings.TrimRight(existing, "\n") + "\n\n" + updated
	}
	return true, writeFilePreservingMode(path, []byte(updated), 0o644)
}

// ── Codex (TOML) ────────────────────────────────────────────────────────────

// codexConfigPath returns the project-scoped Codex config for projectRoot.
//
// Codex loads project-scoped `<project>/.codex/config.toml` only for trusted
// projects, and mcp_servers is not among the keys a project config is forbidden
// to set. Writing here (rather than the global ~/.codex/config.toml) keeps each
// project's safe scan-root isolated — installing for a second project
// cannot overwrite the first or expose one project's MCP to another.
func codexConfigPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".codex", "config.toml")
}

func runInstallCodex(cmd *cobra.Command, args []string) error {
	root, err := resolveProjectRoot(args)
	if err != nil {
		return err
	}
	configPath := codexConfigPath(root)
	existing, err := readFileOrEmpty(configPath)
	if err != nil {
		return err
	}

	if clientUninstall {
		updated := tomlRemoveServer(existing, mcpServerName)
		configChanged := updated != existing
		if configChanged {
			if err := writeFilePreservingMode(configPath, []byte(updated), 0o600); err != nil {
				return err
			}
		}
		// Keep the shared AGENTS.md contract if Cursor or Antigravity is still
		// connected here — they read the same file and would lose their contract.
		contractShared := agentsMdSiblingInstalled(root, "codex")
		contractChanged := false
		if !contractShared {
			contractChanged, err = syncAgentContract(root, "AGENTS.md", agentsMdContent, true)
			if err != nil {
				return err
			}
		}
		if !configChanged && !contractChanged {
			if contractShared {
				fmt.Printf("Removed nothing: another client still uses the shared AGENTS.md here.\n")
			} else {
				fmt.Printf("AITriage was not present in %s or AGENTS.md — nothing to remove.\n", root)
			}
			return nil
		}
		if contractShared {
			fmt.Printf("✅ Removed AITriage from Codex config. Kept AGENTS.md — another client still uses it: %s\n", root)
		} else {
			fmt.Printf("✅ Removed AITriage from Codex config and managed AGENTS.md instructions: %s\n", root)
		}
		return nil
	}
	if err := validateClientRuntime(); err != nil {
		return err
	}

	bin, err := aitriageBinaryPath()
	if err != nil {
		return err
	}

	block := codexServerBlock(mcpServerName, bin, safeProfileArgs(root))
	updated := tomlSetServer(existing, mcpServerName, block)
	if err := writeFilePreservingMode(configPath, []byte(updated), 0o600); err != nil {
		return err
	}
	if _, err := syncAgentContract(root, "AGENTS.md", agentsMdContent, false); err != nil {
		return fmt.Errorf("install Codex agent instructions: %w", err)
	}
	if _, err := ensureGitignoreEntry(root, reportsGitignoreEntry); err != nil {
		return fmt.Errorf("ignore AITriage reports: %w", err)
	}

	fmt.Printf("✅ AITriage wired into Codex (safe profile) at:\n   %s\n", configPath)
	fmt.Printf("   scan root: %s\n", root)
	fmt.Printf("   agent contract: %s\n", filepath.Join(root, "AGENTS.md"))
	fmt.Println("   Codex loads this config only for TRUSTED projects — trust this project in Codex,")
	fmt.Println("   then ask it to run an AITriage scan to verify.")
	return nil
}

// codexServerBlock renders a Codex [mcp_servers.<name>] TOML section.
func codexServerBlock(name, command string, args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = tomlQuote(a)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "[mcp_servers.%s]\n", name)
	fmt.Fprintf(&sb, "command = %s\n", tomlQuote(command))
	fmt.Fprintf(&sb, "args = [%s]\n", strings.Join(quoted, ", "))
	// Project config must explicitly re-enable the server. Otherwise an older
	// user-level entry with `enabled = false` wins through config merging and the
	// freshly installed project-local server remains disabled.
	sb.WriteString("enabled = true\n")
	return sb.String()
}

func tomlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// tomlSetServer removes any existing [mcp_servers.<name>] section (and its
// subtables) and appends block, preserving all other content verbatim.
func tomlSetServer(existing, name, block string) string {
	base := tomlRemoveServer(existing, name)
	base = strings.TrimRight(base, "\n")
	if base == "" {
		return ensureTrailingNewline(block)
	}
	return base + "\n\n" + ensureTrailingNewline(block)
}

// tomlRemoveServer drops the [mcp_servers.<name>] section and any
// [mcp_servers.<name>.*] subtables, leaving everything else untouched.
func tomlRemoveServer(existing, name string) string {
	if existing == "" {
		return ""
	}
	lines := strings.Split(existing, "\n")
	var out []string
	skipping := false
	for _, line := range lines {
		if isTomlHeader(line) {
			hdr := tomlHeaderName(line)
			skipping = isServerSection(hdr, name)
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func isTomlHeader(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "[")
}

// tomlHeaderName extracts the dotted key of a header line, e.g.
// "[mcp_servers.aitriage]" -> "mcp_servers.aitriage".
func tomlHeaderName(line string) string {
	t := strings.TrimSpace(line)
	t = strings.TrimPrefix(t, "[[")
	t = strings.TrimPrefix(t, "[")
	t = strings.TrimSuffix(t, "]]")
	t = strings.TrimSuffix(t, "]")
	return strings.TrimSpace(t)
}

func isServerSection(headerName, server string) bool {
	target := "mcp_servers." + server
	return headerName == target || strings.HasPrefix(headerName, target+".")
}

// ── Claude Code (JSON) ──────────────────────────────────────────────────────

func runInstallClaudeCode(cmd *cobra.Command, args []string) error {
	root, err := resolveProjectRoot(args)
	if err != nil {
		return err
	}
	if !clientUninstall {
		if err := validateClientRuntime(); err != nil {
			return err
		}
	}

	// Preferred path: the official `claude mcp add --scope local` flow. It records
	// the server in the user's own ~/.claude.json keyed to this project, so it is
	// immediately usable — no "Pending approval" and no trust bypass. We only take
	// this path when the `claude` binary is actually present.
	if claudeBin, lookErr := exec.LookPath("claude"); lookErr == nil {
		return installClaudeCodeViaCLI(claudeBin, root)
	}

	// Fallback: no `claude` binary on PATH. Write a project-scoped .mcp.json and
	// tell the truth — Claude Code will list it as "Pending approval" until the
	// user runs `claude` in the project and approves it. We do NOT claim it is
	// connected, and we do not fake approval via settings.json (that is ignored
	// for checked-in files in untrusted folders as of Claude Code v2.1.196).
	return installClaudeCodeViaMcpJSON(root)
}

// installClaudeCodeViaCLI shells out to `claude mcp add/remove` at local scope.
// Errors from the CLI are surfaced to the user, never masked as success.
func installClaudeCodeViaCLI(claudeBin, root string) error {
	if clientUninstall {
		out, err := runClaudeMCP(claudeBin, root, "mcp", "remove", "--scope", "local", mcpServerName)
		if err != nil {
			return fmt.Errorf("claude mcp remove failed: %w\n%s", err, out)
		}
		if _, err := syncAgentContract(root, "CLAUDE.md", claudeMdContent, true); err != nil {
			return err
		}
		fmt.Printf("✅ Removed AITriage from Claude Code (local scope) for:\n   %s\n", root)
		return nil
	}
	bin, err := aitriageBinaryPath()
	if err != nil {
		return err
	}
	// Remove any prior entry first so re-running is an idempotent update.
	_, _ = runClaudeMCP(claudeBin, root, "mcp", "remove", "--scope", "local", mcpServerName)

	addArgs := []string{"mcp", "add", "--scope", "local", mcpServerName, "--", bin}
	addArgs = append(addArgs, safeProfileArgs(root)...)
	out, err := runClaudeMCP(claudeBin, root, addArgs...)
	if err != nil {
		return fmt.Errorf("claude mcp add failed: %w\n%s", err, out)
	}
	if _, err := syncAgentContract(root, "CLAUDE.md", claudeMdContent, false); err != nil {
		return fmt.Errorf("install Claude Code agent instructions: %w", err)
	}
	if _, err := ensureGitignoreEntry(root, reportsGitignoreEntry); err != nil {
		return fmt.Errorf("ignore AITriage reports: %w", err)
	}

	fmt.Printf("✅ AITriage wired into Claude Code (safe profile, local scope):\n   %s\n", root)
	fmt.Printf("   scan root: %s\n", root)
	fmt.Println("   Verify with: claude mcp get aitriage  (should be connected, not Pending)")
	return nil
}

// installClaudeCodeViaMcpJSON is the fallback used when the `claude` CLI is not
// available. It manages a project-scoped .mcp.json and is honest about the
// required manual approval step.
func installClaudeCodeViaMcpJSON(root string) error {
	mcpPath := filepath.Join(root, ".mcp.json")
	mcpData, err := readBytesOrEmpty(mcpPath)
	if err != nil {
		return err
	}

	if clientUninstall {
		updated, changed, err := jsonRemoveServer(mcpData, mcpServerName)
		if err != nil {
			return err
		}
		if changed {
			if err := writeFilePreservingMode(mcpPath, updated, 0o644); err != nil {
				return err
			}
		}
		contractChanged, err := syncAgentContract(root, "CLAUDE.md", claudeMdContent, true)
		if err != nil {
			return err
		}
		if !changed && !contractChanged {
			fmt.Printf("AITriage was not present in %s or CLAUDE.md — nothing to remove.\n", root)
			return nil
		}
		fmt.Printf("✅ Removed AITriage from %s and managed CLAUDE.md instructions\n", mcpPath)
		return nil
	}

	bin, err := aitriageBinaryPath()
	if err != nil {
		return err
	}
	entry := map[string]any{
		"command": bin,
		"args":    safeProfileArgs(root),
		"env":     map[string]any{},
	}
	updated, err := jsonSetServer(mcpData, mcpServerName, entry)
	if err != nil {
		return err
	}
	if err := writeFilePreservingMode(mcpPath, updated, 0o644); err != nil {
		return err
	}
	if _, err := syncAgentContract(root, "CLAUDE.md", claudeMdContent, false); err != nil {
		return fmt.Errorf("install Claude Code agent instructions: %w", err)
	}
	if _, err := ensureGitignoreEntry(root, reportsGitignoreEntry); err != nil {
		return fmt.Errorf("ignore AITriage reports: %w", err)
	}

	fmt.Printf("⚠️  Wrote AITriage to %s, but it is NOT yet active.\n", mcpPath)
	fmt.Printf("   scan root: %s\n", root)
	fmt.Println("   The `claude` CLI was not found on PATH, so the server could not be approved")
	fmt.Println("   automatically. Claude Code will show it as \"Pending approval\".")
	fmt.Println("   To activate: run `claude` in this project and approve the aitriage server,")
	fmt.Println("   or install the Claude Code CLI and re-run this command.")
	fmt.Println("   Note: .mcp.json contains machine-specific paths; add it to .gitignore if the repo is shared.")
	return nil
}

// runClaudeMCP runs the claude CLI with cwd set to root (so local scope keys to
// this project) and returns combined output.
func runClaudeMCP(claudeBin, root string, args ...string) (string, error) {
	c := exec.Command(claudeBin, args...)
	c.Dir = root
	out, err := c.CombinedOutput()
	return string(out), err
}

// jsonSetServer inserts/updates mcpServers.<name> = entry, preserving all other
// servers and top-level keys. Empty input yields a fresh document.
func jsonSetServer(existing []byte, name string, entry map[string]any) ([]byte, error) {
	return jsonSetServerWithKey(existing, "mcpServers", name, entry)
}

// jsonRemoveServer deletes mcpServers.<name>. The returned bool reports whether
// the entry existed.
func jsonRemoveServer(existing []byte, name string) ([]byte, bool, error) {
	return jsonRemoveServerWithKey(existing, "mcpServers", name)
}

// jsonSetServerWithKey is jsonSetServer generalised over the top-level servers
// key. Most MCP clients (Cursor, Antigravity, Claude Desktop) nest servers under
// "mcpServers"; VS Code uses "servers". Everything else about the document is
// preserved verbatim, so unrelated servers and top-level keys survive.
func jsonSetServerWithKey(existing []byte, serversKey, name string, entry map[string]any) ([]byte, error) {
	doc, err := decodeJSONObject(existing)
	if err != nil {
		return nil, err
	}
	servers, _ := doc[serversKey].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers[name] = entry
	doc[serversKey] = servers
	return encodeJSON(doc)
}

// jsonRemoveServerWithKey deletes <serversKey>.<name>. The returned bool reports
// whether the entry existed.
func jsonRemoveServerWithKey(existing []byte, serversKey, name string) ([]byte, bool, error) {
	doc, err := decodeJSONObject(existing)
	if err != nil {
		return nil, false, err
	}
	servers, _ := doc[serversKey].(map[string]any)
	if servers == nil {
		return existing, false, nil
	}
	if _, ok := servers[name]; !ok {
		return existing, false, nil
	}
	delete(servers, name)
	doc[serversKey] = servers
	out, err := encodeJSON(doc)
	return out, true, err
}

// ── small IO/JSON utilities ─────────────────────────────────────────────────

func readFileOrEmpty(path string) (string, error) {
	b, err := readBytesOrEmpty(path)
	return string(b), err
}

func readBytesOrEmpty(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// decodeJSONObject parses a JSON object, treating empty/whitespace input as {}.
func decodeJSONObject(data []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("existing config is not valid JSON: %w", err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

func encodeJSON(doc map[string]any) ([]byte, error) {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
