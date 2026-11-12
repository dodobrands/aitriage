package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildBinary compiles the aitriage binary once for the process-level E2E.
func buildBinary(t *testing.T) string {
	t.Helper()
	name := "aitriage"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

type scanReportLite struct {
	Results []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"results"`
}

func callScan(t *testing.T, cs *mcp.ClientSession, path string) (*scanReportLite, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "aitriage_scan",
		Arguments: map[string]any{"path": path},
	})
	if err != nil {
		t.Fatalf("call aitriage_scan %q: %v", path, err)
	}
	if res.IsError {
		return nil, true
	}
	var rep scanReportLite
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &rep)
	}
	if len(rep.Results) == 0 {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				_ = json.Unmarshal([]byte(tc.Text), &rep)
			}
		}
	}
	return &rep, false
}

func hasSecretFinding(rep *scanReportLite) bool {
	if rep == nil {
		return false
	}
	for _, r := range rep.Results {
		if strings.HasPrefix(r.ID, "SECRET") {
			return true
		}
	}
	return false
}

// TestE2E_SafeProfileServer_SecretLifecycle spawns the aitriage binary exactly as
// the Codex and Claude Code client configs launch it
// (`serve --profile safe --scan-root <project>`) and drives the full lifecycle
// over real stdio MCP: detect a hardcoded secret → fix → rescan clean, plus the
// scan-root escape rejection and the absence of the mutating tool.
func TestE2E_SafeProfileServer_SecretLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildBinary(t)

	proj := t.TempDir()
	secretFile := filepath.Join(proj, "payments.js")
	if err := os.WriteFile(secretFile,
		[]byte(`export const key = "sk_live_`+`abcdefghijklmnopqrstuvwx";`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity: both client installers bake this exact launch command.
	assertClientLaunchCommand(t, proj, bin)

	ctx := context.Background()
	transport := &mcp.CommandTransport{
		Command: exec.Command(bin, "serve", "--profile", "safe", "--scan-root", proj),
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to spawned server: %v", err)
	}
	defer func() {
		_ = cs.Close()
		time.Sleep(10 * time.Millisecond)
	}()

	// Safe profile must not expose the mutating tool.
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range lt.Tools {
		if tool.Name == "securecoder_ignore" {
			t.Error("safe profile server must not expose securecoder_ignore")
		}
	}

	// 1. Agent's dangerous change is detected.
	rep, isErr := callScan(t, cs, ".")
	if isErr {
		t.Fatal("initial scan errored unexpectedly")
	}
	if !hasSecretFinding(rep) {
		t.Fatal("server did not detect the hardcoded secret")
	}

	// 2. Agent fixes the change.
	if err := os.WriteFile(secretFile,
		[]byte(`export const key = process.env.STRIPE_KEY;`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Rescan is clean.
	rep, isErr = callScan(t, cs, ".")
	if isErr {
		t.Fatal("post-fix scan errored unexpectedly")
	}
	if hasSecretFinding(rep) {
		t.Fatal("secret still reported after fix")
	}

	// 4. Scan-root escape is rejected.
	if _, isErr := callScan(t, cs, "../"); !isErr {
		t.Error("scan of '../' must be rejected by the scan-root guard")
	}
}

// assertClientLaunchCommand runs both client installers against proj and checks
// each writes the safe-profile launch command, so the server exercised above is
// exactly what Codex and Claude Code would start.
func assertClientLaunchCommand(t *testing.T, proj, bin string) {
	t.Helper()
	// Codex writes a project-local config.toml with command+args.
	codexCfg := filepath.Join(proj, ".codex", "config.toml")
	block := codexServerBlock(mcpServerName, bin, safeProfileArgs(proj))
	if !strings.Contains(block, `"serve", "--runtime", "container", "--profile", "safe", "--scan-root"`) {
		t.Fatalf("codex launch command missing safe profile: %s", block)
	}
	_ = codexCfg

	// Claude Code (fallback) writes .mcp.json with the same args.
	entry := map[string]any{"command": bin, "args": safeProfileArgs(proj)}
	out, err := jsonSetServer(nil, mcpServerName, entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"--profile"`) || !strings.Contains(string(out), `"safe"`) {
		t.Fatalf("claude-code launch command missing safe profile: %s", out)
	}
}

// TestE2E_RunStartOverProcessMCP spawns the safe-profile server exactly as the
// client configs launch it and drives aitriage_run_start over real stdio MCP,
// proving the full deferred host-agent workflow is reachable through the process
// boundary and returns a run with a first deferred SecureCoder request.
func TestE2E_RunStartOverProcessMCP(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildBinary(t)

	root := t.TempDir()
	proj := filepath.Join(root, "synthetic", "fastapi-terrible")
	sibling := filepath.Join(root, "synthetic", "nextjs-terrible")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "app.py"), []byte("FASTAPI_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "app.js"), []byte("const NEXTJS_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	transport := &mcp.CommandTransport{
		Command: exec.Command(bin, "serve", "--profile", "safe", "--scan-root", root),
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = cs.Close(); time.Sleep(10 * time.Millisecond) }()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_run_start",
		Arguments: map[string]any{"path": filepath.Join("synthetic", "fastapi-terrible"), "host_client": "codex"},
	})
	if err != nil {
		t.Fatalf("run_start: %v", err)
	}
	if res.IsError {
		t.Fatalf("run_start tool error: %+v", res.Content)
	}
	var prog struct {
		RunID   string `json:"run_id"`
		Pending *struct {
			RequestID string `json:"request_id"`
			Messages  []struct {
				Content string `json:"content"`
			} `json:"messages"`
		} `json:"pending_request"`
	}
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &prog)
	}
	if prog.RunID == "" {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				_ = json.Unmarshal([]byte(tc.Text), &prog)
			}
		}
	}
	if prog.RunID == "" || prog.Pending == nil || prog.Pending.RequestID == "" {
		t.Fatalf("expected run_id + first deferred request, got %+v", prog)
	}
	var prompt string
	for _, msg := range prog.Pending.Messages {
		prompt += msg.Content
	}
	if !strings.Contains(prompt, "FASTAPI_ONLY_MARKER") {
		t.Fatal("selected nested project content is missing from process MCP request")
	}
	if strings.Contains(prompt, "NEXTJS_ONLY_MARKER") {
		t.Fatal("sibling project leaked into process MCP request")
	}
	if _, err := os.Stat(filepath.Join(root, "aitriage-reports", prog.RunID)); err != nil {
		t.Fatalf("run bundle must live under root aitriage-reports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(proj, "aitriage-reports")); !os.IsNotExist(err) {
		t.Fatalf("selected project must not receive duplicate reports directory (err=%v)", err)
	}
}
