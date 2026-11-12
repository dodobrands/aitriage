package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectClient wires an in-memory MCP client to a safe/full server and
// returns a live client session.
func connectClient(t *testing.T, cfg Config) *mcp.ClientSession {
	t.Helper()
	s, err := NewServerWithConfig("test", cfg)
	if err != nil {
		t.Fatalf("NewServerWithConfig: %v", err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()

	ss, err := s.srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func listToolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

// TestSafeProfileHidesMutatingTool proves the safe profile exposes the
// read-only scan tools but never registers the mutating securecoder_ignore,
// while the full profile does.
func TestSafeProfileHidesMutatingTool(t *testing.T) {
	root := t.TempDir()

	safe := listToolNames(t, connectClient(t, Config{Profile: ProfileSafe, ScanRoot: root}))
	if safe["securecoder_ignore"] {
		t.Error("safe profile must NOT expose securecoder_ignore")
	}
	for _, want := range []string{"aitriage_scan", "aitriage_secrets", "run_securecoder", "run_securecoder_deps"} {
		if !safe[want] {
			t.Errorf("safe profile is missing read-only tool %q", want)
		}
	}

	full := listToolNames(t, connectClient(t, Config{Profile: ProfileFull}))
	if !full["securecoder_ignore"] {
		t.Error("full profile must still expose securecoder_ignore")
	}
}

// TestRunToolsRegisteredInSafeProfile proves the deferred host-agent workflow
// tools are exposed under the safe profile (which has a scan root), and that a
// real aitriage_run_start over MCP scans + starts a run, returning a run_id and
// a first deferred request for a project that has findings.
func TestRunToolsRegisteredInSafeProfile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const k = \"AKIA"+"Z7Q4XWVB3NMK2PLT\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cs := connectClient(t, Config{Profile: ProfileSafe, ScanRoot: root})
	ctx := context.Background()

	names := listToolNames(t, cs)
	for _, want := range []string{
		"aitriage_run_start", "aitriage_run_submit", "aitriage_run_status",
		"aitriage_run_continue", "aitriage_run_approve", "aitriage_run_decline", "aitriage_run_verify",
	} {
		if !names[want] {
			t.Errorf("safe profile is missing run tool %q", want)
		}
	}
	if names["securecoder_ignore"] {
		t.Error("safe profile must still hide the mutating securecoder_ignore")
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_run_start",
		Arguments: map[string]any{"host_client": "codex"},
	})
	if err != nil {
		t.Fatalf("aitriage_run_start: %v", err)
	}
	if res.IsError {
		t.Fatalf("aitriage_run_start returned tool error: %+v", res.Content)
	}
	var prog struct {
		RunID   string `json:"run_id"`
		Status  string `json:"status"`
		Pending *struct {
			RequestID string `json:"request_id"`
		} `json:"pending_request"`
	}
	decodeStructured(t, res, &prog)
	if prog.RunID == "" {
		t.Fatal("aitriage_run_start did not return a run_id")
	}
	if prog.Pending == nil || prog.Pending.RequestID == "" {
		t.Fatalf("expected a first deferred request for a project with findings; status=%s", prog.Status)
	}
}

// TestRunStartSelectsNestedProject proves the intended one-configuration UX:
// the MCP is bound once to a repository root and a full SecureCoder run may
// select any nested project without changing or reloading client config.
func TestRunStartSelectsNestedProject(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "synthetic", "fastapi-terrible")
	sibling := filepath.Join(root, "synthetic", "nextjs-terrible")
	if err := os.MkdirAll(selected, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "app.py"), []byte("FASTAPI_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "app.js"), []byte("const NEXTJS_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cs := connectClient(t, Config{Profile: ProfileSafe, ScanRoot: root})
	ctx := context.Background()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "aitriage_run_start",
		Arguments: map[string]any{
			"path":        filepath.Join("synthetic", "fastapi-terrible"),
			"host_client": "codex",
		},
	})
	if err != nil {
		t.Fatalf("nested aitriage_run_start transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("nested aitriage_run_start returned tool error: %+v", res.Content)
	}
	var prog struct {
		RunID   string `json:"run_id"`
		Status  string `json:"status"`
		Pending *struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		} `json:"pending_request"`
	}
	decodeStructured(t, res, &prog)
	if prog.RunID == "" || prog.Pending == nil {
		t.Fatalf("nested project did not start a full run: status=%s run_id=%q", prog.Status, prog.RunID)
	}
	var prompt string
	for _, msg := range prog.Pending.Messages {
		prompt += msg.Content
	}
	if !strings.Contains(prompt, "FASTAPI_ONLY_MARKER") {
		t.Fatal("selected nested project content is missing from the SecureCoder request")
	}
	if strings.Contains(prompt, "NEXTJS_ONLY_MARKER") {
		t.Fatal("sibling project leaked into the nested-project SecureCoder request")
	}
	if _, err := os.Stat(filepath.Join(root, "aitriage-reports", prog.RunID)); err != nil {
		t.Fatalf("run bundle must live in root aitriage-reports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(selected, "aitriage-reports")); !os.IsNotExist(err) {
		t.Fatalf("selected project must not receive a duplicate reports directory (err=%v)", err)
	}

	escape, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_run_start",
		Arguments: map[string]any{"path": "../"},
	})
	if err != nil {
		t.Fatalf("escape run transport error: %v", err)
	}
	if !escape.IsError {
		t.Error("aitriage_run_start must reject a project outside the configured root")
	}
}

func decodeStructured(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if json.Unmarshal(b, v) == nil {
			return
		}
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if json.Unmarshal([]byte(tc.Text), v) == nil {
				return
			}
		}
	}
	t.Fatalf("could not decode structured result: %+v", res)
}

// TestSafeScanConfinement proves that, end-to-end over MCP, a scan inside
// the root succeeds while a path escaping the root is rejected as a tool error.
func TestSafeScanConfinement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := connectClient(t, Config{Profile: ProfileSafe, ScanRoot: root})
	ctx := context.Background()

	// A scan of the project root (".") succeeds.
	ok, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_scan",
		Arguments: map[string]any{"path": "."},
	})
	if err != nil {
		t.Fatalf("in-root scan transport error: %v", err)
	}
	if ok.IsError {
		t.Fatalf("in-root scan should succeed, got tool error: %+v", ok.Content)
	}

	// A scan that tries to climb out of the root is rejected.
	escape, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_scan",
		Arguments: map[string]any{"path": "../"},
	})
	if err != nil {
		t.Fatalf("escape scan transport error: %v", err)
	}
	if !escape.IsError {
		t.Error("scan of '../' must be rejected by the scan-root guard")
	}
}
