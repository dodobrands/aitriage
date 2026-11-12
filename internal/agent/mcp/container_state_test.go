package mcp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// containerWorkspace reproduces what the MCP server sees inside the container:
// a project with one finding and its aitriage-reports directory, and the
// environment the container launcher sets. External scanners are made
// unavailable so baseline writes stay fast and deterministic.
func containerWorkspace(t *testing.T) (root, reports string) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	root = t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("document.body.innerHTML = location.hash;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reports = filepath.Join(root, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	return root, reports
}

// readOnlyProject makes the project tree unwritable, as the container's
// read-only /workspace mount does, while the reports directory at its root
// stays writable. Permission bits do not restrict root or Windows; there the
// assertions about where files land still hold.
func readOnlyProject(t *testing.T, root string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	reports := filepath.Join(root, "aitriage-reports")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == reports {
			return filepath.SkipDir
		}
		mode, restore := os.FileMode(0o444), os.FileMode(0o644)
		if d.IsDir() {
			mode, restore = 0o555, 0o755
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		t.Cleanup(func() { _ = os.Chmod(path, restore) })
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func callToolOK(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s transport error: %v", name, err)
	}
	if res.IsError {
		var text []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		t.Fatalf("%s %v returned a tool error: %s", name, args, strings.Join(text, "; "))
	}
	decodeStructured(t, res, out)
}

func requireFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func requireNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat err = %v", path, err)
	}
}

// In the container the project is mounted read-only. A dismissal made by an
// IDE agent must land under the writable reports directory, where the Web UI
// and the scans in the container read it, instead of failing.
func TestSuppressToolInContainerWritesUnderReports(t *testing.T) {
	root, reports := containerWorkspace(t)
	readOnlyProject(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})
	want := filepath.Join(reports, "suppressions", suppression.File)

	var added suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{
		"action": "add", "rule_id": "ENTR-INNERHTML", "source": "core", "file": "app.js",
		"evidence": "document.body.innerHTML = location.hash", "reason": "false_positive",
	}, &added)
	if added.File != want || added.Total != 1 {
		t.Fatalf("add result = %+v, want one entry recorded in %s", added, want)
	}
	if !strings.Contains(added.Summary, want) || !strings.Contains(added.Summary, "commit") {
		t.Errorf("add summary does not say where the decision went and how to share it: %q", added.Summary)
	}
	requireFile(t, want)
	requireNoFile(t, filepath.Join(root, suppression.File))

	var listed suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{"action": "list"}, &listed)
	if listed.File != want || listed.Total != 1 {
		t.Fatalf("list result = %+v, want the entry from %s", listed, want)
	}

	var removed suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{"action": "remove", "rule_id": "ENTR-INNERHTML"}, &removed)
	if removed.File != want || removed.Total != 0 {
		t.Fatalf("remove result = %+v, want an empty record in %s", removed, want)
	}
}

// toolErrorText calls a tool that must fail and returns its error text.
func toolErrorText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s transport error: %v", name, err)
	}
	if !res.IsError {
		t.Fatalf("%s %v succeeded, want a tool error", name, args)
	}
	var text []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = append(text, tc.Text)
		}
	}
	return strings.Join(text, "; ")
}

// Decisions committed with the project keep applying next to the ones an
// agent records in the container, and cannot be undone from there.
func TestSuppressToolInContainerMergesTheProjectFile(t *testing.T) {
	root, reports := containerWorkspace(t)
	committed := suppression.New()
	if _, _, err := committed.Add(baseline.Item{Source: "trivy", RuleID: "CVE-2026-1", File: "package-lock.json", Evidence: "lodash 4.17.20"}, "accepted_risk", "not reachable from our code", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(root, committed); err != nil {
		t.Fatal(err)
	}
	readOnlyProject(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	var added suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{
		"action": "add", "rule_id": "ENTR-INNERHTML", "source": "core", "file": "app.js",
		"evidence": "document.body.innerHTML = location.hash", "reason": "false_positive",
	}, &added)
	if added.Total != 2 || added.File != filepath.Join(reports, "suppressions", suppression.File) {
		t.Fatalf("add result = %+v, want the committed and the local decision", added)
	}

	if msg := toolErrorText(t, cs, "aitriage_suppress", map[string]any{"action": "remove", "rule_id": "CVE-2026-1"}); !strings.Contains(msg, "read-only") {
		t.Fatalf("removing a committed decision failed with %q, want it to say the project file is read-only", msg)
	}

	var removed suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{"action": "remove", "rule_id": "ENTR-INNERHTML"}, &removed)
	if removed.Total != 1 || removed.Entries[0].RuleID != "CVE-2026-1" {
		t.Fatalf("remove result = %+v, want the committed decision left", removed)
	}
}

// nestedFolder adds services/api with one finding to the project.
func nestedFolder(t *testing.T, root string) string {
	t.Helper()
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "index.js"), []byte("el.innerHTML = input;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return nested
}

// In the container only the project root's aitriage-reports is writable. A
// report for a nested folder must land there instead of failing on the
// folder's own aitriage-reports, which sits on the read-only mount.
func TestReportToolInContainerWritesNestedFolderReportsUnderTheRootReports(t *testing.T) {
	root, reports := containerWorkspace(t)
	nested := nestedFolder(t, root)
	readOnlyProject(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	var report reportResult
	callToolOK(t, cs, "aitriage_report", map[string]any{"path": "services/api", "format": "csv"}, &report)
	if filepath.Dir(report.File) != reports {
		t.Fatalf("report written to %s, want it under %s", report.File, reports)
	}
	requireFile(t, report.File)
	requireNoFile(t, filepath.Join(nested, "aitriage-reports"))
}

// Natively a nested folder's report keeps going to that folder's own
// aitriage-reports.
func TestReportToolNativeKeepsTheFolderReports(t *testing.T) {
	root, _ := containerWorkspace(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	nested := nestedFolder(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	var report reportResult
	callToolOK(t, cs, "aitriage_report", map[string]any{"path": "services/api", "format": "csv"}, &report)
	if want := filepath.Join(nested, "aitriage-reports"); filepath.Dir(report.File) != want {
		t.Fatalf("native report written to %s, want it under %s", report.File, want)
	}
	requireFile(t, report.File)
}

// Natively the tool keeps writing the project file it shares with the CLI.
func TestSuppressToolNativeWritesTheProjectFile(t *testing.T) {
	root, reports := containerWorkspace(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	var added suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{
		"action": "add", "rule_id": "ENTR-INNERHTML", "source": "core", "file": "app.js", "reason": "false_positive",
	}, &added)
	if want := filepath.Join(root, suppression.File); added.File != want {
		t.Fatalf("native add wrote %s, want the project file %s", added.File, want)
	}
	requireNoFile(t, filepath.Join(reports, "suppressions"))
}

// The baseline tool in the container writes, reads and clears the copy under
// the reports directory, the same file the Web UI uses there.
func TestBaselineToolInContainerWritesUnderReports(t *testing.T) {
	root, reports := containerWorkspace(t)
	readOnlyProject(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})
	want := filepath.Join(reports, "baselines", baseline.BaselineFile)

	var created baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{"action": "create"}, &created)
	if !created.Exists || created.File != want || created.Total == 0 {
		t.Fatalf("create result = %+v, want a populated baseline at %s", created, want)
	}
	requireFile(t, want)
	requireNoFile(t, filepath.Join(root, baseline.BaselineFile))

	var status baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{"action": "status"}, &status)
	if !status.Exists || status.File != want || status.Total != created.Total {
		t.Fatalf("status after create = %+v, want the copy at %s", status, want)
	}

	var cleared baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{"action": "clear"}, &cleared)
	if cleared.Exists || cleared.File != want {
		t.Fatalf("clear result = %+v, want the copy at %s removed", cleared, want)
	}
	requireNoFile(t, want)
}

// A baseline committed with the project keeps applying in the container. An
// update writes a copy that takes precedence, and clearing removes only the
// copy and reports that the project's own file still applies.
func TestBaselineToolInContainerHonoursTheProjectFile(t *testing.T) {
	root, reports := containerWorkspace(t)
	committed := baseline.NewFromItems(nil)
	committed.CreatedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := baseline.Save(root, committed); err != nil {
		t.Fatal(err)
	}
	projectFile := filepath.Join(root, baseline.BaselineFile)
	original, err := os.ReadFile(projectFile)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyProject(t, root)
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})
	copyFile := filepath.Join(reports, "baselines", baseline.BaselineFile)

	var status baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{}, &status)
	if !status.Exists || status.File != projectFile {
		t.Fatalf("status = %+v, want the project's own baseline", status)
	}

	var updated baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{"action": "update"}, &updated)
	if updated.File != copyFile || updated.Total == 0 || updated.CreatedAt != "2025-01-02T03:04:05Z" {
		t.Fatalf("update result = %+v, want a populated copy at %s keeping the original creation date", updated, copyFile)
	}

	var cleared baselineResult
	callToolOK(t, cs, "aitriage_baseline", map[string]any{"action": "clear"}, &cleared)
	if !cleared.Exists || cleared.File != projectFile {
		t.Fatalf("clear result = %+v, want the project's baseline reported as still applying", cleared)
	}
	requireNoFile(t, copyFile)
	after, err := os.ReadFile(projectFile)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("the project's baseline file changed (err=%v)", err)
	}
}
