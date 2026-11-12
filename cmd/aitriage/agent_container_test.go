package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAgentDefaultsToContainerRuntime(t *testing.T) {
	flag := agentCmd.Flags().Lookup("runtime")
	if flag == nil || flag.DefValue != "container" {
		t.Fatalf("agent --runtime default = %v, want container", flag)
	}
}

func TestNewCLIRunIDUsesRunBundleShape(t *testing.T) {
	id := newCLIRunID()
	if !strings.HasPrefix(id, "run-") || len(id) < len("run-20060102T150405-00000000") {
		t.Fatalf("unexpected CLI run id %q", id)
	}
}

func TestAgentContainerCommandUsesNativeInnerProcessAndReportMount(t *testing.T) {
	root := t.TempDir()
	previousReport, previousManifest, previousNoChat := agentReportOut, agentManifestOut, agentNoChat
	previousFailOn, previousOutput := agentFailOn, agentOutput
	agentReportOut = filepath.Join(root, "aitriage-reports", "run", "report.md")
	agentManifestOut = filepath.Join(root, "aitriage-reports", "run", "manifest.json")
	agentNoChat = true
	agentFailOn = "critical"
	agentOutput = "text"
	t.Cleanup(func() {
		agentReportOut, agentManifestOut, agentNoChat = previousReport, previousManifest, previousNoChat
		agentFailOn, agentOutput = previousFailOn, previousOutput
	})

	args, err := agentContainerCommandArgs(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"agent --runtime native",
		"--no-chat",
		"--report-out /workspace/aitriage-reports/run/report.md",
		"--manifest-out /workspace/aitriage-reports/run/manifest.json",
		"--fail-on critical",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("inner agent args missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "--api-key") {
		t.Fatalf("secret-bearing flag leaked into container argv: %s", joined)
	}
}

// The agent container must know where the writable reports mount is, or it
// ignores the dismissals the Web UI and IDE tools record there for a
// read-only project.
func TestAgentContainerEnvNamesTheReportsMount(t *testing.T) {
	for _, want := range []string{
		"AITRIAGE_RUNTIME=container",
		"AITRIAGE_REPORTS_DIR=/workspace/aitriage-reports",
	} {
		if !slices.Contains(agentContainerEnv, want) {
			t.Errorf("agent container env %v is missing %q", agentContainerEnv, want)
		}
	}
}

func TestAgentContainerRejectsOutputOutsideReports(t *testing.T) {
	root := t.TempDir()
	previous := agentReportOut
	agentReportOut = filepath.Join(root, "report.md")
	t.Cleanup(func() { agentReportOut = previous })
	if _, err := agentContainerCommandArgs(root); err == nil || !strings.Contains(err.Error(), "aitriage-reports") {
		t.Fatalf("outside output error = %v", err)
	}
}

func TestAgentContainerRejectsReportSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	reports := filepath.Join(root, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(reports, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := containerReportPath(root, filepath.Join(reports, "escape", "report.md")); err == nil {
		t.Fatal("report symlink escape must be rejected")
	}
}
