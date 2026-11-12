package external_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// installFakeTool puts a shell script named name first on PATH.
func installFakeTool(t *testing.T, name, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in scanner is a POSIX shell script")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Semgrep prints its update notice on stderr before the version on stdout.
// Reading combined output recorded the notice as Semgrep's version.
func TestToolVersionIgnoresStderrNotices(t *testing.T) {
	installFakeTool(t, "semgrep",
		"echo 'A new version of Semgrep is available. See https://semgrep.dev/docs/upgrading' >&2\n"+
			"echo '1.170.1'\n")

	if got := external.ToolVersion(context.Background(), "semgrep"); got != "1.170.1" {
		t.Fatalf("semgrep version = %q; want 1.170.1", got)
	}
}

// The version check is a network call on every Semgrep run, scan and version
// probe alike; SEMGREP_ENABLE_VERSION_CHECK=0 is Semgrep's documented switch.
func TestSemgrepRunsWithVersionCheckDisabled(t *testing.T) {
	installFakeTool(t, "semgrep", "echo \"check=${SEMGREP_ENABLE_VERSION_CHECK:-unset}\"\n")
	t.Setenv("SEMGREP_ENABLE_VERSION_CHECK", "1")

	result, err := external.RunTool(context.Background(), "semgrep", "scan")
	if err != nil {
		t.Fatalf("RunTool: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "check=0" {
		t.Errorf("semgrep scan environment: %s; want the version check disabled", got)
	}
	if got := external.ToolVersion(context.Background(), "semgrep"); got != "check=0" {
		t.Errorf("semgrep version probe environment: %s; want the version check disabled", got)
	}
}

func TestOtherToolsInheritTheEnvironment(t *testing.T) {
	installFakeTool(t, "gitleaks", "echo \"check=${SEMGREP_ENABLE_VERSION_CHECK:-unset} marker=${AITRIAGE_TEST_MARKER:-unset}\"\n")
	t.Setenv("AITRIAGE_TEST_MARKER", "kept")

	result, err := external.RunTool(context.Background(), "gitleaks", "version")
	if err != nil {
		t.Fatalf("RunTool: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "check=unset marker=kept" {
		t.Errorf("gitleaks environment: %s; want it inherited unchanged", got)
	}
}
