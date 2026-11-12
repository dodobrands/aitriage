package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestContainerServeArgs proves the MCP container launch is built correctly:
// stdio (no TTY), read-only source, read-write reports, /workspace scan-root,
// and an inner native server (the scanner bundle lives in the image).
func TestContainerServeArgs(t *testing.T) {
	t.Setenv("AITRIAGE_IMAGE", "ghcr.io/dodobrands/aitriage:v1.7.0")
	hostRoot := t.TempDir()
	cache := t.TempDir()
	args := containerServeArgs("ghcr.io/dodobrands/aitriage:v1.7.0", hostRoot, "safe", cache, "aitriage-mcp-test")
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"run --rm",
		"--name aitriage-mcp-test",
		"-i --security-opt",
		"--security-opt no-new-privileges",
		hostRoot + ":/workspace:ro",
		filepath.Join(hostRoot, "aitriage-reports") + ":/workspace/aitriage-reports:rw",
		cache + ":/home/aitriage/.cache:rw",
		"AITRIAGE_CACHE_DIR=/workspace/aitriage-reports/cache",
		// The baseline and dismissal tools write there: the project is read-only.
		"AITRIAGE_REPORTS_DIR=/workspace/aitriage-reports",
		"ghcr.io/dodobrands/aitriage:v1.7.0 serve --runtime native --profile safe --scan-root /workspace",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("container serve args missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, " -t") {
		t.Error("MCP container serve must not allocate a TTY")
	}
}
