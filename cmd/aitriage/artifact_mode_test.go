package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
)

// Inside the scanner container the process runs as root and writes into a
// bind-mounted CI workspace; later CI steps run as another user and must be
// able to read the reports. On a developer machine they stay private.
func TestArtifactFileModeDependsOnRuntime(t *testing.T) {
	t.Setenv("AITRIAGE_RUNTIME", "container")
	if got := artifactFileMode(); got != 0o644 {
		t.Fatalf("container artifact mode = %o, want 644", got)
	}
	t.Setenv("AITRIAGE_RUNTIME", "")
	if got := artifactFileMode(); got != 0o600 {
		t.Fatalf("host artifact mode = %o, want 600", got)
	}
}

func TestTriageArtifactIsReadableByOtherUsersInContainer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	t.Setenv("AITRIAGE_RUNTIME", "container")
	path := filepath.Join(t.TempDir(), "triage-findings.json")
	if err := writeTriageArtifact(path, &graph.AgentState{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 != 0o044 {
		t.Fatalf("triage artifact mode %o is not readable by group/others", info.Mode().Perm())
	}
}
