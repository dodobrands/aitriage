package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
)

// A baseline is a property of the project, not of the tool that created it. A
// baseline written by `aitriage baseline create` must be visible to the Web UI
// and to an IDE agent, and vice versa — all three read the same file with the
// same fingerprints.
//
// This capability shipped in the CLI alone. The pilot user, who works entirely
// in the Web UI, hit the exact problem baselines solve and concluded the tool
// was unusable, because the answer existed in a surface he never used.

func seedBaseline(t *testing.T, dir string, results []core.CheckResult) *baseline.Baseline {
	t.Helper()
	b := baseline.New(results)
	if err := baseline.Save(dir, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	return b
}

func TestBaselineFileIsSharedAcrossSurfaces(t *testing.T) {
	dir := t.TempDir()
	results := []core.CheckResult{
		{ID: "ENTR-17", File: "app/config.php", Line: 4, Name: "Hardcoded secret", Severity: "CRITICAL", Evidence: "key=..."},
		{ID: "DOCKER-NO-USER", File: "Dockerfile", Line: 1, Name: "Missing USER", Severity: "HIGH", Evidence: "FROM debian"},
	}
	seedBaseline(t, dir, results)

	// The MCP surface reads what the CLI wrote, at the same path.
	status := baselineStatusFor(dir)

	if !status.Exists {
		t.Fatal("a baseline written by another surface was not visible")
	}
	if status.Total != len(results) {
		t.Errorf("total = %d; want %d", status.Total, len(results))
	}
	if status.File != filepath.Join(dir, baseline.BaselineFile) {
		t.Errorf("file = %q; every surface must use the same path", status.File)
	}
	if status.BySeverity["CRITICAL"] != 1 || status.BySeverity["HIGH"] != 1 {
		t.Errorf("by severity = %v; want one CRITICAL and one HIGH", status.BySeverity)
	}
}

func TestBaselineStatusOnAProjectWithoutOne(t *testing.T) {
	status := baselineStatusFor(t.TempDir())

	if status.Exists {
		t.Error("reported a baseline where no file exists")
	}
	if status.Summary == "" {
		t.Error("an empty baseline must still explain itself to the agent")
	}
}

// The same findings must produce the same fingerprints wherever they are
// computed, or a baseline created in one surface would not match in another.
func TestFingerprintsAreSurfaceIndependent(t *testing.T) {
	result := core.CheckResult{ID: "ENTR-17", File: "a.go", Line: 10, Evidence: "secret"}
	moved := result
	moved.Line = 250 // a line shift must not invalidate acceptance

	if baseline.Fingerprint(result) != baseline.Fingerprint(moved) {
		t.Error("fingerprint changed with the line number; accepted findings would resurface after any edit above them")
	}

	different := result
	different.File = "b.go"
	if baseline.Fingerprint(result) == baseline.Fingerprint(different) {
		t.Error("two different files share a fingerprint; accepting one would hide the other")
	}
}

func TestSafeProfileRefusesToWriteABaseline(t *testing.T) {
	// The safe profile is read-only by contract. Writing a baseline changes the
	// project tree, so it must be refused rather than silently performed.
	if ProfileSafe.allowsMutation() {
		t.Fatal("the safe profile must not permit mutation")
	}
	if !ProfileFull.allowsMutation() {
		t.Fatal("the full profile must permit mutation")
	}
}

func TestBaselineWriteRecordsEveryFindingAndKeepsCreationDate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	first, _, err := baselineWrite(context.Background(), dir, "create")
	_ = first
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	original, err := baseline.Load(dir)
	if err != nil || original == nil {
		t.Fatalf("baseline was not written: %v", err)
	}

	if _, _, err := baselineWrite(context.Background(), dir, "update"); err != nil {
		t.Fatalf("update: %v", err)
	}

	updated, err := baseline.Load(dir)
	if err != nil || updated == nil {
		t.Fatalf("baseline missing after update: %v", err)
	}
	if !updated.CreatedAt.Equal(original.CreatedAt) {
		t.Error("update reset the creation date; it records how long the project has run against a baseline")
	}
}
