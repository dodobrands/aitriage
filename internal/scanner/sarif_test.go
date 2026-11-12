package scanner_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
)

// G1: what `aitriage scan` prints or writes names files relative to the
// project root; the scanned report itself keeps the engine's absolute paths.
func TestScanOutputUsesProjectRelativePaths(t *testing.T) {
	projectPath := t.TempDir()
	mainPy := filepath.Join(projectPath, "src", "main.py")
	report := scanner.ScanReport{
		ProjectPath: projectPath,
		Results: []core.CheckResult{
			{ID: "FAST-SUBPROCESS", Name: "Unsafe Subprocess", Severity: "CRITICAL", Status: core.Absent, File: mainPy, Line: 11, Evidence: "Rule FAST-SUBPROCESS found issue in " + mainPy},
			{ID: "ENTR-02", Name: "Missing Lockfile", Severity: "HIGH", Status: core.Absent, Evidence: "No lockfile for npm"},
		},
	}

	out := report.WithRelativePaths()
	if got := out.Results[0]; got.File != "src/main.py" || got.Evidence != "Rule FAST-SUBPROCESS found issue in src/main.py" {
		t.Fatalf("output finding = %q / %q, want project-relative", got.File, got.Evidence)
	}
	if out.Results[1].File != "" {
		t.Fatalf("project-level finding got file %q", out.Results[1].File)
	}
	if report.Results[0].File != mainPy {
		t.Fatal("WithRelativePaths modified the scanned report")
	}
	results, err := json.Marshal(out.Results)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := report.ToSARIF()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.ToSlash(projectPath)
	for name, body := range map[string][]byte{"json results": results, "sarif": sarif} {
		if strings.Contains(string(body), root) {
			t.Fatalf("%s contain the absolute project path %s:\n%s", name, root, body)
		}
	}
}

// Only active located findings are exported. A dismissed finding is left out:
// GitHub's SARIF upload ignores SARIF suppressions and would reopen it.
func TestToSARIFExportsOnlyActiveLocatedFindings(t *testing.T) {
	projectPath := t.TempDir()
	report := scanner.ScanReport{
		ProjectPath: projectPath,
		Results: []core.CheckResult{
			{
				ID:         "ACTIVE-HIGH",
				Name:       "Active high",
				Severity:   "HIGH",
				Status:     core.Absent,
				File:       filepath.Join(projectPath, "main.go"),
				Line:       42,
				Suggestion: "Fix it",
			},
			{
				ID:          "IGNORED-HIGH",
				Name:        "Ignored high",
				Severity:    "HIGH",
				Status:      core.Absent,
				File:        filepath.Join(projectPath, "ignored.go"),
				Line:        10,
				AuditStatus: core.AuditStatusIgnored,
			},
			{
				ID:       "PRESENT",
				Name:     "Present check",
				Severity: "LOW",
				Status:   core.Present,
				File:     filepath.Join(projectPath, "present.go"),
				Line:     1,
			},
			{
				ID:       "PROJECT-LEVEL",
				Name:     "Project-level issue",
				Severity: "MEDIUM",
				Status:   core.Absent,
			},
		},
	}

	data, err := report.ToSARIF()
	if err != nil {
		t.Fatalf("ToSARIF failed: %v", err)
	}

	var sarif scanner.SarifLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF JSON did not parse: %v", err)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d; want 1", len(sarif.Runs))
	}
	results := sarif.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("results = %d; want 1 active located finding", len(results))
	}
	if results[0].RuleID != "ACTIVE-HIGH" {
		t.Fatalf("ruleId = %q; want ACTIVE-HIGH", results[0].RuleID)
	}
	if got := results[0].Locations[0].PhysicalLocation.ArtifactLocation.Uri; got != "main.go" {
		t.Fatalf("uri = %q; want main.go", got)
	}
	if results[0].Level != "error" {
		t.Fatalf("level = %q; want error", results[0].Level)
	}
	if strings.Contains(string(data), "suppressions") {
		t.Fatal("SARIF must not carry suppressions: GitHub would reopen the dismissed alert")
	}
}
