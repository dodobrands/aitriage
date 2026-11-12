package graph

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// The scanner table counts what each scanner returned; the inventory counts
// each defect once, after inline suppression. Semgrep reported 4, two were
// silenced inline and the two left merged into the built-in findings of the
// same defects, so the table says 4 while the inventory has none from
// Semgrep alone. The column says "Raw results" and a note says where the
// difference went.
func TestSummaryLabelsScannerCountsAsRawResults(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{"main.py": strings.Repeat("x = 1\n", 20)})
	state := &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "FAST-SUBPROCESS", Name: "Unsafe Subprocess", Status: core.Absent, Severity: "HIGH", File: "main.py", Line: 11, Evidence: "shell=True"},
			{ID: "FAST-SQLI", Name: "SQL Injection", Status: core.Absent, Severity: "HIGH", File: "main.py", Line: 14, Evidence: "raw query"},
		},
		ExternalFindings: []external.UnifiedFinding{
			{Source: "semgrep", RuleID: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", Severity: "HIGH", File: "main.py", Line: 11, Message: "shell=True"},
			{Source: "semgrep", RuleID: "python.django.security.injection.sql.sql-injection-using-db-cursor-execute", Severity: "HIGH", File: "main.py", Line: 14, Message: "user input in SQL"},
		},
		ScannerExecutions: []external.ScannerExecution{
			{Scanner: "aitriage", Status: external.StatusCompleted, Findings: 2},
			{Scanner: "semgrep", Status: external.StatusCompleted, Findings: 4, Version: "1.2.3"},
		},
		SuppressedInline: map[string]int{"semgrep:python.lang.security.audit.eval-detected.eval-detected": 2},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("findings = %+v, want the two defects", state.EnrichedFindings)
	}
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	summary := state.SummaryMarkdown
	for _, want := range []string{
		"| Scanner | Status | Raw results | Version |",
		"| `semgrep` | `completed` | 4 | 1.2.3 |",
		"_Raw results are the reports each scanner returned, before they became findings: 2 merged into findings of the same defect, 2 silenced by inline `aitriage-ignore` comments._",
		"· 2 duplicates merged",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	if strings.Contains(summary, "| Scanner | Status | Findings |") {
		t.Errorf("summary still labels raw counts as findings:\n%s", summary)
	}
}
