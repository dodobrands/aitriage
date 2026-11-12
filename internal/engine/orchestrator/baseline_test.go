package orchestrator

import (
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// The decisions `aitriage ignore add` records most often name a rule, not a
// finding: a CVE accepted for the whole project, or a rule dismissed in one
// file. Both used to be stored and then matched against nothing, because a
// scanned finding always carries its evidence.
func TestApplySuppressionsHonoursRuleWideDismissals(t *testing.T) {
	root := t.TempDir()
	store := suppression.New()
	// Built exactly as runIgnoreAdd builds them: no --evidence, and for the CVE
	// no --file either.
	for _, add := range []struct {
		item         baseline.Item
		reason, note string
	}{
		{baseline.Item{Source: "trivy", RuleID: "CVE-2026-1", File: baseline.RelativePath(root, "")}, "accepted-risk", "mitigated at the gateway"},
		{baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: baseline.RelativePath(root, "core/fns.py")}, "false-positive", ""},
	} {
		if _, _, err := store.Add(add.item, add.reason, add.note, "reviewer"); err != nil {
			t.Fatal(err)
		}
	}

	result := llm.RichScanResult{
		ProjectPath: root,
		Report: scanner.ScanReport{Results: []core.CheckResult{
			{ID: "SECRET-ASSIGN", Status: core.Absent, Severity: "CRITICAL", File: filepath.Join(root, "core", "fns.py"), Line: 3, Evidence: "CLIENT_SECRET = '...'"},
			{ID: "SECRET-ASSIGN", Status: core.Absent, Severity: "CRITICAL", File: filepath.Join(root, "core", "settings.py"), Line: 7, Evidence: "DB_SECRET = '...'"},
			{ID: "PY-EVAL", Status: core.Absent, Severity: "HIGH", File: filepath.Join(root, "core", "fns.py"), Line: 4, Evidence: "eval(x)"},
		}},
		External: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "CVE-2026-1", Severity: "HIGH", File: filepath.Join(root, "requirements.txt"), Message: "pillow: arbitrary code execution"},
			{Source: "trivy", RuleID: "CVE-2026-1", Severity: "HIGH", File: filepath.Join(root, "services", "api", "requirements.txt"), Message: "pillow: arbitrary code execution"},
			{Source: "trivy", RuleID: "CVE-2026-2", Severity: "CRITICAL", File: filepath.Join(root, "requirements.txt"), Message: "pillow: expression evaluation"},
		},
	}

	if got := ApplySuppressions(&result, store); got != 3 {
		t.Fatalf("ApplySuppressions dismissed %d finding(s), want 3", got)
	}
	ignored := map[string]bool{}
	for _, r := range result.Report.Results {
		if r.AuditStatus == core.AuditStatusIgnored {
			ignored[r.ID+" "+filepath.Base(r.File)] = true
		}
	}
	if len(ignored) != 1 || !ignored["SECRET-ASSIGN fns.py"] {
		t.Fatalf("dismissed built-in findings = %v, want only SECRET-ASSIGN in core/fns.py", ignored)
	}
	if len(result.External) != 1 || result.External[0].RuleID != "CVE-2026-2" {
		t.Fatalf("external findings left = %+v, want only the CVE nobody accepted", result.External)
	}
}
