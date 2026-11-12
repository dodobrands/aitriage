package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

type ignoreAddFlags struct {
	source, file, evidence, reason, note string
}

// runIgnoreAddWith runs `aitriage ignore add RULE PROJECT` with the given flags
// and restores the flag values afterwards.
func runIgnoreAddWith(t *testing.T, project, ruleID string, flags ignoreAddFlags) {
	t.Helper()
	prevSource, prevFile, prevLine, prevReason, prevNote, prevEvid := ignoreSource, ignoreFile, ignoreLine, ignoreReason, ignoreNote, ignoreEvid
	t.Cleanup(func() {
		ignoreSource, ignoreFile, ignoreLine, ignoreReason, ignoreNote, ignoreEvid = prevSource, prevFile, prevLine, prevReason, prevNote, prevEvid
	})
	ignoreSource, ignoreFile, ignoreLine, ignoreEvid = flags.source, flags.file, 0, flags.evidence
	ignoreReason, ignoreNote = flags.reason, flags.note
	if err := runIgnoreAdd(ignoreAddCmd, []string{ruleID, project}); err != nil {
		t.Fatalf("ignore add %s: %v", ruleID, err)
	}
}

// The two commands below were recorded, and then ignored by the next scan:
// neither names the matched text, and the CVE names no file, while every
// scanned finding carries both.
func TestIgnoreAddDecisionsApplyToScannedFindings(t *testing.T) {
	project := t.TempDir()
	runIgnoreAddWith(t, project, "CVE-2026-1", ignoreAddFlags{source: "trivy", reason: "accepted-risk", note: "mitigated at the gateway"})
	runIgnoreAddWith(t, project, "SECRET-ASSIGN", ignoreAddFlags{source: "core", file: "core/fns.py", reason: "false-positive"})

	store, err := suppression.Load(project)
	if err != nil {
		t.Fatal(err)
	}
	rich := llm.RichScanResult{
		ProjectPath: project,
		Report: scanner.ScanReport{Results: []core.CheckResult{
			{ID: "SECRET-ASSIGN", Status: core.Absent, Severity: "CRITICAL", File: filepath.Join(project, "core", "fns.py"), Line: 3, Evidence: "CLIENT_SECRET = '...'"},
			{ID: "PY-EVAL", Status: core.Absent, Severity: "HIGH", File: filepath.Join(project, "core", "fns.py"), Line: 4, Evidence: "eval(x)"},
		}},
		External: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "CVE-2026-1", Severity: "HIGH", File: filepath.Join(project, "requirements.txt"), Message: "pillow: arbitrary code execution"},
			{Source: "trivy", RuleID: "CVE-2026-2", Severity: "CRITICAL", File: filepath.Join(project, "requirements.txt"), Message: "pillow: expression evaluation"},
		},
	}

	if got := orchestrator.ApplySuppressions(&rich, store); got != 2 {
		t.Fatalf("the next scan applied %d of the 2 recorded decisions", got)
	}
	for _, r := range rich.Report.Results {
		if dismissed := r.AuditStatus == core.AuditStatusIgnored; dismissed != (r.ID == "SECRET-ASSIGN") {
			t.Errorf("%s dismissed = %v", r.ID, dismissed)
		}
	}
	if len(rich.External) != 1 || rich.External[0].RuleID != "CVE-2026-2" {
		t.Errorf("external findings left = %+v, want only CVE-2026-2", rich.External)
	}
}

// The note printed after `ignore add` must describe what the stored entry
// actually covers.
func TestIgnoreScopeNoteDescribesTheCoverage(t *testing.T) {
	cve := suppression.Entry{Source: "trivy", RuleID: "CVE-2026-1"}
	secret := suppression.Entry{Source: "core", RuleID: "SECRET-ASSIGN", File: "core/fns.py"}
	for _, tc := range []struct {
		entry    suppression.Entry
		evidence string
		want     string
	}{
		{cve, "", "covers every trivy finding of CVE-2026-1 anywhere in the project"},
		{secret, "", "covers every core finding of SECRET-ASSIGN in core/fns.py"},
		{cve, "pillow 9.0", "matches only trivy findings of CVE-2026-1 reported without a file"},
		{secret, "CLIENT_SECRET = '...'", ""},
	} {
		got := ignoreScopeNote(tc.entry, tc.evidence)
		if tc.want == "" {
			if got != "" {
				t.Errorf("an exact dismissal printed a scope note: %q", got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("note for %s (evidence %q) = %q, want it to say %q", tc.entry.RuleID, tc.evidence, got, tc.want)
		}
	}
}
