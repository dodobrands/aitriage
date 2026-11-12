package pipeline

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// In the container the project is read-only, so the Web UI and the IDE tools
// record dismissals under aitriage-reports. The agent run in the container
// must apply that copy together with the project's own file, or a decision
// made in the container, or one committed after it, is ignored by the next run.
func TestBuildStateAppliesDecisionsRecordedInTheContainer(t *testing.T) {
	project, rich := decisionsFixture(t)
	reports := filepath.Join(project, "aitriage-reports")
	copyDir := filepath.Join(reports, "suppressions")
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(project, suppression.File), filepath.Join(copyDir, suppression.File)); err != nil {
		t.Fatal(err)
	}
	// A commit pulled after the copy was written dismisses the eval finding.
	committed := suppression.New()
	evalFinding := rich.Report.Results[1]
	if _, _, err := committed.Add(baseline.FromCore(rich.Report.Results[1:2])[0], "false-positive", "input is a constant", "upstream"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(project, committed); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)

	want := map[string]int{suppression.ReasonAcceptedRisk: 1, suppression.ReasonFalsePositive: 2}
	// The container agent scans "." from the project root.
	t.Chdir(project)
	for _, projectPath := range []string{project, "."} {
		state := BuildState(Options{ProjectPath: projectPath, Policy: healthcheck.DefaultPolicy()}, rich)
		if state.Suppressions.LoadError != "" || state.Suppressions.Total != 3 || !reflect.DeepEqual(state.Suppressions.ByReason, want) {
			t.Fatalf("ProjectPath %q: suppressions = %+v, want the container's decisions and the committed one", projectPath, state.Suppressions)
		}
		if len(state.ExternalFindings) != 1 || state.ExternalFindings[0].RuleID != "CVE-2022-22817" {
			t.Fatalf("ProjectPath %q: external findings = %+v, want only the open CVE", projectPath, state.ExternalFindings)
		}
		if decision := state.Suppressions.Core[graph.CoreDecisionKey(evalFinding.ID, evalFinding.File, evalFinding.Line)]; decision.Note != "input is a constant" {
			t.Fatalf("ProjectPath %q: the committed decision on %s was not applied: %+v", projectPath, evalFinding.ID, decision)
		}
	}
}

// Outside the container the project file is the record, whatever the reports
// directory holds.
func TestBuildStateNativeReadsTheProjectFile(t *testing.T) {
	project, rich := decisionsFixture(t)
	reports := filepath.Join(project, "aitriage-reports")
	stale := filepath.Join(reports, "suppressions")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(stale, suppression.New()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.DefaultPolicy()}, rich)
	if state.Suppressions.Total != 2 {
		t.Fatalf("suppressions = %+v, want the two decisions in the project file", state.Suppressions)
	}
}

// `aitriage ignore add` most often names a rule rather than one finding: a CVE
// accepted project-wide (no --file, no --evidence) and a rule dismissed in one
// file (no --evidence). The run must apply and count both.
func TestBuildStateCountsRuleWideDecisions(t *testing.T) {
	project, rich := decisionsFixture(t)
	store := suppression.New()
	// Built as runIgnoreAdd builds them.
	if _, _, err := store.Add(baseline.Item{Source: "trivy", RuleID: "CVE-2023-50447", File: baseline.RelativePath(project, "")}, "accepted-risk", "pinned until the upstream release", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Add(baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: baseline.RelativePath(project, "core/fns.py")}, "false-positive", "", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(project, store); err != nil {
		t.Fatal(err)
	}

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.DefaultPolicy()}, rich)
	want := map[string]int{suppression.ReasonAcceptedRisk: 1, suppression.ReasonFalsePositive: 1}
	if state.Suppressions.Total != 2 || !reflect.DeepEqual(state.Suppressions.ByReason, want) {
		t.Fatalf("suppressions = %+v, want both rule-wide decisions applied", state.Suppressions)
	}
	if len(state.ExternalFindings) != 1 || state.ExternalFindings[0].RuleID != "CVE-2022-22817" {
		t.Fatalf("external findings = %+v, want only the CVE nobody accepted", state.ExternalFindings)
	}
}
