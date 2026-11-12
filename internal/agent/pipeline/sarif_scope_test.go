package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// absoluteEnginePaths rewrites the fixture's built-in findings the way the
// engine reports them: absolute paths under the project root.
func absoluteEnginePaths(project string, rich llm.RichScanResult) llm.RichScanResult {
	results := append([]core.CheckResult(nil), rich.Report.Results...)
	for i := range results {
		results[i].File = filepath.Join(project, filepath.FromSlash(results[i].File))
	}
	rich.Report.Results = results
	rich.Report.ProjectPath = project
	return rich
}

// sarifRuleIDs renders the agent SARIF and returns its results by rule id.
func sarifRuleIDs(t *testing.T, project string, rich llm.RichScanResult) map[string]scanner.SarifResult {
	t.Helper()
	data, err := SARIF(Options{ProjectPath: project}, rich)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "suppressions") {
		t.Fatal("SARIF must not carry suppressions: GitHub's upload would reopen the alerts")
	}
	var log scanner.SarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	results := map[string]scanner.SarifResult{}
	for _, r := range log.Runs[0].Results {
		results[r.RuleID] = r
	}
	return results
}

// A finding dismissed in .aitriage-suppressions.json is left out of the agent
// SARIF, as `aitriage scan` leaves out audit-log dismissals: GitHub's SARIF
// upload ignores SARIF suppressions and would reopen it.
func TestSARIFLeavesOutDismissedFindings(t *testing.T) {
	project, rich := decisionsFixture(t)
	rich = absoluteEnginePaths(project, rich)

	results := sarifRuleIDs(t, project, rich)
	if _, ok := results["SECRET-ASSIGN"]; ok {
		t.Fatal("the dismissed finding is in the SARIF")
	}
	open, ok := results["PY-EVAL"]
	if !ok {
		t.Fatalf("the open finding is missing from the SARIF: %v", results)
	}
	if uri := open.Locations[0].PhysicalLocation.ArtifactLocation.Uri; uri != "core/fns.py" {
		t.Fatalf("uri = %q, want core/fns.py", uri)
	}
	if rich.Report.Results[0].AuditStatus != "" {
		t.Fatal("SARIF modified the caller's scan result")
	}
}

// mergedSecretFixture is one hardcoded secret reported by four detectors and
// an open finding on the next line, with paths as the scanners report them.
func mergedSecretFixture(t *testing.T) (string, llm.RichScanResult) {
	t.Helper()
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "core"), 0o755); err != nil {
		t.Fatal(err)
	}
	fns := filepath.Join(project, "core", "fns.py")
	if err := os.WriteFile(fns, []byte("import os\n\nCLIENT_SECRET = 'placeholder'\nresult = eval(os.environ['X'])\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var rich llm.RichScanResult
	rich.ProjectPath = project
	rich.Report.ProjectPath = project
	rich.Report.Results = []core.CheckResult{
		{ID: "SECRET-ASSIGN", Name: "Hardcoded secret", Status: core.Absent, Severity: "CRITICAL", File: fns, Line: 3, Evidence: "CLIENT_SECRET = '...'"},
		{ID: "PY-EVAL", Name: "Code evaluation", Status: core.Absent, Severity: "HIGH", File: fns, Line: 4, Evidence: "eval(os.environ['X'])"},
	}
	rich.External = []external.UnifiedFinding{
		{Source: "bandit", RuleID: "B105", Severity: "LOW", File: fns, Line: 3, Message: "hardcoded_password_string: Possible hardcoded password"},
		{Source: "gitleaks", RuleID: "generic-api-key", Severity: "CRITICAL", File: fns, Line: 3, Message: "Detected a Generic API Key: pl****er"},
		{Source: "semgrep", RuleID: "generic.secrets.security.detected-generic-secret.detected-generic-secret", Severity: "HIGH", File: "core/fns.py", Line: 3, Message: "Generic Secret detected"},
	}
	return project, rich
}

func saveFalsePositive(t *testing.T, project string, item baseline.Item) {
	t.Helper()
	store := suppression.New()
	if _, _, err := store.Add(item, "false-positive", "fixture value, not a credential", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(project, store); err != nil {
		t.Fatal(err)
	}
}

// A recorded dismissal of any detector of a merged finding covers the whole
// finding: `aitriage ignore add SECRET-ASSIGN --file core/fns.py --reason
// false-positive`, or the same for the Gitleaks report, suppresses the
// hardcoded secret four detectors reported, keeps the decision visible, and
// keeps every report of it out of the LLM, the score and the SARIF.
func TestDecisionOnOneDetectorSuppressesTheMergedFinding(t *testing.T) {
	for name, dismissed := range map[string]func(rich llm.RichScanResult, project string) baseline.Item{
		"built-in report": func(rich llm.RichScanResult, project string) baseline.Item {
			return baseline.Relativize(project, baseline.FromCore(rich.Report.Results[:1]))[0]
		},
		"gitleaks report": func(rich llm.RichScanResult, project string) baseline.Item {
			return baseline.Relativize(project, baseline.FromExternal(rich.External[1:2]))[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AITRIAGE_CONCURRENCY", "1")
			t.Setenv("AITRIAGE_CACHE_DIR", "")
			t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
			t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
			project, rich := mergedSecretFixture(t)
			saveFalsePositive(t, project, dismissed(rich, project))
			client := &recordingLLM{}

			state := BuildState(Options{ProjectPath: project, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed}}, rich)
			res, err := RunState(context.Background(), state, client)
			if err != nil {
				t.Fatal(err)
			}
			for _, prompt := range client.modelPrompts() {
				for _, rule := range []string{"SECRET-ASSIGN", "B105", "generic-api-key", "detected-generic-secret"} {
					if strings.Contains(prompt, rule) {
						t.Fatalf("a report of the dismissed defect (%s) was sent to the LLM", rule)
					}
				}
			}
			var secret *graph.FindingDisposition
			for i, d := range res.State.FindingDispositions {
				if res.State.EnrichedFindings[d.FindingIndex].Class == "hardcoded_secret" {
					secret = &res.State.FindingDispositions[i]
				}
			}
			if secret == nil || secret.DispositionSource != "suppressed" || secret.Disposition != "False Positive" ||
				!strings.Contains(secret.Rationale, "false_positive") || !strings.Contains(secret.Rationale, "fixture value, not a credential") {
				t.Fatalf("merged hardcoded secret disposition = %+v, want suppressed with the recorded decision", secret)
			}
			if bd := res.Health.Breakdown; bd.IgnoredFindings != 1 || bd.ActiveFindings != 1 {
				t.Fatalf("breakdown = %+v, want the secret ignored and only PY-EVAL active", bd)
			}

			results := sarifRuleIDs(t, project, rich)
			if _, ok := results["SECRET-ASSIGN"]; ok {
				t.Fatal("the built-in report of the dismissed defect is in the SARIF")
			}
			if _, ok := results["PY-EVAL"]; !ok {
				t.Fatal("the open finding is missing from the SARIF")
			}
		})
	}
}

// The counts of what ignore.rules and inline comments removed reach the
// state, triage-findings.json and one line of summary.md.
func TestScopeExclusionsReachTheArtifacts(t *testing.T) {
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	project, rich := decisionsFixture(t)
	rich.IgnoredByConfig = map[string]int{"ENTR-SLOP-01": 1, "port-53": 2}
	rich.SuppressedInline = map[string]int{"bandit:B105": 1}

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed}}, rich)
	if !reflect.DeepEqual(state.IgnoredByConfig, rich.IgnoredByConfig) || !reflect.DeepEqual(state.SuppressedInline, rich.SuppressedInline) {
		t.Fatalf("state scope = %v / %v", state.IgnoredByConfig, state.SuppressedInline)
	}
	res, err := RunState(context.Background(), state, &recordingLLM{})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := res.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scope.IgnoredByConfig["port-53"] != 2 || artifact.Scope.SuppressedInline["bandit:B105"] != 1 {
		t.Fatalf("artifact scope = %+v", artifact.Scope)
	}
	data, _ := json.Marshal(artifact)
	if !strings.Contains(string(data), `"scope":{"ignored_by_config":{`) {
		t.Fatalf("triage-findings.json has no scope field: %s", data)
	}
	want := "_Scope: 3 finding(s) removed by `ignore.rules` in `.aitriage.yaml` (ENTR-SLOP-01 ×1, port-53 ×2) · 1 silenced by inline `aitriage-ignore` comments (bandit:B105 ×1)."
	if !strings.Contains(res.Summary, want) {
		t.Fatalf("summary lacks the scope line %q:\n%s", want, res.Summary)
	}
}

// Decisions recorded against project-relative paths still apply when the
// engine reports absolute ones, now that findings enter triage relative.
func TestProjectDecisionsMatchAbsoluteEnginePaths(t *testing.T) {
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	project, rich := decisionsFixture(t)
	rich = absoluteEnginePaths(project, rich)
	client := &recordingLLM{}

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed}}, rich)
	res, err := RunState(context.Background(), state, client)
	if err != nil {
		t.Fatal(err)
	}
	for _, prompt := range client.modelPrompts() {
		if strings.Contains(prompt, "SECRET-ASSIGN") {
			t.Fatal("the dismissed finding was sent to the LLM")
		}
	}
	for _, d := range res.State.FindingDispositions {
		f := res.State.EnrichedFindings[d.FindingIndex]
		if f.ID == "SECRET-ASSIGN" && !strings.Contains(d.Rationale, "test fixture value") {
			t.Fatalf("dismissed finding rationale = %q, want the recorded note", d.Rationale)
		}
		if filepath.IsAbs(f.File) {
			t.Fatalf("finding %s kept an absolute path %q", f.ID, f.File)
		}
	}
}
