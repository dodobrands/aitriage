package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// decisionsFixture mirrors a project where `aitriage ignore add` accepted one
// dependency CVE and dismissed one hardcoded-secret finding.
func decisionsFixture(t *testing.T) (string, llm.RichScanResult) {
	t.Helper()
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "core"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "core", "fns.py"), []byte("import os\n\nCLIENT_SECRET = 'placeholder'\nresult = eval(os.environ['X'])\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	secret := core.CheckResult{ID: "SECRET-ASSIGN", Name: "Hardcoded secret", Status: core.Absent, Severity: "CRITICAL", File: "core/fns.py", Line: 3, Evidence: "CLIENT_SECRET = '...'"}
	eval := core.CheckResult{ID: "PY-EVAL", Name: "Code evaluation", Status: core.Absent, Severity: "HIGH", File: "core/fns.py", Line: 4, Evidence: "eval(os.environ['X'])"}
	acceptedCVE := external.UnifiedFinding{Source: "trivy", RuleID: "CVE-2023-50447", Severity: "HIGH", File: "requirements.txt", Message: "pillow: arbitrary code execution"}
	openCVE := external.UnifiedFinding{Source: "trivy", RuleID: "CVE-2022-22817", Severity: "CRITICAL", File: "requirements.txt", Message: "pillow: expression evaluation"}

	store := suppression.New()
	if _, _, err := store.Add(baseline.FromExternal([]external.UnifiedFinding{acceptedCVE})[0], "accepted-risk", "pinned until the upstream release", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Add(baseline.FromCore([]core.CheckResult{secret})[0], "false-positive", "test fixture value", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(project, store); err != nil {
		t.Fatal(err)
	}

	var rich llm.RichScanResult
	rich.ProjectPath = project
	rich.Report.Results = []core.CheckResult{secret, eval}
	rich.External = []external.UnifiedFinding{acceptedCVE, openCVE}
	return project, rich
}

// B4: decisions recorded with `aitriage ignore add` apply in the shared
// pipeline, as they do in the Web server: the accepted CVE is dropped, the
// dismissed built-in finding stays visible but marked, and the counts by
// reason are reported. The caller's scan result is not modified.
func TestBuildStateAppliesProjectDecisions(t *testing.T) {
	project, rich := decisionsFixture(t)
	originalExternal := append([]external.UnifiedFinding(nil), rich.External...)
	originalCore := append([]core.CheckResult(nil), rich.Report.Results...)

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.DefaultPolicy()}, rich)

	if len(state.ExternalFindings) != 1 || state.ExternalFindings[0].RuleID != "CVE-2022-22817" {
		t.Fatalf("external findings = %+v, want only the open CVE", state.ExternalFindings)
	}
	statuses := map[string]core.AuditStatus{}
	for _, r := range state.CoreFindings {
		statuses[r.ID] = r.AuditStatus
	}
	if statuses["SECRET-ASSIGN"] != core.AuditStatusIgnored || statuses["PY-EVAL"] == core.AuditStatusIgnored {
		t.Fatalf("core audit statuses = %v, want only SECRET-ASSIGN dismissed", statuses)
	}
	want := map[string]int{suppression.ReasonAcceptedRisk: 1, suppression.ReasonFalsePositive: 1}
	if state.Suppressions.Total != 2 || !reflect.DeepEqual(state.Suppressions.ByReason, want) {
		t.Fatalf("suppressions = %+v, want %v", state.Suppressions, want)
	}
	decision := state.Suppressions.Core[graph.CoreDecisionKey("SECRET-ASSIGN", "core/fns.py", 3)]
	if decision.Reason != suppression.ReasonFalsePositive || decision.Note != "test fixture value" {
		t.Fatalf("core decision = %+v, want the recorded reason and note", decision)
	}
	if !reflect.DeepEqual(rich.External, originalExternal) || !reflect.DeepEqual(rich.Report.Results, originalCore) {
		t.Fatal("BuildState modified the caller's scan result in place")
	}
}

// B4, end to end: neither dismissed finding reaches the LLM, and the health
// check does not count them.
func TestRunStateNeverSendsProjectDecisionsToTheLLM(t *testing.T) {
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	project, rich := decisionsFixture(t)
	client := &recordingLLM{}

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed}}, rich)
	res, err := RunState(context.Background(), state, client)
	if err != nil {
		t.Fatalf("RunState() error = %v", err)
	}
	for _, prompt := range client.modelPrompts() {
		for _, dismissed := range []string{"SECRET-ASSIGN", "CVE-2023-50447"} {
			if strings.Contains(prompt, dismissed) {
				t.Fatalf("dismissed finding %s was sent to the LLM", dismissed)
			}
		}
	}
	bd := res.Health.Breakdown
	if bd.ActiveFindings != 2 || bd.IgnoredFindings != 1 {
		t.Fatalf("breakdown = %+v, want the two open findings active and the dismissed one ignored", bd)
	}
	artifact, err := res.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Suppressions.Total != 2 || artifact.Classification.BySource["suppressed"] != 1 {
		t.Fatalf("artifact suppressions = %+v by_source = %v", artifact.Suppressions, artifact.Classification.BySource)
	}
	if !strings.Contains(res.Summary, "1 false_positive · 1 accepted_risk") {
		t.Fatalf("summary does not show the decisions by reason:\n%s", res.Summary)
	}
}

// A decisions file that cannot be read is reported, and its findings stay
// open: failing closed beats silently waiving nothing or everything.
func TestBuildStateReportsUnreadableDecisions(t *testing.T) {
	project, rich := decisionsFixture(t)
	if err := os.WriteFile(filepath.Join(project, suppression.File), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := BuildState(Options{ProjectPath: project}, rich)
	if state.Suppressions.LoadError == "" || len(state.ExternalFindings) != 2 {
		t.Fatalf("suppressions = %+v external = %d, want the error reported and nothing dismissed", state.Suppressions, len(state.ExternalFindings))
	}
}

// F1: the compose probe is opt-in and the option reaches the scanners.
func TestScannerOptionsForwardsProbeCompose(t *testing.T) {
	if scannerOptions(Options{}).ProbeCompose {
		t.Fatal("compose probing must be off unless requested")
	}
	if !scannerOptions(Options{Scan: ScanOptions{ProbeCompose: true}}).ProbeCompose {
		t.Fatal("ScanOptions.ProbeCompose was not forwarded to the scanner orchestrator")
	}
}

// recordingLLM answers every stage with a well-formed reply and records what
// was sent for classification and threat modelling.
type recordingLLM struct {
	mu      sync.Mutex
	prompts []string
}

func (c *recordingLLM) modelPrompts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.prompts...)
}

func (c *recordingLLM) Chat(_ context.Context, messages []llm.Message) (string, llm.Usage, error) {
	system, user := messages[0].Content, messages[1].Content
	switch {
	case strings.Contains(system, "Current Task: Threat Model & Finding Classification"):
		c.record(user)
		return `{"component_overview":"fixture"}`, llm.Usage{}, nil
	case strings.Contains(system, "Current Task: Finding Classification"):
		c.record(user)
		return classifyEverything(user, "Needs Manual Review"), llm.Usage{}, nil
	case strings.Contains(system, "Current Task: PoC Verification"):
		return "[]", llm.Usage{}, nil
	default:
		return "# narrative\n", llm.Usage{}, nil
	}
}

func (c *recordingLLM) record(prompt string) {
	c.mu.Lock()
	c.prompts = append(c.prompts, prompt)
	c.mu.Unlock()
}

// classifyEverything echoes the identity of every finding in a
// classification prompt with one disposition.
func classifyEverything(user, disposition string) string {
	start := strings.Index(user, "## Findings to classify")
	if start < 0 {
		return `{"finding_dispositions":[]}`
	}
	open := strings.Index(user[start:], "[")
	var items []struct {
		FindingIndex int    `json:"finding_index"`
		FindingID    string `json:"finding_id"`
		Fingerprint  string `json:"fingerprint"`
	}
	_ = json.NewDecoder(strings.NewReader(user[start+open:])).Decode(&items)
	var entries []string
	for _, item := range items {
		entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"finding_id":%q,"fingerprint":%q,"disposition":%q,"confidence":"medium","rationale":"r"}`,
			item.FindingIndex, item.FindingID, item.Fingerprint, disposition))
	}
	return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`
}
