package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// monorepoAuthFixture is a project with a FastAPI backend that has no
// authentication and a static Next.js frontend without middleware. The team
// ran `aitriage ignore add NEXT-AUTH --reason accepted-risk` (no --file, no
// --evidence) for the frontend.
func monorepoAuthFixture(t *testing.T) (string, llm.RichScanResult) {
	t.Helper()
	project := t.TempDir()
	store := suppression.New()
	if _, _, err := store.Add(baseline.Item{Source: "core", RuleID: "NEXT-AUTH"}, "accepted-risk", "static marketing frontend, no sessions", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(project, store); err != nil {
		t.Fatal(err)
	}
	var rich llm.RichScanResult
	rich.ProjectPath = project
	rich.Report.Results = []core.CheckResult{
		{ID: "FAST-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "HIGH: No authentication mechanisms found."},
		{ID: "NEXT-AUTH", Name: "Missing Auth Middleware", Status: core.Absent, Severity: "HIGH", Evidence: "HIGH: Missing Next.js middleware."},
	}
	return project, rich
}

func hermeticPipeline(t *testing.T) {
	t.Helper()
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
	for _, name := range []string{"AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR", "AITRIAGE_GATING", "AITRIAGE_LLM_BUDGET", "AITRIAGE_CLASSIFY_RETRIES"} {
		t.Setenv(name, "")
	}
}

// A decision about one stack's project-level check must not dismiss another
// stack's check of the same class: the FastAPI finding is triaged and blocks
// fail_on=critical. It used to be merged with NEXT-AUTH into one finding that
// the frontend decision dismissed, and the gate passed.
func TestRunStateDecisionAboutOneStackKeepsTheOtherStackOpen(t *testing.T) {
	hermeticPipeline(t)
	project, rich := monorepoAuthFixture(t)
	client := &recordingLLM{}

	state := BuildState(Options{ProjectPath: project, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical}}, rich)
	res, err := RunState(context.Background(), state, client)
	if err != nil {
		t.Fatalf("RunState() error = %v", err)
	}
	sent := strings.Join(client.modelPrompts(), "\n")
	if !strings.Contains(sent, "FAST-AUTH") || strings.Contains(sent, "NEXT-AUTH") {
		t.Fatalf("model prompts must carry FAST-AUTH and not the dismissed NEXT-AUTH:\n%s", sent)
	}
	sources := map[string]string{}
	for _, d := range state.FindingDispositions {
		sources[state.EnrichedFindings[d.FindingIndex].ID] = d.DispositionSource
	}
	if sources["NEXT-AUTH"] != "suppressed" || sources["FAST-AUTH"] != "llm" {
		t.Fatalf("disposition sources = %v, want NEXT-AUTH suppressed and FAST-AUTH triaged", sources)
	}
	bd := res.Health.Breakdown
	if bd.ActiveFindings != 1 || bd.IgnoredFindings != 1 {
		t.Fatalf("breakdown = %+v, want FAST-AUTH active and NEXT-AUTH ignored", bd)
	}
	if res.Gate.Passed || !hasReason(res.Gate, "critical_or_high_findings") {
		t.Fatalf("gate = %+v, want fail_on=critical to block FastAPI's missing authentication", res.Gate)
	}
}

// Each stack's defect counts for max_high, before and after a dismissal.
func TestRunStateCountsEveryStacksProjectLevelDefect(t *testing.T) {
	hermeticPipeline(t)
	project, rich := monorepoAuthFixture(t)
	rich.Report.Results = append(rich.Report.Results, core.CheckResult{
		ID: "EXPRESS-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "HIGH: passport not found",
	})
	policy := healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed, MaxCritical: -1, MaxHigh: 1, MaxMedium: -1}

	state := BuildState(Options{ProjectPath: project, Policy: policy}, rich)
	res, err := RunState(context.Background(), state, &recordingLLM{})
	if err != nil {
		t.Fatalf("RunState() error = %v", err)
	}
	if got := res.Health.Breakdown.CountBySeverity["HIGH"]; got != 2 {
		t.Fatalf("HIGH count = %d, want FAST-AUTH and EXPRESS-AUTH (NEXT-AUTH is dismissed)", got)
	}
	if res.Gate.Passed || !hasReason(res.Gate, "high_threshold") {
		t.Fatalf("gate = %+v, want max_high=1 exceeded", res.Gate)
	}
}

func hasReason(verdict healthcheck.Verdict, code string) bool {
	for _, reason := range verdict.BlockingReasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}
