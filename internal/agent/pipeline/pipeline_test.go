package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func sampleRich() llm.RichScanResult {
	var rich llm.RichScanResult
	rich.ProjectPath = "/tmp/proj"
	rich.Report.SecurityScore = 42
	rich.Report.SecurityGrade = "C"
	rich.Report.Results = []core.CheckResult{
		{ID: "CS-A", Name: "A", Status: core.Present, Severity: "HIGH", File: "a.go", Line: 10},
		{ID: "CS-B", Name: "B", Status: core.Present, Severity: "LOW", File: "b.go", Line: 20},
	}
	rich.Diagram = "graph"
	return rich
}

func sampleOpts() Options {
	return Options{
		ProjectPath: "/tmp/proj",
		Policy:      healthcheck.DefaultPolicy(),
		LLM: LLMIdentity{
			Provider:        "gemini",
			Model:           "gemini-2.0-flash",
			BaseURL:         "https://example",
			DisableThinking: true,
			BatchSize:       5,
		},
	}
}

// TestBuildStateMatchesHistoricalConstruction proves the shared runner builds
// the exact AgentState the CLI used to assemble inline, so migrating the CLI to
// the shared runner cannot silently change CI/CD behaviour.
func TestBuildStateMatchesHistoricalConstruction(t *testing.T) {
	opts := sampleOpts()
	rich := sampleRich()

	got := BuildState(opts, rich)

	// Historical inline construction copied verbatim from cmd/aitriage/agent.go
	// before the refactor (llm identity + scan sources + policy + diagram).
	want := &graph.AgentState{
		ProjectPath:        opts.ProjectPath,
		DeepScan:           true,
		BatchSize:          opts.LLM.BatchSize,
		LLMProvider:        opts.LLM.Provider,
		LLMModel:           opts.LLM.Model,
		LLMBaseURL:         opts.LLM.BaseURL,
		LLMDisableThinking: opts.LLM.DisableThinking,
		CoreFindings:       rich.Report.Results,
		ExternalFindings:   rich.External,
		NFRFindings:        rich.NFR,
		DeployFindings:     rich.Deploy,
		NetworkFindings:    rich.Network,
		ScannerExecutions:  rich.ScannerExecutions,
		ScannerCoverage:    "partial",
		SecurityScore:      rich.Report.SecurityScore,
		SecurityGrade:      rich.Report.SecurityGrade,
		Policy:             opts.Policy,
		Diagram:            rich.Diagram,
		CriticalFiles:      rich.CriticalFiles,
		HistoryLeaks:       rich.HistoryLeaks,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildState diverged from historical construction:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestBuildStateTargetFilter proves targeted mode keeps only the matching core
// finding and drops the other scanner sources, matching the old CLI filter.
func TestBuildStateTargetFilter(t *testing.T) {
	opts := sampleOpts()
	opts.Target = Target{RuleID: "CS-A", File: "a.go", Line: 10}
	rich := sampleRich()
	rich.NFR = nil

	state := BuildState(opts, rich)

	if len(state.CoreFindings) != 1 || state.CoreFindings[0].ID != "CS-A" {
		t.Fatalf("target filter should keep only CS-A, got %+v", state.CoreFindings)
	}
	if state.ExternalFindings != nil || state.NFRFindings != nil || state.DeployFindings != nil || state.NetworkFindings != nil {
		t.Fatalf("target mode must clear non-core sources")
	}
}

// TestRunStateNilGuards proves defensive input validation.
func TestRunStateNilGuards(t *testing.T) {
	if _, err := RunState(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil state")
	}
	if _, err := RunState(context.Background(), &graph.AgentState{}, nil); err == nil {
		t.Fatal("expected error for nil client")
	}
}

// The pre-triage score the agent prints covers every scanner under the run's
// policy: a --quality-findings report flag leaves out a code-quality finding
// that the project configuration scores, and the default policy (block)
// counts one the configuration only reports.
func TestPreTriageScoreFollowsTheRunPolicy(t *testing.T) {
	var rich llm.RichScanResult
	rich.Report.Results = []core.CheckResult{
		{ID: "ENTR-12", Name: "God File Detected", Status: core.Absent, Severity: "LOW", File: "app/views.py", Line: 1, Subcategory: healthcheck.SubcategoryQuality},
	}

	rich.Report.HealthCheck.Policy = healthcheck.DefaultPolicy()
	reported := scoreUnderPolicy(rich, healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsReport})
	if reported.Report.SecurityScore != 100 || reported.Report.HealthCheck.Breakdown.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 1 {
		t.Fatalf("score %d, breakdown %+v; want the quality finding reported only", reported.Report.SecurityScore, reported.Report.HealthCheck.Breakdown)
	}

	rich.Report.HealthCheck.Policy = healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsReport}
	blocked := scoreUnderPolicy(rich, healthcheck.DefaultPolicy())
	if blocked.Report.SecurityScore >= 100 || blocked.Report.HealthCheck.Policy.QualityFindings != healthcheck.QualityFindingsBlock {
		t.Fatalf("score %d, policy %+v; want the run's default policy (block) to count the finding", blocked.Report.SecurityScore, blocked.Report.HealthCheck.Policy)
	}
}
