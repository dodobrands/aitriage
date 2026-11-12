// Package pipeline provides the single, shared AI-triage runner used by both
// the CLI `agent` command and the local MCP host-agent workflow.
//
// There must be exactly one path that assembles a graph.AgentState, runs the
// existing graph.Run, computes the post-AI Health Check gate, and produces the
// canonical triage artifact. Both CI/CD (synchronous provider client) and the
// local deferred host-agent client feed the same runner with different
// llm.Client implementations, so their artifacts and gate verdict stay
// byte-for-byte comparable.
package pipeline

import (
	"context"
	"fmt"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// ScanOptions mirrors the scan-orchestration knobs used by the CLI. RunExternal
// defaults to true for a full AI-triage; callers that want a lighter run may
// disable it, but the local host-agent workflow always runs the full set.
type ScanOptions struct {
	ProbeHost    string
	ForceStack   string
	RunExternal  bool
	FullPortScan bool
	// ProbeCompose opts in to probing the hosts declared in docker-compose
	// files. It inspects the network around the scanner, not the code, so it
	// never runs unless asked for.
	ProbeCompose bool `json:",omitempty"`
}

// LLMIdentity carries the resolved provider/model identity (never credentials).
// These populate the AgentState cache-key fields so deferred and synchronous
// runs share the same verdict/artifact cache namespace.
type LLMIdentity struct {
	Provider        string
	Model           string
	BaseURL         string
	DisableThinking bool
	BatchSize       int
}

// Target optionally narrows the run to a single finding (rule id / file / line),
// matching the CLI `--rule-id/--file/--line` behaviour. Zero value means "run
// the full finding set".
type Target struct {
	RuleID string
	File   string
	Line   int
}

// Enabled reports whether a specific finding was targeted.
func (t Target) Enabled() bool { return t.RuleID != "" }

// Options is the complete, deterministic input to a triage run.
type Options struct {
	ProjectPath string
	Scan        ScanOptions
	Policy      healthcheck.Policy
	LLM         LLMIdentity
	Target      Target

	// Progress, when set, is forwarded to graph.AgentState.RunwayProgress so a
	// UI (web Runway or MCP status) can persist live progress.
	Progress func(step int, progressMessage string)
}

// Result is the typed output of a completed run. It exposes both the raw scan
// context and the AI-triage products so callers never rebuild them.
type Result struct {
	State   *graph.AgentState
	Scan    ScanSummary
	Report  string
	Summary string
	FixSpec string
	Gate    healthcheck.Verdict
	Health  healthcheck.Result
}

// ScanSummary captures the pre-AI scanner counts for observability. It is
// derived data only; the authoritative findings live on Result.State.
type ScanSummary struct {
	CoreFindings     int
	ExternalFindings int
	NFRFindings      int
	DeployFindings   int
	NetworkFindings  int
	PreAIScore       int
	PreAIGrade       string
}

// Scan runs only the deterministic scanner orchestration and returns the rich
// result. It is exposed so callers (CLI, MCP) can inspect raw findings and
// build state without duplicating orchestrator wiring.
func Scan(ctx context.Context, opts Options) llm.RichScanResult {
	return orchestrator.RunAllScanners(ctx, scannerOptions(opts))
}

// scannerOptions maps the pipeline options onto the scanner orchestrator.
func scannerOptions(opts Options) orchestrator.Options {
	return orchestrator.Options{
		ProjectPath:  opts.ProjectPath,
		ProbeHost:    opts.Scan.ProbeHost,
		ForceStack:   opts.Scan.ForceStack,
		RunExternal:  opts.Scan.RunExternal,
		FullPortScan: opts.Scan.FullPortScan,
		ProbeCompose: opts.Scan.ProbeCompose,
	}
}

// BuildState assembles the graph.AgentState from a rich scan result. It applies
// the optional single-finding target filter and the project decisions, and
// never diverges between callers, so the CLI and the host-agent workflow hit
// graph.Run identically.
//
// Decisions are applied here rather than in Scan because the host-agent
// workflow persists the raw scan and rebuilds the state on every turn: keeping
// the raw result untouched lets each rebuild recount the decisions by reason.
func BuildState(opts Options, rich llm.RichScanResult) *graph.AgentState {
	if opts.Target.Enabled() {
		rich = applyTarget(rich, opts.Target)
	}
	decisions := applyProjectDecisions(&rich, opts.ProjectPath)

	coverage := "partial"
	if len(rich.MissingRequiredScanners()) == 0 {
		coverage = "full"
	}

	return &graph.AgentState{
		ProjectPath:        opts.ProjectPath,
		DeepScan:           true,
		BatchSize:          opts.LLM.BatchSize,
		RunwayProgress:     opts.Progress,
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
		ScannerCoverage:    coverage,
		SecurityScore:      rich.Report.SecurityScore,
		SecurityGrade:      rich.Report.SecurityGrade,
		Policy:             opts.Policy,
		Diagram:            rich.Diagram,
		CriticalFiles:      rich.CriticalFiles,
		HistoryLeaks:       rich.HistoryLeaks,
		Suppressions:       decisions,
	}
}

// applyTarget mirrors the CLI targeted-mode filter: keep only the matching core
// finding(s) and drop the other scanner sources so the AI focuses on one issue.
func applyTarget(rich llm.RichScanResult, t Target) llm.RichScanResult {
	var filtered []core.CheckResult
	for _, r := range rich.Report.Results {
		if r.ID != t.RuleID {
			continue
		}
		if t.File != "" && r.File != t.File {
			continue
		}
		if t.Line > 0 && r.Line != t.Line {
			continue
		}
		filtered = append(filtered, r)
	}
	rich.Report.Results = filtered
	rich.External = nil
	rich.NFR = nil
	rich.Deploy = nil
	rich.Network = nil
	return rich
}

// RunState executes graph.Run on a prepared state and returns the typed result.
// It is the seam the deferred host-agent client uses: callers own state
// construction (via BuildState) so they can persist/replay it, then delegate
// the graph execution here to guarantee identical stages and gate logic.
func RunState(ctx context.Context, state *graph.AgentState, client llm.Client) (*Result, error) {
	if state == nil {
		return nil, fmt.Errorf("pipeline: nil agent state")
	}
	if client == nil {
		return nil, fmt.Errorf("pipeline: nil llm client")
	}

	if err := graph.Run(ctx, state, client); err != nil {
		return nil, err
	}

	return &Result{
		State:   state,
		Report:  state.ReportMarkdown,
		Summary: state.SummaryMarkdown,
		FixSpec: state.AIFixSpec,
		Gate:    state.HealthCheck.Verdict,
		Health:  state.HealthCheck,
		Scan: ScanSummary{
			CoreFindings:     len(state.CoreFindings),
			ExternalFindings: len(state.ExternalFindings),
			NFRFindings:      len(state.NFRFindings),
			DeployFindings:   len(state.DeployFindings),
			NetworkFindings:  len(state.NetworkFindings),
			PreAIScore:       state.SecurityScore,
			PreAIGrade:       state.SecurityGrade,
		},
	}, nil
}

// Run is the end-to-end convenience entry point: scan, build state, run the
// graph, and return the typed result. The CLI uses this directly; the MCP
// workflow uses Scan + BuildState + RunState so it can persist state between
// deferred turns.
func Run(ctx context.Context, opts Options, client llm.Client) (*Result, error) {
	rich := Scan(ctx, opts)
	// Capture pre-AI scan counts before AI triage mutates state fields.
	preScore := rich.Report.SecurityScore
	preGrade := rich.Report.SecurityGrade

	state := BuildState(opts, rich)
	res, err := RunState(ctx, state, client)
	if err != nil {
		return nil, err
	}
	res.Scan.PreAIScore = preScore
	res.Scan.PreAIGrade = preGrade
	return res, nil
}

// Artifact builds the canonical triage findings artifact from a completed run.
// It reuses the single existing builder so CLI and MCP emit identical schema.
func (r *Result) Artifact() (graph.TriageFindingsArtifact, error) {
	if r == nil || r.State == nil {
		return graph.TriageFindingsArtifact{}, fmt.Errorf("pipeline: nil result state")
	}
	return graph.BuildTriageFindingsArtifact(r.State)
}
