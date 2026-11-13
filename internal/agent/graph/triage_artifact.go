package graph

import (
	"fmt"
	"math"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// TriageArtifactSchemaVersion is incremented only for incompatible changes to
// triage-findings.json: a field removed or renamed, or a field whose type or
// meaning changes, such as the form of an identifier, how paths are written
// or what one entry stands for. Adding a field does not increment it.
// Consumers must reject versions they do not understand. An increment breaks
// the public contract, so it ships only in a major release (see
// "Compatibility and versioning" in CONTRIBUTING.md).
//
// Additions such as stable_id, class, the dependency fields, per-origin
// locations and the scope counts kept version 1. v1.14.0 also changed
// meanings without an increment, before this rule was written down: paths
// became project-relative, vuln_id took the CS-<CLASS>-<hex> form, one
// finding may stand for several detectors, and
// health_check.breakdown.count_by_class became keyed by canonical class
// (per-rule counts moved to count_by_rule). Version 1 means the fields as
// v1.14.0 writes them. The only in-tree consumer that parses the file
// (hostrun approval) compares vuln_id verbatim and was unaffected.
const TriageArtifactSchemaVersion = 1

// TriageFindingsArtifact is the canonical, machine-readable record of an AI
// triage. Reports are derived views; this artifact preserves every original
// finding, including findings classified as false positives. It is written
// for an incomplete triage too: triage_status is then "failed", the reason is
// recorded, and the findings the model never classified carry
// disposition_source "triage-failed".
type TriageFindingsArtifact struct {
	SchemaVersion int `json:"schema_version"`
	// TriageStatus is "complete" or "failed".
	TriageStatus string `json:"triage_status"`
	// TriageFailureReason, TriageFailureStage and TriageFailureCause
	// ("provider_failure" or "no_verdict") explain a failed triage.
	TriageFailureReason string             `json:"triage_failure_reason,omitempty"`
	TriageFailureStage  string             `json:"triage_failure_stage,omitempty"`
	TriageFailureCause  string             `json:"triage_failure_cause,omitempty"`
	TotalFindings       int                `json:"total_findings"`
	HealthCheck         healthcheck.Result `json:"health_check"`
	LLMUsage            LLMUsageArtifact   `json:"llm_usage"`
	VerdictCache        VerdictCacheStats  `json:"verdict_cache"`
	ArtifactCache       ArtifactCacheStats `json:"artifact_cache"`
	PoCStats            PoCStats           `json:"poc_verification"`
	// ThreatModelSource is "llm", "cache_skipped", "skipped_empty",
	// "failed_parse" or "failed".
	ThreatModelSource string `json:"threat_model_source,omitempty"`
	// StageFailures lists LLM stages that degraded or fell back to a
	// deterministic rendering.
	StageFailures []StageFailure `json:"stage_failures,omitempty"`
	// Classification shows how the verdicts were produced, including how many
	// findings the model left without one.
	Classification ClassificationStats `json:"classification"`
	// Suppressions counts the findings project decisions dismissed.
	Suppressions SuppressionSummary `json:"suppressions"`
	// Scope counts the findings the project configuration removed before
	// triage: ignore.rules entries and inline aitriage-ignore comments.
	Scope    ScopeSummary     `json:"scope"`
	Findings []TriagedFinding `json:"findings"`
	// ClassificationAudit records raw structured model responses and their
	// validation outcome. It is sensitive triage evidence and follows the same
	// artifact retention policy as the finding inventory.
	ClassificationAudit []ClassificationAuditEntry `json:"classification_audit"`
}

// LLMUsageArtifact records provider-reported token usage. Cost is deliberately
// not estimated here because pricing depends on provider, model, region,
// prompt-cache tier, and contract.
type LLMUsageArtifact struct {
	Total                llm.Usage            `json:"total"`
	Stages               map[string]llm.Usage `json:"stages,omitempty"`
	CacheTelemetryStatus string               `json:"cache_telemetry_status"`
	// Provider and Model name what served the requests, the model after
	// defaults, so a change of verdicts between runs can be traced to a
	// change of model. Never an endpoint or a credential.
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// Temperature is the sampling temperature the requests carried, such as
	// "0", or "provider default" when they carried none.
	Temperature string `json:"temperature,omitempty"`
}

// TriagedFinding pairs one original scanner finding with its one validated
// disposition. FindingIndex preserves original scanner order and makes the
// 1:1 mapping independently auditable.
//
// A finding stands for every scanner report of one defect: finding.id,
// finding.source and finding.message are the representative report's, and
// finding.origins[] is the full list of reports (type, source, rule_id,
// file, line, severity). Consumers that gate on a scanner or a rule, such as
// "fail when Gitleaks found a secret", must check origins[]; for a hardcoded
// secret the representative is Gitleaks whenever Gitleaks reported it.
type TriagedFinding struct {
	FindingIndex int                `json:"finding_index"`
	Finding      EnrichedFinding    `json:"finding"`
	Disposition  FindingDisposition `json:"disposition"`
}

// BuildTriageFindingsArtifact builds an export only from a complete, unambiguous
// triage result. It deliberately keeps duplicate findings: deduplication is an
// LLM optimization, while this artifact is the audit inventory of all inputs.
func BuildTriageFindingsArtifact(state *AgentState) (TriageFindingsArtifact, error) {
	if state == nil {
		return TriageFindingsArtifact{}, fmt.Errorf("build triage artifact: nil agent state")
	}
	if err := validateFindingDispositions(state.FindingDispositions, len(state.EnrichedFindings)); err != nil {
		return TriageFindingsArtifact{}, fmt.Errorf("build triage artifact: incomplete dispositions: %w", err)
	}

	findings := make([]TriagedFinding, len(state.EnrichedFindings))
	for _, disposition := range state.FindingDispositions {
		findings[disposition.FindingIndex] = TriagedFinding{
			FindingIndex: disposition.FindingIndex,
			Finding:      state.EnrichedFindings[disposition.FindingIndex],
			Disposition:  disposition,
		}
	}

	status := TriageStatusComplete
	if state.TriageFailed() {
		status = TriageStatusFailed
	}
	return TriageFindingsArtifact{
		SchemaVersion:       TriageArtifactSchemaVersion,
		TriageStatus:        status,
		TriageFailureReason: state.TriageFailureReason,
		TriageFailureStage:  state.TriageFailureStage,
		TriageFailureCause:  state.TriageFailureCause,
		TotalFindings:       len(findings),
		HealthCheck:         state.HealthCheck,
		LLMUsage:            buildLLMUsageArtifact(state),
		VerdictCache:        state.VerdictCacheStats,
		ArtifactCache:       state.ArtifactCacheStats,
		PoCStats:            state.PoCStats,
		ThreatModelSource:   state.ThreatModelSource,
		StageFailures:       state.StageFailures,
		Classification:      buildClassificationStats(state),
		Suppressions:        state.Suppressions,
		Scope:               ScopeSummary{IgnoredByConfig: state.IgnoredByConfig, SuppressedInline: state.SuppressedInline},
		Findings:            findings,
		ClassificationAudit: state.ClassificationAudit,
	}, nil
}

// ClassificationStats summarises how dispositions were produced. NRFallbackRate
// is the share of findings the model was asked to classify that ended without
// a verdict (nr-fallback or triage-failed); a rising rate means the model is
// dropping items and the batch size or retries need attention.
type ClassificationStats struct {
	BatchSize  int `json:"batch_size"`
	MaxRetries int `json:"max_retries"`
	// BySource counts every finding's disposition_source.
	BySource map[string]int `json:"by_source"`
	// ModelBound counts findings whose verdict had to come from the model in
	// this run: classified by it, or left unclassified.
	ModelBound     int     `json:"model_bound"`
	Unclassified   int     `json:"unclassified"`
	NRFallback     int     `json:"nr_fallback"`
	TriageFailed   int     `json:"triage_failed"`
	NRFallbackRate float64 `json:"nr_fallback_rate"`
}

func buildClassificationStats(state *AgentState) ClassificationStats {
	stats := ClassificationStats{
		BatchSize:  GetBatchSize(state),
		MaxRetries: classifyMaxRetries(),
		BySource:   map[string]int{},
	}
	for _, d := range state.FindingDispositions {
		if d.DispositionSource != "" {
			stats.BySource[d.DispositionSource]++
		}
	}
	stats.NRFallback = stats.BySource[dispositionSourceNRFallback]
	stats.TriageFailed = stats.BySource[dispositionSourceTriageFailed]
	stats.Unclassified = stats.NRFallback + stats.TriageFailed
	stats.ModelBound = stats.BySource[dispositionSourceLLM] + stats.Unclassified
	if stats.ModelBound > 0 {
		rate := float64(stats.Unclassified) / float64(stats.ModelBound)
		stats.NRFallbackRate = math.Round(rate*10000) / 10000
	}
	return stats
}

// RecordLLMSettings notes what client's requests carry, for the verdict cache
// key and llm_usage in triage-findings.json: the temperature, and the
// provider and model after the client's defaults. Callers of Run record them
// before the run and again after it: an endpoint that refuses the temperature
// makes the client drop it mid-run, and the record must show what the
// requests carried, while the cache key keeps the starting value, which is
// the same on every run against that endpoint. A client that does not know
// its model, such as a host agent, leaves the configured identity in the
// record and the key.
func (s *AgentState) RecordLLMSettings(client llm.Client) {
	if s == nil {
		return
	}
	s.LLMTemperature = llm.EffectiveTemperature(client)
	if provider, model := llm.RequestModel(client); model != "" {
		s.LLMRequestProvider, s.LLMRequestModel = provider, model
	}
}

func buildLLMUsageArtifact(state *AgentState) LLMUsageArtifact {
	stages := make(map[string]llm.Usage, len(state.StageUsage))
	for name, usage := range state.StageUsage {
		if isZeroUsage(usage) {
			continue
		}
		stages[name] = usage
	}
	if len(stages) == 0 {
		stages = nil
	}

	status := "provider_did_not_report"
	if state.TotalUsage.CacheTelemetryReported {
		status = "reported"
	}

	return LLMUsageArtifact{
		Total:                state.TotalUsage,
		Stages:               stages,
		CacheTelemetryStatus: status,
		Provider:             firstNonEmpty(state.LLMRequestProvider, state.LLMProvider),
		Model:                firstNonEmpty(state.LLMRequestModel, state.LLMModel),
		Temperature:          state.LLMTemperature,
	}
}
