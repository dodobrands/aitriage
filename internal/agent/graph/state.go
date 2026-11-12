package graph

import (
	"encoding/json"
	"strconv"
	"strings"

	agentcontext "github.com/dodobrands/aitriage/internal/agent/context"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/entropy"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// AgentState represents the shared state flowing through the orchestrator.
type AgentState struct {
	ProjectPath string
	DeepScan    bool
	BatchSize   int

	// Language is the output language for generated narrative (report, fix spec,
	// summary). Technical identifiers stay verbatim in every language. It is
	// part of the verdict/artifact cache namespace, since the same findings
	// rendered in a different language are different artifacts.
	Language string

	// RunwayProgress is optional; web Runway uses it to persist live progress.
	RunwayProgress func(step int, progressMessage string)

	// Resolved LLM identity (never credentials). Cache keys must reflect the
	// provider/model that actually produced the verdicts; env vars alone miss
	// configurations coming from CLI flags, yaml config, or API-key
	// auto-detection. Empty fields fall back to the env-derived defaults.
	LLMProvider        string
	LLMModel           string
	LLMBaseURL         string
	LLMDisableThinking bool

	// Deterministic Go findings
	CoreFindings      []core.CheckResult
	ExternalFindings  []external.UnifiedFinding
	NFRFindings       []nfr.NFRFinding
	DeployFindings    []deployaudit.DeployFinding
	NetworkFindings   []network.NetworkFinding
	ScannerExecutions []external.ScannerExecution
	ScannerCoverage   string

	SecurityScore int
	SecurityGrade string

	// HealthCheck holds the unified, multi-source Security Health Check result.
	// It is the authoritative security posture score, recomputed after AI
	// triage so that False Positives no longer penalise the repository.
	HealthCheck healthcheck.Result
	Policy      healthcheck.Policy

	// Repository context (gathered by gatherRepoContext)
	RepoContext *agentcontext.RepoContext

	// Data from scanners that was previously lost
	CriticalFiles []entropy.CriticalFile
	HistoryLeaks  []entropy.HistoryLeak
	Diagram       string

	// Map-Reduce state
	EnrichedFindings []EnrichedFinding
	Batches          [][]EnrichedFinding // Deprecated: runWorkers removed (June 2026)
	TriagedResults   []string            // Deprecated: runWorkers removed (June 2026)

	// SecureCoder-enhanced fields
	ThreatModel *ThreatModel // Structured threat model analysis
	// ThreatModelSource is "llm" | "cache_skipped" | "skipped_empty" |
	// "failed_parse" (unparseable after repair retries; triage ran without
	// it) | "failed" (provider failure).
	ThreatModelSource   string
	FindingDispositions []FindingDisposition       // TP/FP/NR classification per finding
	ClassificationAudit []ClassificationAuditEntry // Raw structured LLM responses and validation decisions
	PoCResults          []PoCResult                // PoC verification results

	// TriageStatus is TriageStatusComplete or TriageStatusFailed. A failed
	// triage still carries one disposition per finding: the ones the model
	// never classified are Needs Manual Review with source "triage-failed".
	TriageStatus        string
	TriageFailureReason string // redacted, single-line provider error
	TriageFailureStage  string // "threat_model" | "classification"
	// TriageFailureCause is TriageFailureCauseProvider (the provider failed)
	// or TriageFailureCauseNoVerdict (no reply carried a verdict for some
	// findings after every retry).
	TriageFailureCause string
	// StageFailures lists LLM stages that degraded or fell back to a
	// deterministic rendering instead of failing the run.
	StageFailures []StageFailure

	// Suppressions summarises the project decisions (.aitriage-suppressions.json
	// and the audit log) applied before triage. Suppressed findings are never
	// sent to the LLM.
	Suppressions SuppressionSummary

	// IgnoredByConfig counts findings removed by .aitriage.yaml ignore.rules,
	// keyed by the entry as written; SuppressedInline counts findings silenced
	// by an aitriage-ignore comment, keyed by "source:rule". Both were removed
	// before triage and only their counts remain.
	IgnoredByConfig  map[string]int
	SuppressedInline map[string]int

	// LLM usage tracking (accumulated across all Chat calls)
	TotalUsage         llm.Usage
	StageUsage         map[string]llm.Usage
	VerdictCacheStats  VerdictCacheStats
	ArtifactCacheStats ArtifactCacheStats
	PoCStats           PoCStats

	// Outputs
	ReportMarkdown  string // Full report (includes FP rationale) → artifact
	SummaryMarkdown string // Actionable summary (TP + NR only) → GHA Step Summary
	AIFixSpec       string
	AgentHandoff    *AgentHandoff // Canonical typed CI/Web handoff built with SummaryMarkdown
}

// EnrichedFinding is a unified representation of any finding with its source snippet attached.
type EnrichedFinding struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "core", "external", "nfr", "deploy", "network"
	Source   string `json:"source,omitempty"`
	Severity string `json:"severity"`
	// File is relative to the project root, with forward slashes. A path
	// outside the root stays absolute.
	File      string          `json:"file,omitempty"`
	Line      int             `json:"line,omitempty"`
	Message   string          `json:"message"`
	Snippet   string          `json:"code_snippet,omitempty"`
	ExtraData string          `json:"extra_data,omitempty"`
	Origins   []FindingOrigin `json:"origins,omitempty"`
	// VulnID is the display id, CS-<CLASS>-<first hex digits of StableID>.
	VulnID string `json:"vuln_id,omitempty"`
	// StableID identifies the finding across runs without depending on its
	// line number (see assignStableIDs).
	StableID string `json:"stable_id,omitempty"`
	// Class is the canonical defect class the finding was merged under
	// (healthcheck.ClassifyRule); empty when no class covers its rule.
	Class string `json:"class,omitempty"`
	// Package, InstalledVersion, FixedVersion and PrimaryURL describe a
	// dependency advisory.
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	PrimaryURL       string `json:"primary_url,omitempty"`
}

// FindingOrigin keeps every scanner/rule that corroborated a semantic issue.
// Deduplication reduces user-visible issue count without losing provenance.
type FindingOrigin struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	// File, Line and Severity are what this scanner reported, which may differ
	// from the merged finding: a project-level rule has no file, and each
	// detector rates the defect on its own scale.
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// ── SecureCoder Threat Model Types ───────────────────────────────────────────

// ThreatModel holds the structured output from the LLM threat model step.
type ThreatModel struct {
	ComponentOverview  string       `json:"component_overview"`
	EntryPoints        []EntryPoint `json:"entry_points"`
	TrustBoundaries    TrustBounds  `json:"trust_boundaries"`
	SensitiveDataPaths []DataPath   `json:"sensitive_data_paths"`
	PrivilegedActions  []PrivAction `json:"privileged_actions"`
	PriorityAreas      []string     `json:"priority_areas"`
}

// EntryPoint describes a point where external data enters the system.
type EntryPoint struct {
	Endpoint   string       `json:"endpoint"`
	Type       string       `json:"type"`
	Trusted    FlexibleBool `json:"trusted"`
	Validation string       `json:"validation"`
}

// FlexibleBool decodes the boolean shapes models actually emit: true/false,
// "true"/"false", "yes"/"no", 1/0, and null. One quoted boolean used to make
// the whole threat model unparseable and abort the run. Anything that is not
// recognisably true decodes as false, the conservative reading for "trusted".
// It always encodes as a plain JSON boolean.
type FlexibleBool bool

// UnmarshalJSON implements json.Unmarshaler and never fails.
func (b *FlexibleBool) UnmarshalJSON(data []byte) error {
	*b = FlexibleBool(parseLooseBool(data))
	return nil
}

func parseLooseBool(data []byte) bool {
	text := strings.TrimSpace(string(data))
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = strings.TrimSpace(unquoted)
	}
	switch strings.ToLower(text) {
	case "true", "yes", "y", "on", "1":
		return true
	}
	if number, err := strconv.ParseFloat(text, 64); err == nil {
		return number != 0
	}
	return false
}

// TrustBounds describes authentication/authorization assumptions.
type TrustBounds struct {
	Authentication string `json:"authentication"`
	Authorization  string `json:"authorization"`
	ImplicitTrust  string `json:"implicit_trust"`
}

// DataPath describes a flow of sensitive data through the system.
type DataPath struct {
	DataType    string `json:"data_type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protection  string `json:"protection"`
}

// PrivAction describes a privileged operation.
type PrivAction struct {
	Action   string `json:"action"`
	Location string `json:"location"`
	Guard    string `json:"guard"`
}

// DispositionEvidence is the structured, checkable basis for an LLM verdict.
// Only evidence that passes deterministic validation may suppress a finding.
type DispositionEvidence struct {
	// Basis is one of: test_only or code_mitigation. Other values are retained
	// in the audit trail but cannot authorize a False Positive suppression.
	Basis string `json:"basis"`
	File  string `json:"file,omitempty"`
	Line  int    `json:"line,omitempty"`
	// Observed is a literal source fragment for code_mitigation.
	Observed string `json:"observed,omitempty"`
}

// ClassificationAuditEntry preserves the exact response and index mapping for
// one LLM classification request. It is intentionally stored in the canonical
// artifact so a weak model's output can be audited without relying on logs.
type ClassificationAuditEntry struct {
	Attempt int `json:"attempt"`
	// UniqueFindingIndices are indexes after exact-fingerprint deduplication.
	// Fingerprints link them back to every original record in findings.
	UniqueFindingIndices   []int            `json:"unique_finding_indices"`
	FindingIDs             []string         `json:"finding_ids"`
	Fingerprints           []string         `json:"fingerprints"`
	RawResponse            string           `json:"raw_response"`
	ParseError             string           `json:"parse_error,omitempty"`
	AcceptedFindingIndices []int            `json:"accepted_finding_indices,omitempty"`
	Rejected               []AuditRejection `json:"rejected,omitempty"`
	// Downgraded lists verdicts accepted in a weaker form than the model
	// gave, for example a False Positive kept as Needs Manual Review by policy.
	Downgraded []AuditRejection `json:"downgraded,omitempty"`
}

// AuditRejection records why an LLM item was not trusted and became NR.
type AuditRejection struct {
	FindingIndex int    `json:"finding_index"`
	Reason       string `json:"reason"`
}

// FindingDisposition records the TP/FP/NR classification for a single finding.
type FindingDisposition struct {
	FindingIndex int    `json:"finding_index"`
	FindingID    string `json:"finding_id"`
	Disposition  string `json:"disposition"` // "True Positive", "False Positive", "Needs Manual Review"
	Rationale    string `json:"rationale"`
	// Confidence is the model's self-reported certainty: "high" | "medium" | "low".
	Confidence string `json:"confidence,omitempty"`
	// DispositionSource records how the disposition was produced for the audit
	// trail: "llm" | "cache" | "deterministic" | "nr-fallback" (the model gave
	// this finding verdicts of its own and validation rejected each of them,
	// or the finding was over the LLM budget) | "triage-failed" (the provider
	// failed, or no reply carried a verdict for the finding after retries:
	// left out, malformed or empty) | "suppressed" (a recorded project
	// decision) | "network-probe" (describes the scanning host, never scored).
	// It is decided per finding, never by what other findings of the same
	// request got.
	DispositionSource string `json:"disposition_source,omitempty"`
	// Fingerprint is the stable content hash used for dedup/caching.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Evidence is required and deterministically validated before an LLM may
	// classify a finding as False Positive.
	Evidence *DispositionEvidence `json:"evidence,omitempty"`
}

// PoCResult holds reasoning-based PoC verification for a finding.
type PoCResult struct {
	VulnerabilityType string    `json:"vulnerability_type"`
	Severity          string    `json:"severity"`
	AffectedFile      string    `json:"affected_file"`
	ReasoningSteps    []PoCStep `json:"reasoning_steps"`
	Conclusion        string    `json:"conclusion"`      // "Fix verified", "Fix incomplete", "Needs Manual Review"
	ExploitBlocked    *bool     `json:"exploit_blocked"` // nil = unknown
}

// PoCStep is one reasoning step in the PoC verification chain.
type PoCStep struct {
	// JSON numbers preserve labels such as 2.1 without weakening validation of
	// the surrounding PoC result.
	Step        json.Number `json:"step"`
	Description string      `json:"description"`
	Result      string      `json:"result"`
}
