package graph

import (
	"encoding/json"

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
	ThreatModel         *ThreatModel               // Structured threat model analysis
	ThreatModelSource   string                     // "llm" | "cache_skipped" | "skipped_empty"
	FindingDispositions []FindingDisposition       // TP/FP/NR classification per finding
	ClassificationAudit []ClassificationAuditEntry // Raw structured LLM responses and validation decisions
	PoCResults          []PoCResult                // PoC verification results

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
	ID        string          `json:"id"`
	Type      string          `json:"type"` // "core", "external", "nfr", "deploy", "network"
	Source    string          `json:"source,omitempty"`
	Severity  string          `json:"severity"`
	File      string          `json:"file,omitempty"`
	Line      int             `json:"line,omitempty"`
	Message   string          `json:"message"`
	Snippet   string          `json:"code_snippet,omitempty"`
	ExtraData string          `json:"extra_data,omitempty"`
	Origins   []FindingOrigin `json:"origins,omitempty"`
	VulnID    string          `json:"vuln_id,omitempty"` // CS-XXX-NNN format
}

// FindingOrigin keeps every scanner/rule that corroborated a semantic issue.
// Deduplication reduces user-visible issue count without losing provenance.
type FindingOrigin struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
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
	Endpoint   string `json:"endpoint"`
	Type       string `json:"type"`
	Trusted    bool   `json:"trusted"`
	Validation string `json:"validation"`
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
	// trail: "llm" | "cache" | "deterministic" | "nr-fallback".
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
