package graph

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// AgentHandoffSchemaVersion versions the Web/CI handoff envelope. It is
// independent from TriageArtifactSchemaVersion because the handoff contains
// only actionable findings while triage-findings.json is the full audit log.
const AgentHandoffSchemaVersion = 1

// AgentHandoff is the single deterministic representation consumed by both
// GitHub Actions and the Web UI. No LLM is called while building it.
type AgentHandoff struct {
	SchemaVersion             int         `json:"schema_version"`
	GeneratedAt               time.Time   `json:"generated_at"`
	SummaryMarkdown           string      `json:"summary_markdown"`
	RemediationPromptMarkdown string      `json:"remediation_prompt_markdown"`
	AgentData                 AIAgentData `json:"agent_data"`
}

type AIAgentData struct {
	ScanDate        string                      `json:"scan_date"`
	Score           int                         `json:"score"`
	Grade           string                      `json:"grade"`
	GateStatus      string                      `json:"gate_status"`
	ScannerCoverage string                      `json:"scanner_coverage"`
	Scanners        []external.ScannerExecution `json:"scanners,omitempty"`
	Policy          struct {
		Profile string `json:"profile"`
		FailOn  string `json:"fail_on"`
	} `json:"policy"`
	Stats struct {
		TruePositives  int `json:"true_positives"`
		NeedsReview    int `json:"needs_review"`
		FalsePositives int `json:"false_positives"`
		Total          int `json:"total"`
	} `json:"stats"`
	Findings []AIAgentFinding `json:"findings"`
}

type AIAgentFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
	Title          string `json:"title"`
	Disposition    string `json:"disposition"`
	Recommendation string `json:"recommendation,omitempty"`
}

// BuildAgentHandoff builds the canonical actionable handoff. A completed scan
// must have one validated disposition for every finding; ambiguous data is
// rejected instead of being silently published to an AI IDE.
func BuildAgentHandoff(state *AgentState, generatedAt time.Time) (AgentHandoff, error) {
	if state == nil {
		return AgentHandoff{}, fmt.Errorf("build agent handoff: nil agent state")
	}
	if err := validateFindingDispositions(state.FindingDispositions, len(state.EnrichedFindings)); err != nil {
		return AgentHandoff{}, fmt.Errorf("build agent handoff: incomplete dispositions: %w", err)
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	} else {
		generatedAt = generatedAt.UTC()
	}

	actionable, tp, fp, nr := collectActionableFindings(state)
	agentData := buildAIAgentData(state, actionable, tp, fp, nr, generatedAt)

	var prompt strings.Builder
	writeAIRemediationPrompt(&prompt, state, actionable, generatedAt)

	var summary strings.Builder
	writeHumanSummary(&summary, state, actionable, tp, fp, nr)
	summary.WriteString(prompt.String())
	writeAIAgentData(&summary, agentData)
	writeAgentHandoffFooter(&summary, state, fp)

	return AgentHandoff{
		SchemaVersion:             AgentHandoffSchemaVersion,
		GeneratedAt:               generatedAt,
		SummaryMarkdown:           summary.String(),
		RemediationPromptMarkdown: prompt.String(),
		AgentData:                 agentData,
	}, nil
}

func collectActionableFindings(state *AgentState) ([]actionableFinding, int, int, int) {
	tp, fp, nr := 0, 0, 0
	dispositionMap := make(map[int]string, len(state.FindingDispositions))
	for _, disposition := range state.FindingDispositions {
		switch disposition.Disposition {
		case "True Positive":
			tp++
		case "False Positive":
			fp++
		default:
			nr++
		}
		dispositionMap[disposition.FindingIndex] = disposition.Disposition
	}

	actionable := make([]actionableFinding, 0, tp+nr)
	for i, finding := range state.EnrichedFindings {
		disposition := dispositionMap[i]
		if disposition == "False Positive" {
			continue
		}
		message := finding.Message
		if len(message) > 120 {
			message = message[:117] + "..."
		}
		message = strings.ReplaceAll(message, "|", "\\|")
		message = strings.ReplaceAll(message, "\n", " ")

		actionable = append(actionable, actionableFinding{
			vulnID:      finding.VulnID,
			source:      finding.Source,
			severity:    finding.Severity,
			file:        finding.File,
			line:        finding.Line,
			message:     message,
			disposition: disposition,
		})
	}
	return actionable, tp, fp, nr
}

func buildAIAgentData(state *AgentState, actionable []actionableFinding, tp, fp, nr int, generatedAt time.Time) AIAgentData {
	scanners := append([]external.ScannerExecution(nil), state.ScannerExecutions...)
	// Wall-clock durations remain in manifest.json for observability, but they
	// are normalized out of the canonical handoff so direct CI and deferred IDE
	// executions remain byte-for-byte comparable.
	for i := range scanners {
		scanners[i].DurationMs = 0
	}
	data := AIAgentData{
		ScanDate:        generatedAt.Format("2006-01-02"),
		Score:           state.HealthCheck.Score,
		Grade:           state.HealthCheck.Grade,
		ScannerCoverage: state.ScannerCoverage,
		Scanners:        scanners,
		Findings:        make([]AIAgentFinding, 0, len(actionable)),
	}
	if state.HealthCheck.Verdict.Passed {
		data.GateStatus = "PASSED"
	} else {
		data.GateStatus = "FAILED"
	}
	data.Policy.Profile = string(state.HealthCheck.Policy.Profile)
	data.Policy.FailOn = string(state.HealthCheck.Policy.FailOn)
	data.Stats.TruePositives = tp
	data.Stats.NeedsReview = nr
	data.Stats.FalsePositives = fp
	data.Stats.Total = len(state.EnrichedFindings)

	recommendations := make(map[string]string, len(state.FindingDispositions))
	for _, disposition := range state.FindingDispositions {
		if disposition.Disposition != "False Positive" && disposition.Rationale != "" {
			recommendations[disposition.FindingID] = disposition.Rationale
		}
	}
	for _, finding := range actionable {
		item := AIAgentFinding{
			ID:          finding.vulnID,
			Severity:    finding.severity,
			File:        finding.file,
			Line:        finding.line,
			Title:       strings.ReplaceAll(finding.message, "\\|", "|"),
			Disposition: finding.disposition,
		}
		item.Recommendation = recommendations[finding.vulnID]
		data.Findings = append(data.Findings, item)
	}
	return data
}

func writeAIAgentData(sb *strings.Builder, data AIAgentData) {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	sb.WriteString("\n<details>\n")
	sb.WriteString("<summary>🤖 AI Agent Data (structured findings for Cursor / Claude / Antigravity)</summary>\n\n")
	sb.WriteString("```json\n")
	sb.Write(jsonBytes)
	sb.WriteString("\n```\n\n")
	sb.WriteString("</details>\n")
}

func writeAgentHandoffFooter(sb *strings.Builder, state *AgentState, fpCount int) {
	sb.WriteString("\n---\n")
	if fpCount > 0 {
		_, _ = fmt.Fprintf(sb, "\n_%d false positive(s) suppressed. Download `report.md` artifact for the full audit trail with FP rationale._\n", fpCount)
	}
	if state.TotalUsage.TotalTokens > 0 {
		_, _ = fmt.Fprintf(sb, "\n_LLM usage (provider reported): %s. Cost is not estimated because it depends on provider, model, caching, and billing tier._\n", formatLLMUsage(state.TotalUsage))
	}
	if state.VerdictCacheStats.Enabled {
		// The raw counters answer "did the cache work"; this line answers the
		// question an operator actually asks, which is "what did it save me".
		if reused := verdictReusePercent(state.VerdictCacheStats); reused > 0 {
			_, _ = fmt.Fprintf(sb, "\n_Cache reuse: %d%% of verdicts came from cache, so those findings cost no tokens this run._\n", reused)
		}
		_, _ = fmt.Fprintf(sb, "\n_AITriage verdict cache: %d hits · %d misses · %d stored · %d sensitive skipped · %d stale FP invalidated · saved=%t._\n",
			state.VerdictCacheStats.Hits,
			state.VerdictCacheStats.Misses,
			state.VerdictCacheStats.Stores,
			state.VerdictCacheStats.SkippedSensitive,
			state.VerdictCacheStats.InvalidatedFalsePositives,
			state.VerdictCacheStats.Saved)
	}
	if state.ArtifactCacheStats.Enabled {
		status := "miss"
		if state.ArtifactCacheStats.ExactHit {
			status = "exact hit"
		}
		missReason := state.ArtifactCacheStats.MissReason
		if missReason == "" {
			missReason = "n/a"
		}
		_, _ = fmt.Fprintf(sb, "\n_AITriage artifact cache: %s · restored poc=%t report=%t fixspec=%t · stored=%d · sensitive skipped=%d · corrupt ignored=%t · miss_reason=%s · saved=%t · uncached verdicts=%d · eligibility skipped=%t · integrity failed=%t._\n",
			status,
			state.ArtifactCacheStats.RestoredPoC,
			state.ArtifactCacheStats.RestoredReport,
			state.ArtifactCacheStats.RestoredFixSpec,
			state.ArtifactCacheStats.Stores,
			state.ArtifactCacheStats.SkippedSensitive,
			state.ArtifactCacheStats.CorruptCacheIgnored,
			missReason,
			state.ArtifactCacheStats.Saved,
			state.ArtifactCacheStats.UncachedVerdicts,
			state.ArtifactCacheStats.EligibilitySkipped,
			state.ArtifactCacheStats.IntegrityFailed)
	}
}

// verdictReusePercent reports the share of verdicts served from cache. It
// returns 0 when nothing was classified, so a run with no findings does not
// claim a saving it did not make.
func verdictReusePercent(stats VerdictCacheStats) int {
	total := stats.Hits + stats.Misses
	if total <= 0 {
		return 0
	}
	return stats.Hits * 100 / total
}
