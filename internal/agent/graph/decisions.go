package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// ── Deterministic dispositions decided before any LLM call ───────────────────
//
// Two kinds of findings never need a model verdict, and sending them to the
// LLM cost tokens and produced verdicts that contradicted the gate:
//
//   - Findings a person already dismissed (`aitriage ignore add`, the Web UI,
//     the audit log). The decision is the verdict. The finding stays in the
//     inventory with the reason attached, so a reviewer can disagree.
//   - Network probe results. They describe the machine AITriage ran on, not
//     the repository, and are excluded from the score and the gate anyway.
//
// Both keep one of the three schema dispositions so existing consumers of
// triage-findings.json keep working; disposition_source says why.

// Suppression reasons. The first three mirror .aitriage-suppressions.json;
// SuppressionReasonAuditLog covers dismissals recorded in the AITriage audit
// log (Web UI / TUI) rather than in the decisions file.
const (
	SuppressionReasonFalsePositive = "false_positive"
	SuppressionReasonAcceptedRisk  = "accepted_risk"
	SuppressionReasonWontFix       = "wont_fix"
	SuppressionReasonAuditLog      = "audit_log"
)

// SuppressionSummary records the project decisions applied before triage.
type SuppressionSummary struct {
	// Total counts every finding a decision dismissed, across all scanners.
	Total int `json:"total"`
	// ByReason splits Total by decision reason.
	ByReason map[string]int `json:"by_reason,omitempty"`
	// LoadError is set when the decisions file exists but could not be read;
	// its decisions were then not applied, so the affected findings stay open.
	LoadError string `json:"load_error,omitempty"`
	// Core maps CoreDecisionKey of each dismissed built-in finding to the
	// decision behind it. Such findings stay in the inventory, unlike external
	// ones, which a decision removes. Not serialized: the finding's own
	// disposition rationale carries the decision.
	Core map[string]SuppressionDecision `json:"-"`
}

// SuppressionDecision is the reason and note of one recorded decision.
type SuppressionDecision struct {
	Reason string
	Note   string
}

// CoreDecisionKey identifies a built-in finding the way the graph matches
// project decisions to it.
func CoreDecisionKey(ruleID, file string, line int) string {
	return hcKey(ruleID, file, line)
}

// isEnvironmentFinding reports whether a finding describes the scanning host
// rather than the repository.
func isEnvironmentFinding(f EnrichedFinding) bool {
	return strings.EqualFold(strings.TrimSpace(f.Type), "network")
}

// deterministicDispositions decides, without the LLM, the findings that must
// never reach it. The map is keyed by EnrichedFindings index.
func deterministicDispositions(state *AgentState) map[int]FindingDisposition {
	dismissed := make(map[string]core.AuditStatus)
	for _, result := range state.CoreFindings {
		if result.AuditStatus == core.AuditStatusIgnored || result.AuditStatus == core.AuditStatusTriage {
			dismissed[hcKey(result.ID, result.File, result.Line)] = result.AuditStatus
		}
	}

	out := make(map[int]FindingDisposition)
	for i, finding := range state.EnrichedFindings {
		var d FindingDisposition
		switch {
		case isEnvironmentFinding(finding):
			d = networkProbeDisposition()
		default:
			status, ok := dismissedCoreStatus(finding, dismissed)
			if !ok {
				continue
			}
			d = suppressedDisposition(finding, status, state.Suppressions)
		}
		d.FindingIndex = i
		d.FindingID = finding.VulnID
		d.Fingerprint = Fingerprint(finding)
		out[i] = d
	}
	return out
}

// dismissedCoreStatus reports whether every scanner behind a finding is a
// dismissed built-in rule. A finding merged with a still-open external or NFR
// origin is not dismissed: that scanner's report has not been decided on.
func dismissedCoreStatus(f EnrichedFinding, dismissed map[string]core.AuditStatus) (core.AuditStatus, bool) {
	if len(dismissed) == 0 {
		return "", false
	}
	var status core.AuditStatus
	for _, origin := range findingOrigins(f) {
		if !strings.EqualFold(origin.Type, "core") {
			return "", false
		}
		s, ok := dismissed[hcKey(origin.RuleID, f.File, f.Line)]
		if !ok {
			return "", false
		}
		status = s
	}
	return status, true
}

// findingOrigins returns the scanners behind a finding; a finding built
// without enrichment stands for itself.
func findingOrigins(f EnrichedFinding) []FindingOrigin {
	if len(f.Origins) > 0 {
		return f.Origins
	}
	return []FindingOrigin{originOf(f)}
}

func suppressedDisposition(f EnrichedFinding, status core.AuditStatus, summary SuppressionSummary) FindingDisposition {
	rationale := fmt.Sprintf("Dismissed in the AITriage audit log (status %s).", status)
	for _, origin := range findingOrigins(f) {
		decision, ok := summary.Core[hcKey(origin.RuleID, f.File, f.Line)]
		if !ok || decision.Reason == SuppressionReasonAuditLog {
			continue
		}
		rationale = fmt.Sprintf("Dismissed by a project decision in .aitriage-suppressions.json (%s).", decision.Reason)
		if note := strings.TrimSpace(decision.Note); note != "" {
			rationale += " Note: " + note
		}
		break
	}
	return FindingDisposition{
		Disposition:       "False Positive",
		Rationale:         rationale + " Not sent to the LLM; excluded from the score and the gate.",
		DispositionSource: dispositionSourceSuppressed,
	}
}

func networkProbeDisposition() FindingDisposition {
	return FindingDisposition{
		Disposition:       "Needs Manual Review",
		Rationale:         "Network probe result about the host AITriage ran on, not the repository code. Reported for review; never sent to the LLM and never scored.",
		DispositionSource: dispositionSourceNetworkProbe,
	}
}

// dispositionTally counts dispositions the way the reports present them:
// network probe findings are kept apart because they are not repository
// findings and never reach the score or the gate.
type dispositionTally struct {
	TruePositives  int
	FalsePositives int
	NeedsReview    int
	// Unclassified is the part of NeedsReview with no model verdict at all.
	Unclassified int
	// TriageFailed is the part of Unclassified lost to a provider failure.
	TriageFailed int
	// Suppressed is the part of FalsePositives dismissed by project decisions.
	Suppressed int
	// Network counts network probe findings (outside the three counts above).
	Network int
	// BySource counts every disposition by disposition_source.
	BySource map[string]int
}

func tallyDispositions(state *AgentState) dispositionTally {
	t := dispositionTally{BySource: map[string]int{}}
	for _, d := range state.FindingDispositions {
		if d.DispositionSource != "" {
			t.BySource[d.DispositionSource]++
		}
		if idx := d.FindingIndex; idx >= 0 && idx < len(state.EnrichedFindings) && isEnvironmentFinding(state.EnrichedFindings[idx]) {
			t.Network++
			continue
		}
		switch d.Disposition {
		case "True Positive":
			t.TruePositives++
		case "False Positive":
			t.FalsePositives++
			if d.DispositionSource == dispositionSourceSuppressed {
				t.Suppressed++
			}
		default:
			t.NeedsReview++
			if isUnclassifiedSource(d.DispositionSource) {
				t.Unclassified++
			}
			if d.DispositionSource == dispositionSourceTriageFailed {
				t.TriageFailed++
			}
		}
	}
	return t
}

// dispositionLabel is the status shown in tables. A Needs Manual Review the
// model never produced is labelled as such, so "the model was unsure" and
// "the model never answered" read differently.
func dispositionLabel(d FindingDisposition) string {
	if d.Disposition == "Needs Manual Review" && isUnclassifiedSource(d.DispositionSource) {
		return "Needs Manual Review (unclassified)"
	}
	return d.Disposition
}

// suppressionReasonsLine renders the by-reason counts in a stable order.
func suppressionReasonsLine(summary SuppressionSummary) string {
	if len(summary.ByReason) == 0 {
		return ""
	}
	order := []string{SuppressionReasonFalsePositive, SuppressionReasonAcceptedRisk, SuppressionReasonWontFix, SuppressionReasonAuditLog}
	seen := map[string]bool{}
	var parts []string
	for _, reason := range order {
		if n := summary.ByReason[reason]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, reason))
		}
		seen[reason] = true
	}
	var extra []string
	for reason, n := range summary.ByReason {
		if !seen[reason] && n > 0 {
			extra = append(extra, fmt.Sprintf("%d %s", n, reason))
		}
	}
	sort.Strings(extra)
	return strings.Join(append(parts, extra...), " · ")
}
