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
	// Reports lists the reports of the other scanners (external, NFR, deploy)
	// a decision removed before triage. Another detector's report of the same
	// defect is covered by the same decision (see dismissals.of).
	Reports []DismissedReport `json:"-"`
}

// SuppressionDecision is the reason and note of one recorded decision.
type SuppressionDecision struct {
	Reason string
	Note   string
}

// ReportRef identifies one scanner report by what decides which defect it
// describes. File is project-relative (ProjectRelativePath).
type ReportRef struct {
	Type             string
	Source           string
	RuleID           string
	File             string
	Line             int
	Package          string
	InstalledVersion string
}

// DismissedReport is a scanner report a recorded decision dismissed.
type DismissedReport struct {
	ReportRef
	Decision SuppressionDecision
}

// DefectKey returns the key under which a report merges with the other
// detectors of the same defect (see semanticFindingKey). It returns false
// when no canonical class covers the report's rule: such a report merges only
// with identical reports, so a decision about it covers nothing else.
func DefectKey(r ReportRef) (string, bool) {
	f := EnrichedFinding{ID: r.RuleID, Type: r.Type, Source: r.Source, File: r.File, Line: r.Line, Package: r.Package, InstalledVersion: r.InstalledVersion}
	if _, ok := findingClass(f); !ok {
		return "", false
	}
	return semanticFindingKey(f), true
}

// CoreDecisionKey identifies a built-in finding the way the graph matches
// project decisions to it. file is the project-relative path, as
// ProjectRelativePath returns it: findings enter the graph that way.
func CoreDecisionKey(ruleID, file string, line int) string {
	return hcKey(ruleID, file, line)
}

// dismissal is one recorded decision about one scanner report.
type dismissal struct {
	source, ruleID string
	// reason is a .aitriage-suppressions.json reason, or
	// SuppressionReasonAuditLog for a dismissal in the audit log, whose
	// status is then set.
	reason, note string
	status       core.AuditStatus
}

// dismissals indexes the decisions of a run the way findings are matched to
// them.
type dismissals struct {
	// byOrigin holds the dismissed built-in reports, keyed like
	// CoreDecisionKey; they stay in the inventory as origins of findings.
	byOrigin map[string]dismissal
	// byDefect holds every dismissed report of a canonical class by its
	// DefectKey, including the reports removed before triage.
	byDefect map[string]dismissal
}

// recordedDismissals collects the decisions of a run: built-in findings
// dismissed in the audit log or by a project decision, and the reports of
// other scanners a project decision removed.
func recordedDismissals(state *AgentState) dismissals {
	paths := newPathResolver(state.ProjectPath)
	d := dismissals{byOrigin: map[string]dismissal{}, byDefect: map[string]dismissal{}}
	for _, result := range state.CoreFindings {
		if result.AuditStatus != core.AuditStatusIgnored && result.AuditStatus != core.AuditStatusTriage {
			continue
		}
		file := paths.relative(result.File)
		key := hcKey(result.ID, file, result.Line)
		dm := dismissal{source: "aitriage", ruleID: result.ID, reason: SuppressionReasonAuditLog, status: result.AuditStatus}
		if decision, ok := state.Suppressions.Core[key]; ok && decision.Reason != SuppressionReasonAuditLog {
			dm.reason, dm.note = decision.Reason, decision.Note
		}
		if _, seen := d.byOrigin[key]; !seen {
			d.byOrigin[key] = dm
		}
		if defect, ok := DefectKey(ReportRef{Type: "core", Source: "aitriage", RuleID: result.ID, File: file, Line: result.Line}); ok {
			if _, seen := d.byDefect[defect]; !seen {
				d.byDefect[defect] = dm
			}
		}
	}
	for _, r := range state.Suppressions.Reports {
		defect, ok := DefectKey(r.ReportRef)
		if !ok {
			continue
		}
		if _, seen := d.byDefect[defect]; !seen {
			d.byDefect[defect] = dismissal{source: r.Source, ruleID: r.RuleID, reason: firstNonEmpty(r.Decision.Reason, SuppressionReasonFalsePositive), note: r.Decision.Note}
		}
	}
	return d
}

// of returns the decision that covers a finding. A finding is one defect,
// however many detectors reported it, and a person decided about it: a
// dismissal of any detector behind it covers it, and so does a dismissal of a
// report of the same canonical class at the same location that was removed
// before triage. A decision never covers a finding of another class, even on
// the same line.
func (d dismissals) of(f EnrichedFinding) (dismissal, bool) {
	if isEnvironmentFinding(f) {
		return dismissal{}, false
	}
	for _, origin := range findingOrigins(f) {
		if !strings.EqualFold(origin.Type, "core") {
			continue
		}
		for _, key := range originKeys(f, origin) {
			if dm, ok := d.byOrigin[key]; ok {
				return dm, true
			}
		}
	}
	if len(d.byDefect) > 0 {
		if _, classified := findingClass(f); classified {
			if dm, ok := d.byDefect[semanticFindingKey(f)]; ok {
				return dm, true
			}
		}
	}
	return dismissal{}, false
}

// originKeys are the keys a decision about one origin of f may be recorded
// under: the origin's own location, which is what the scanner reported, and
// the finding's location for origins built without one.
func originKeys(f EnrichedFinding, origin FindingOrigin) []string {
	own := hcKey(origin.RuleID, origin.File, origin.Line)
	merged := hcKey(origin.RuleID, f.File, f.Line)
	if own == merged {
		return []string{own}
	}
	return []string{own, merged}
}

// isEnvironmentFinding reports whether a finding describes the scanning host
// rather than the repository.
func isEnvironmentFinding(f EnrichedFinding) bool {
	return strings.EqualFold(strings.TrimSpace(f.Type), "network")
}

// deterministicDispositions decides, without the LLM, the findings that must
// never reach it. The map is keyed by EnrichedFindings index.
func deterministicDispositions(state *AgentState) map[int]FindingDisposition {
	recorded := recordedDismissals(state)

	out := make(map[int]FindingDisposition)
	for i, finding := range state.EnrichedFindings {
		var d FindingDisposition
		switch {
		case isEnvironmentFinding(finding):
			d = networkProbeDisposition()
		default:
			decision, ok := recorded.of(finding)
			if !ok {
				continue
			}
			d = suppressedDisposition(finding, decision)
		}
		d.FindingIndex = i
		d.FindingID = finding.VulnID
		d.Fingerprint = Fingerprint(finding)
		out[i] = d
	}
	return out
}

// findingOrigins returns the scanners behind a finding; a finding built
// without enrichment stands for itself.
func findingOrigins(f EnrichedFinding) []FindingOrigin {
	if len(f.Origins) > 0 {
		return f.Origins
	}
	return []FindingOrigin{originOf(f)}
}

// suppressedDisposition records a dismissed finding with the decision behind
// it. When the finding stands for more than the dismissed report, the
// rationale says which report the decision was recorded for.
func suppressedDisposition(f EnrichedFinding, decision dismissal) FindingDisposition {
	rationale := fmt.Sprintf("Dismissed in the AITriage audit log (status %s).", decision.status)
	if decision.reason != SuppressionReasonAuditLog {
		rationale = fmt.Sprintf("Dismissed by a project decision in .aitriage-suppressions.json (%s).", decision.reason)
		if note := strings.TrimSpace(decision.note); note != "" {
			rationale += " Note: " + note
		}
	}
	origins := findingOrigins(f)
	if len(origins) > 1 || !hasOriginRule(origins, decision.ruleID) {
		defect := firstNonEmpty(f.Class, f.ID)
		rationale += fmt.Sprintf(" The decision was recorded for %s %s and covers every detector's report of this %s finding at %s.",
			decision.source, decision.ruleID, defect, displayLocation(f.File, f.Line))
	}
	return FindingDisposition{
		Disposition:       "False Positive",
		Rationale:         rationale + " Not sent to the LLM; excluded from the score and the gate.",
		DispositionSource: dispositionSourceSuppressed,
	}
}

func hasOriginRule(origins []FindingOrigin, ruleID string) bool {
	for _, origin := range origins {
		if strings.EqualFold(origin.RuleID, ruleID) {
			return true
		}
	}
	return false
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
