package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// unclassifiedNotes explains the Needs Review findings without an accepted
// model verdict, with the remedy that fits each cause. A verdict that failed
// validation (nr-fallback) needs a person. Retries and smaller batches help
// when the model left findings out of every reply (triage-failed, no
// verdict); they do nothing when the provider itself failed, and the only
// remedy then is to run again once it is available.
func unclassifiedNotes(state *AgentState) []string {
	tally := tallyDispositions(state)
	rejected := tally.Unclassified - tally.TriageFailed
	var notes []string
	if rejected > 0 {
		notes = append(notes, fmt.Sprintf("%d unclassified: the model's verdict did not pass validation, or the finding was over the LLM budget (see `classification_audit`) — review by hand", rejected))
	}
	if tally.TriageFailed > 0 {
		if state.TriageFailureCause == TriageFailureCauseNoVerdict {
			notes = append(notes, fmt.Sprintf("%d not triaged: no reply carried a verdict for them — retries=%d, batch=%d; re-run, raise `AITRIAGE_CLASSIFY_RETRIES` or lower `AITRIAGE_BATCH_SIZE`",
				tally.TriageFailed, classifyMaxRetries(), GetBatchSize(state)))
		} else {
			notes = append(notes, fmt.Sprintf("%d not triaged: the LLM provider failed — repeat the run once the provider is available", tally.TriageFailed))
		}
	}
	return notes
}

// maxTopCriticalIssues bounds the Top Critical Issues list.
const maxTopCriticalIssues = 5

// maxDependencyRows keeps the dependency section of the summary header short;
// the full list is in triage-findings.json.
const maxDependencyRows = 10

// topIssue is one line of Top Critical Issues.
type topIssue struct {
	severity string
	title    string
	location string
}

// topCriticalIssues lists the CRITICAL and then the HIGH actionable findings,
// one line per merged finding and one per vulnerable package rather than per
// advisory, keeping the order in which they appear in the inventory.
func topCriticalIssues(actionable []actionableFinding, groups []dependencyGroup, limit int) []topIssue {
	type entry struct {
		issue topIssue
		order int
	}
	critical := func(severity string) bool {
		switch strings.ToUpper(strings.TrimSpace(severity)) {
		case "CRITICAL", "HIGH":
			return true
		}
		return false
	}
	var entries []entry
	for i, f := range actionable {
		if f.pkg != "" || !critical(f.severity) {
			continue
		}
		entries = append(entries, entry{issue: topIssue{severity: f.severity, title: issueTitle(f.message), location: displayLocation(f.file, f.line)}, order: i})
	}
	for _, g := range groups {
		if !critical(g.severity) {
			continue
		}
		entries = append(entries, entry{issue: topIssue{severity: g.severity, title: g.summaryLine(), location: strings.Join(g.files, ", ")}, order: g.first})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if a, b := severitySortRank(entries[i].issue.severity), severitySortRank(entries[j].issue.severity); a != b {
			return a < b
		}
		return entries[i].order < entries[j].order
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]topIssue, len(entries))
	for i, e := range entries {
		out[i] = e.issue
	}
	return out
}

// issueTitle shortens a finding message for a one-line list: the part before
// the first colon when it is short enough to be a title.
func issueTitle(message string) string {
	if idx := strings.Index(message, ":"); idx > 0 && idx < 60 {
		message = message[:idx]
	}
	return strings.ReplaceAll(message, "\\|", "|")
}

// writeDependencySummary renders one line per vulnerable package.
func writeDependencySummary(sb *strings.Builder, groups []dependencyGroup) {
	if len(groups) == 0 {
		return
	}
	advisories := 0
	for _, g := range groups {
		advisories += g.total
	}
	sb.WriteString("### Vulnerable Dependencies\n\n")
	_, _ = fmt.Fprintf(sb, "_%d open advisories in %d package(s). The score and the gate count every advisory; the version shown after the arrow clears all of a package's advisories that have a fix._\n\n",
		advisories, len(groups))
	for i, g := range rankDependencyGroups(groups) {
		if i == maxDependencyRows {
			_, _ = fmt.Fprintf(sb, "\n_…and %d more package(s) (see `triage-findings.json`)._\n", len(groups)-maxDependencyRows)
			break
		}
		sb.WriteString("- " + g.summaryLine())
		if len(g.files) > 0 {
			sb.WriteString(" — `" + strings.Join(g.files, "`, `") + "`")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
}

// mergedReports counts the repository's scanner reports folded into another
// finding because they described the same defect: every report that entered
// the triage graph, less the findings it produced. Network probe results are
// not repository findings and are left out of both.
func mergedReports(state *AgentState) int {
	reports := len(state.CoreFindings) + len(state.ExternalFindings) + len(state.NFRFindings) + len(state.DeployFindings)
	findings := 0
	for _, f := range state.EnrichedFindings {
		if !isEnvironmentFinding(f) {
			findings++
		}
	}
	if merged := reports - findings; merged > 0 {
		return merged
	}
	return 0
}

// rawResultsNote explains why the scanner table and the findings disagree:
// the table counts each scanner's own reports, the findings count each
// defect once, after the project's exclusions.
func rawResultsNote(state *AgentState) string {
	var parts []string
	if n := mergedReports(state); n > 0 {
		parts = append(parts, fmt.Sprintf("%d merged into findings of the same defect", n))
	}
	if n := totalCount(state.SuppressedInline); n > 0 {
		parts = append(parts, fmt.Sprintf("%d silenced by inline `aitriage-ignore` comments", n))
	}
	if n := totalCount(state.IgnoredByConfig); n > 0 {
		parts = append(parts, fmt.Sprintf("%d removed by `ignore.rules`", n))
	}
	if n := len(state.Suppressions.Reports); n > 0 {
		parts = append(parts, fmt.Sprintf("%d removed by project decisions", n))
	}
	note := "_Raw results are the reports each scanner returned, before they became findings"
	if len(parts) > 0 {
		note += ": " + strings.Join(parts, ", ")
	}
	return note + "._"
}

// partialTimeoutFilesShown caps the files a partial-coverage note names.
const partialTimeoutFilesShown = 5

// partialCoverageNotes returns one note per scanner that analysed files only
// partly, naming the files where rules timed out: those are the findings that
// can differ between runs.
func partialCoverageNotes(executions []external.ScannerExecution) []string {
	var notes []string
	for _, ex := range executions {
		if len(ex.PartialFiles) == 0 {
			continue
		}
		var timedOut []string
		for _, pf := range ex.PartialFiles {
			if pf.Reason == external.PartialTimeout {
				timedOut = append(timedOut, "`"+pf.File+"`")
			}
		}
		note := fmt.Sprintf("_`%s` analysed %d file(s) only partly (%s), so findings in them may be missing.",
			ex.Scanner, external.PartialFileCount(ex.PartialFiles), external.PartialFilesSummary(ex.PartialFiles))
		if len(timedOut) > 0 {
			list := strings.Join(timedOut[:min(len(timedOut), partialTimeoutFilesShown)], ", ")
			if extra := len(timedOut) - partialTimeoutFilesShown; extra > 0 {
				list += fmt.Sprintf(" and %d more file(s)", extra)
			}
			note += " Rule timeouts depend on machine load, so findings in " + list + " can differ between runs."
		}
		notes = append(notes, note+" The files are listed under `partial_files` in the scanner manifest._")
	}
	return notes
}

// iacReportOnlyLine says how many IaC misconfiguration findings the policy
// reported without gating them (iac_findings: report), or returns "".
func iacReportOnlyLine(bd healthcheck.Breakdown) string {
	if bd.ReportOnlyFindings == 0 {
		return ""
	}
	return fmt.Sprintf("_%d IaC misconfiguration finding(s) reported, not gating (set `iac_findings: block` to enforce)._", bd.ReportOnlyFindings)
}

// ScopeSummary records what the project configuration kept out of the run:
// findings removed by ignore.rules and findings silenced inline. Only their
// counts remain; the findings themselves were never triaged or scored.
type ScopeSummary struct {
	// IgnoredByConfig counts findings per .aitriage.yaml ignore.rules entry.
	IgnoredByConfig map[string]int `json:"ignored_by_config,omitempty"`
	// SuppressedInline counts findings per "source:rule" silenced by an
	// aitriage-ignore comment.
	SuppressedInline map[string]int `json:"suppressed_inline,omitempty"`
}

// scopeExclusionsLine is the one-line summary of ScopeSummary for summary.md.
func scopeExclusionsLine(ignored, inline map[string]int) string {
	var parts []string
	if n := totalCount(ignored); n > 0 {
		parts = append(parts, fmt.Sprintf("%d finding(s) removed by `ignore.rules` in `.aitriage.yaml` (%s)", n, formatCounts(ignored)))
	}
	if n := totalCount(inline); n > 0 {
		parts = append(parts, fmt.Sprintf("%d silenced by inline `aitriage-ignore` comments (%s)", n, formatCounts(inline)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "_Scope: " + strings.Join(parts, " · ") + ". They are not triaged and not scored._"
}

func totalCount(counts map[string]int) int {
	total := 0
	for _, n := range counts {
		if n > 0 {
			total += n
		}
	}
	return total
}

// formatCounts renders "ENTR-SLOP-01 ×1, port-53 ×2" in a stable order.
func formatCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key, n := range counts {
		if n > 0 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}
