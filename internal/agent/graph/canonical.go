package graph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ── Canonical artifact sections ──────────────────────────────────────────────
//
// triage-findings.json is the single source of truth for what was found and
// how it was classified. Report/fixspec factual tables MUST be derived from the
// same structured state, never re-authored by the LLM — otherwise a model can
// silently drift dispositions or hallucinate CS-*/CVE identifiers that never
// existed (observed in the MiMo/GLM benchmark). The LLM keeps its advisory
// narrative; these deterministic sections carry the canonical facts.

// cvePattern matches CVE identifiers like CVE-2026-28684 (year + at least 4 digits).
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// vulnIDPattern matches generated CS-XXX-NNN vulnerability identifiers.
var vulnIDPattern = regexp.MustCompile(`CS-[A-Z0-9]+-\d{3,}`)

// canonicalDispositionByVulnID maps each finding's generated VulnID to its
// authoritative disposition, straight from state. This is the same 1:1 mapping
// serialized into triage-findings.json.
func canonicalDispositionByVulnID(state *AgentState) map[string]FindingDisposition {
	out := make(map[string]FindingDisposition, len(state.FindingDispositions))
	for _, d := range state.FindingDispositions {
		if idx := d.FindingIndex; idx >= 0 && idx < len(state.EnrichedFindings) {
			vulnID := strings.TrimSpace(state.EnrichedFindings[idx].VulnID)
			if vulnID != "" {
				out[vulnID] = d
			}
		}
	}
	return out
}

// canonicalCVEs returns the set of CVE identifiers that legitimately appear in
// the scanner findings (messages/IDs). Any CVE outside this set in a generated
// artifact is a hallucination.
func canonicalCVEs(state *AgentState) map[string]bool {
	out := make(map[string]bool)
	for _, f := range state.EnrichedFindings {
		for _, cve := range cvePattern.FindAllString(f.Message+" "+f.ID, -1) {
			out[strings.ToUpper(cve)] = true
		}
	}
	return out
}

// buildCanonicalFindingsSection renders the authoritative finding inventory as
// deterministic Markdown. Ordering follows EnrichedFindings (already canonically
// sorted), so the output is byte-stable across identical runs.
func buildCanonicalFindingsSection(state *AgentState) string {
	dispByIndex := make(map[int]FindingDisposition, len(state.FindingDispositions))
	for _, d := range state.FindingDispositions {
		dispByIndex[d.FindingIndex] = d
	}

	var sb strings.Builder
	sb.WriteString("## Canonical Finding Inventory\n\n")
	sb.WriteString("_Derived deterministically from the triage engine (the source of truth in `triage-findings.json`). Do not edit by hand._\n\n")
	sb.WriteString("| Vulnerability ID | Severity | File | Line | Disposition | Source |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for i, f := range state.EnrichedFindings {
		file := f.File
		if file == "" {
			file = "N/A"
		}
		disp := "Needs Manual Review (unclassified)"
		src := ""
		if d, ok := dispByIndex[i]; ok {
			disp = dispositionLabel(d)
			src = d.DispositionSource
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s | %s |\n",
			f.VulnID, f.Severity, file, f.Line, disp, src))
	}

	tally := tallyDispositions(state)
	sb.WriteString(fmt.Sprintf("\n**Dispositions:** %d True Positive · %d False Positive · %d Needs Manual Review · %d total\n",
		tally.TruePositives, tally.FalsePositives, tally.NeedsReview, len(state.EnrichedFindings)))
	var notes []string
	if tally.Unclassified > 0 {
		notes = append(notes, fmt.Sprintf("%d Needs Manual Review finding(s) are unclassified: the model gave no verdict (%d of them because the provider failed)", tally.Unclassified, tally.TriageFailed))
	}
	if tally.Suppressed > 0 {
		notes = append(notes, fmt.Sprintf("%d False Positive finding(s) were dismissed by project decisions and never sent to the LLM", tally.Suppressed))
	}
	if tally.Network > 0 {
		notes = append(notes, fmt.Sprintf("%d network probe finding(s) describe the scanning host; they are listed but never sent to the LLM or scored", tally.Network))
	}
	for _, note := range notes {
		sb.WriteString("- " + note + ".\n")
	}
	return sb.String()
}

// canonicalActiveFindingsBrief renders only the actionable (non-FP) findings as
// a compact, deterministic list for the fix-spec generator. It intentionally
// carries the canonical IDs so the model cannot invent new ones.
func canonicalActiveFindingsBrief(state *AgentState) string {
	dispByIndex := make(map[int]FindingDisposition, len(state.FindingDispositions))
	for _, d := range state.FindingDispositions {
		dispByIndex[d.FindingIndex] = d
	}

	type row struct {
		vulnID, sev, file, disp, rationale string
		line                               int
	}
	var rows []row
	for i, f := range state.EnrichedFindings {
		if isEnvironmentFinding(f) {
			// A port open on the scanning host is not something to fix in
			// this repository.
			continue
		}
		d, ok := dispByIndex[i]
		disp := "Needs Manual Review (unclassified)"
		rationale := ""
		if ok {
			if d.Disposition == "False Positive" {
				continue
			}
			disp = dispositionLabel(d)
			rationale = d.Rationale
		}
		rows = append(rows, row{vulnID: f.VulnID, sev: strings.ToUpper(f.Severity), file: f.File, disp: disp, rationale: rationale, line: f.Line})
	}
	// Stable, severity-first ordering for readable specs.
	sort.SliceStable(rows, func(i, j int) bool {
		if a, b := severitySortRank(rows[i].sev), severitySortRank(rows[j].sev); a != b {
			return a < b
		}
		return rows[i].vulnID < rows[j].vulnID
	})

	var sb strings.Builder
	sb.WriteString("## Canonical Active Findings (authoritative — use these IDs verbatim)\n\n")
	if len(rows) == 0 {
		sb.WriteString("_No actionable findings._\n")
		return sb.String()
	}
	for _, r := range rows {
		file := r.file
		if file == "" {
			file = "N/A"
		}
		sb.WriteString(fmt.Sprintf("- **%s** [%s] %s — `%s:%d` — %s\n", r.vulnID, r.sev, r.disp, file, r.line, r.rationale))
	}
	sb.WriteString("\nDo not introduce any vulnerability ID, CVE, or package that is not listed above.\n")
	return sb.String()
}
