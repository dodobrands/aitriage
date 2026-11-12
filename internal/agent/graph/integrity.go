package graph

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// ── Artifact integrity validation ────────────────────────────────────────────
//
// The security gate is computed from state.FindingDispositions, never from the
// generated Markdown, so a drifting report cannot change the verdict. But the
// report/fixspec are consumed by humans and downstream AI agents, and the
// benchmark caught models inventing CS-*/CVE identifiers and contradicting the
// canonical dispositions. We validate the generated artifacts against the
// canonical state and, on failure, fall back to a deterministic-only artifact
// instead of publishing (or caching) misleading prose.

// validateArtifactIntegrity returns a list of human-readable violations found
// in the generated report/fixspec relative to canonical state. Empty means the
// artifacts are canonical-safe.
func validateArtifactIntegrity(state *AgentState) []string {
	validVulnIDs := canonicalDispositionByVulnID(state)
	validCVEs := canonicalCVEs(state)

	var violations []string
	seenBadVuln := map[string]bool{}
	seenBadCVE := map[string]bool{}

	for _, doc := range []struct{ name, body string }{
		{"report.md", state.ReportMarkdown},
		{"fixspec.md", state.AIFixSpec},
	} {
		for _, id := range vulnIDPattern.FindAllString(doc.body, -1) {
			if _, ok := validVulnIDs[id]; !ok && !seenBadVuln[doc.name+id] {
				seenBadVuln[doc.name+id] = true
				violations = append(violations, fmt.Sprintf("%s references unknown vulnerability ID %s (not in canonical findings)", doc.name, id))
			}
		}
		for _, cve := range cvePattern.FindAllString(doc.body, -1) {
			up := strings.ToUpper(cve)
			if !validCVEs[up] && !seenBadCVE[doc.name+up] {
				seenBadCVE[doc.name+up] = true
				violations = append(violations, fmt.Sprintf("%s references unknown %s (not in any canonical finding)", doc.name, up))
			}
		}
	}

	sort.Strings(violations)
	return violations
}

// enforceArtifactIntegrity validates the generated artifacts and, if they drift
// from canonical state, replaces them with deterministic-only safe versions.
// It returns true when a fallback was applied (the caller records the stat so
// it survives the final ArtifactCacheStats assignment).
func enforceArtifactIntegrity(state *AgentState) bool {
	violations := validateArtifactIntegrity(state)
	if len(violations) == 0 {
		return false
	}
	// Detailed violations go to the operator log; the published artifact carries
	// only a count so the rebuilt document itself stays canonical-safe (echoing
	// the offending identifiers would re-introduce non-canonical references).
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "      · integrity: %s\n", v)
	}
	notice := integrityNotice(len(violations))
	if state.TriageFailed() {
		notice = triageIncompleteBanner(state) + notice
	}
	state.ReportMarkdown = buildDeterministicReport(state, notice)
	state.AIFixSpec = buildDeterministicFixSpec(state, notice)
	return true
}

func integrityNotice(count int) string {
	return fmt.Sprintf("> **Integrity notice:** the AI-generated narrative was withheld because it did not match the canonical triage results (%d issue(s) detected; see run logs). This document was rebuilt deterministically from the triage engine.\n\n", count)
}

// triageIncompleteBanner is the first thing a reader sees when AI triage did
// not finish: what failed, what it means for the findings, and what to do.
func triageIncompleteBanner(state *AgentState) string {
	tally := tallyDispositions(state)
	return fmt.Sprintf("> **AI triage did not complete: %s.** %d finding(s) have no verdict and are listed as Needs Manual Review (unclassified, `triage-failed`). The security gate cannot pass on an incomplete triage; re-run once the LLM provider is available.\n\n",
		state.TriageFailureReason, tally.TriageFailed)
}

// stageFallbackNotice explains why a document was rendered without the LLM.
func stageFallbackNotice(state *AgentState, document string) string {
	if state.TriageFailed() {
		return triageIncompleteBanner(state)
	}
	return fmt.Sprintf("> **AI narrative unavailable:** %s. This %s was rendered deterministically from the triage results; the findings and dispositions below are complete.\n\n",
		providerFailure(state), document)
}

func buildDeterministicReport(state *AgentState, notice string) string {
	var sb strings.Builder
	sb.WriteString("# Security Report (deterministic)\n\n")
	sb.WriteString(notice)
	sb.WriteString(deterministicGateSection(state))
	sb.WriteString(buildCanonicalFindingsSection(state))
	return sb.String()
}

func buildDeterministicFixSpec(state *AgentState, notice string) string {
	var sb strings.Builder
	sb.WriteString("# AI Fix Specification (deterministic)\n\n")
	sb.WriteString(notice)
	sb.WriteString(canonicalActiveFindingsBrief(state))
	return sb.String()
}

// deterministicGateSection states the gate outcome without any model prose.
func deterministicGateSection(state *AgentState) string {
	hc := state.HealthCheck
	var sb strings.Builder
	sb.WriteString("## Security Gate\n\n")
	_, _ = fmt.Fprintf(&sb, "- **Health Check**: %d/100 (%s)\n", hc.Score, hc.Grade)
	_, _ = fmt.Fprintf(&sb, "- **Verdict**: %s under `%s` policy (%s)\n", strings.ToUpper(firstNonEmpty(hc.Verdict.Status, "unknown")), hc.Policy.Profile, policyTerms(hc.Policy))
	_, _ = fmt.Fprintf(&sb, "- **Findings**: %d active (%d confirmed, %d needs review, %d of them unclassified), %d ignored, %d deduplicated\n",
		hc.Breakdown.ActiveFindings, hc.Breakdown.ConfirmedFindings, hc.Breakdown.NeedsReviewFindings,
		hc.Breakdown.UnclassifiedFindings, hc.Breakdown.IgnoredFindings, hc.Breakdown.DedupedFindings)
	for _, reason := range hc.Verdict.BlockingReasons {
		_, _ = fmt.Fprintf(&sb, "- Blocking `%s`: %s\n", reason.Code, reason.Message)
	}
	sb.WriteString("\n")
	return sb.String()
}
