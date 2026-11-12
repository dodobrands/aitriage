package graph

import (
	"fmt"
	"strings"
	"testing"
)

// unclassifiedSummary renders the summary for findings whose dispositions
// carry the given sources.
func unclassifiedSummary(t *testing.T, sources ...string) string {
	t.Helper()
	return unclassifiedSummaryWithCause(t, "", sources...)
}

// unclassifiedSummaryWithCause is unclassifiedSummary for a triage that did
// not complete for the given cause.
func unclassifiedSummaryWithCause(t *testing.T, cause string, sources ...string) string {
	t.Helper()
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
	state := &AgentState{TriageFailureCause: cause}
	for i, source := range sources {
		f := EnrichedFinding{ID: "R", VulnID: fmt.Sprintf("CS-MISC-%06d", i), Type: "core", Severity: "HIGH", File: "app.py", Line: i + 1, Message: "issue"}
		state.EnrichedFindings = append(state.EnrichedFindings, f)
		state.FindingDispositions = append(state.FindingDispositions, FindingDisposition{
			FindingIndex: i, FindingID: f.VulnID, Disposition: "Needs Manual Review", Rationale: "r", DispositionSource: source,
		})
	}
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	return state.SummaryMarkdown
}

// When every unclassified finding was lost to a provider failure, retries
// and batch size are not the remedy: the summary says to repeat the run.
func TestNeedsReviewHintForProviderFailureDoesNotSuggestTuning(t *testing.T) {
	summary := unclassifiedSummary(t, dispositionSourceTriageFailed, dispositionSourceTriageFailed)
	want := "**Needs Review**: 2 (2 not triaged: the LLM provider failed — repeat the run once the provider is available)"
	if !strings.Contains(summary, want) {
		t.Fatalf("summary lacks %q:\n%s", want, summary)
	}
	if strings.Contains(summary, "AITRIAGE_CLASSIFY_RETRIES") || strings.Contains(summary, "AITRIAGE_BATCH_SIZE") {
		t.Fatalf("summary suggests retry tuning for a provider failure:\n%s", summary)
	}
}

// A verdict that failed validation needs a person, and is counted apart from
// the findings the provider failure left untriaged.
func TestNeedsReviewHintSeparatesRejectedVerdictsFromProviderFailures(t *testing.T) {
	summary := unclassifiedSummary(t, dispositionSourceNRFallback, dispositionSourceTriageFailed, dispositionSourceLLM)
	want := "**Needs Review**: 3 (1 unclassified: the model's verdict did not pass validation, or the finding was over the LLM budget (see `classification_audit`) — review by hand; 1 not triaged: the LLM provider failed — repeat the run once the provider is available)"
	if !strings.Contains(summary, want) {
		t.Fatalf("summary lacks %q:\n%s", want, summary)
	}
}

// Findings the model left out of every reply get the tuning hint.
func TestNeedsReviewHintForOmittedFindingsSuggestsTuning(t *testing.T) {
	summary := unclassifiedSummaryWithCause(t, TriageFailureCauseNoVerdict, dispositionSourceTriageFailed, dispositionSourceLLM)
	want := "**Needs Review**: 2 (1 not triaged: no reply carried a verdict for them — retries=2, batch=40; re-run, raise `AITRIAGE_CLASSIFY_RETRIES` or lower `AITRIAGE_BATCH_SIZE`)"
	if !strings.Contains(summary, want) {
		t.Fatalf("summary lacks %q:\n%s", want, summary)
	}
}
