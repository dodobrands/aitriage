package graph

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/network"
)

// B4 + F1: findings a person already dismissed and network probe results get
// deterministic dispositions and never reach the LLM; neither counts as work
// left for review.
func TestRunNeverSendsSuppressedOrNetworkFindingsToTheLLM(t *testing.T) {
	hermeticRun(t)
	state := degradedRunState(t, healthcheck.FailOnConfirmed)
	state.CoreFindings[1].AuditStatus = core.AuditStatusIgnored // PY-SECRET
	state.Suppressions = SuppressionSummary{
		Total:    2,
		ByReason: map[string]int{SuppressionReasonAcceptedRisk: 1, SuppressionReasonFalsePositive: 1},
		Core: map[string]SuppressionDecision{
			CoreDecisionKey("PY-SECRET", "app.py", 3): {Reason: SuppressionReasonAcceptedRisk, Note: "rotated, test fixture only"},
		},
	}
	state.NetworkFindings = []network.NetworkFinding{{Port: 53, Service: "dns", Severity: "MEDIUM", Message: "Failed to resolve db"}}
	stub := newStageLLM(t)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, id := range stub.classified {
		if id == "PY-SECRET" || id == "port-53" {
			t.Fatalf("finding %s was sent to the LLM; classified = %v", id, stub.classified)
		}
	}
	bySource := map[string]FindingDisposition{}
	for _, d := range state.FindingDispositions {
		bySource[d.DispositionSource] = d
	}
	suppressed, ok := bySource[dispositionSourceSuppressed]
	if !ok || suppressed.Disposition != "False Positive" || !strings.Contains(suppressed.Rationale, "accepted_risk") || !strings.Contains(suppressed.Rationale, "rotated, test fixture only") {
		t.Fatalf("suppressed disposition = %+v, want False Positive carrying the decision", suppressed)
	}
	probe, ok := bySource[dispositionSourceNetworkProbe]
	if !ok || probe.Disposition != "Needs Manual Review" {
		t.Fatalf("network disposition = %+v, want a deterministic network-probe entry", probe)
	}

	bd := state.HealthCheck.Breakdown
	if bd.ActiveFindings != 1 || bd.ConfirmedFindings != 1 || bd.NeedsReviewFindings != 0 || bd.IgnoredFindings != 1 {
		t.Fatalf("breakdown = %+v, want only the triaged finding active and the dismissed one ignored", bd)
	}
	tally := tallyDispositions(state)
	if tally.NeedsReview != 0 || tally.Network != 1 || tally.Suppressed != 1 {
		t.Fatalf("tally = %+v, want no network finding counted as Needs Review", tally)
	}
	summary := state.SummaryMarkdown
	for _, want := range []string{
		"2 finding(s) dismissed — 1 false_positive · 1 accepted_risk",
		"### Network Probe (host environment)",
		"| port-53 | MEDIUM |",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary lacks %q:\n%s", want, summary)
		}
	}
	if state.AgentHandoff == nil || state.AgentHandoff.AgentData.Stats.NeedsReview != 0 {
		t.Fatalf("handoff stats = %+v, want network findings outside the Needs Review count", state.AgentHandoff)
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Suppressions.ByReason[SuppressionReasonAcceptedRisk] != 1 || artifact.Classification.BySource[dispositionSourceSuppressed] != 1 {
		t.Fatalf("artifact suppressions = %+v classification = %+v", artifact.Suppressions, artifact.Classification)
	}
}

// A finding merged from a dismissed built-in rule and a still-open external
// scanner report is not dismissed: nobody decided on the external report.
func TestDismissalRequiresEveryOrigin(t *testing.T) {
	finding := EnrichedFinding{ID: "FAST-LAZY-EXC", Type: "core", File: "app.py", Line: 10, Origins: []FindingOrigin{
		{Type: "core", Source: "aitriage", RuleID: "FAST-LAZY-EXC"},
		{Type: "external", Source: "bandit", RuleID: "B110"},
	}}
	dismissed := map[string]core.AuditStatus{hcKey("FAST-LAZY-EXC", "app.py", 10): core.AuditStatusIgnored}
	if _, ok := dismissedCoreStatus(finding, dismissed); ok {
		t.Fatal("a finding with an open external origin must still be triaged")
	}
	finding.Origins = finding.Origins[:1]
	if _, ok := dismissedCoreStatus(finding, dismissed); !ok {
		t.Fatal("a finding whose only origin is dismissed must not be triaged")
	}
}

// N14: the headline counts are the gate's own numbers, also when network
// probe findings are present (they used to be counted in one and not the
// other: "67 needs review" next to "65 unreviewed").
func TestSummaryHeadlineMatchesGateBreakdown(t *testing.T) {
	hermeticRun(t)
	state := degradedRunState(t, healthcheck.FailOnConfirmed)
	state.NetworkFindings = []network.NetworkFinding{
		{Port: 53, Service: "dns", Severity: "MEDIUM", Message: "Failed to resolve app"},
		{Port: 53, Service: "dns", Severity: "MEDIUM", Message: "Failed to resolve db"},
	}
	stub := newStageLLM(t)
	stub.classify = func(_ int, batch []classificationPromptFinding) (string, error) {
		return classifyAll(batch, "Needs Manual Review"), nil
	}

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	bd := state.HealthCheck.Breakdown
	headline := fmt.Sprintf("> **%d** findings analyzed · **%d** true positives · **%d** needs review · **%d** false positives suppressed",
		bd.ActiveFindings+bd.IgnoredFindings+bd.DedupedFindings, bd.ConfirmedFindings, bd.NeedsReviewFindings, bd.IgnoredFindings)
	if !strings.Contains(state.SummaryMarkdown, headline) {
		t.Fatalf("summary headline does not match the gate breakdown %+v:\n%s", bd, state.SummaryMarkdown)
	}
	if bd.NeedsReviewFindings != 2 {
		t.Fatalf("needs review = %d, want 2 (network findings excluded)", bd.NeedsReviewFindings)
	}
	var confirmedReason string
	for _, reason := range state.HealthCheck.Verdict.BlockingReasons {
		confirmedReason += reason.Message
	}
	if confirmedReason != "" {
		t.Fatalf("nothing is confirmed, the gate must pass: %s", confirmedReason)
	}
	if strings.Contains(state.SummaryMarkdown, "**4** findings analyzed") {
		t.Fatal("network findings must not be counted as analysed repository findings")
	}
}
