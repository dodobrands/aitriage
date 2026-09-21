package graph

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/network"
)

func TestComputeHealthCheckHonorsDeployAndNetworkFalsePositives(t *testing.T) {
	state := &AgentState{
		DeployFindings: []deployaudit.DeployFinding{
			{Issue: "dockerfile_root_user", Severity: "HIGH", File: "Dockerfile", Line: 3},
		},
		NetworkFindings: []network.NetworkFinding{
			{Port: 5432, Severity: "MEDIUM", Service: "postgres"},
		},
	}

	enrichFindings(state)
	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("enriched findings = %d; want 2", len(state.EnrichedFindings))
	}
	if state.EnrichedFindings[0].ID != "dockerfile_root_user" {
		t.Fatalf("deploy enriched ID = %q; want dockerfile_root_user", state.EnrichedFindings[0].ID)
	}
	if state.EnrichedFindings[1].ID != "port-5432" {
		t.Fatalf("network enriched ID = %q; want port-5432", state.EnrichedFindings[1].ID)
	}

	state.FindingDispositions = []FindingDisposition{
		{FindingIndex: 0, FindingID: state.EnrichedFindings[0].VulnID, Disposition: "False Positive"},
		{FindingIndex: 1, FindingID: state.EnrichedFindings[1].VulnID, Disposition: "False Positive"},
	}

	computeHealthCheck(state)
	if state.HealthCheck.Breakdown.ActiveFindings != 0 {
		t.Fatalf("active findings = %d; want 0", state.HealthCheck.Breakdown.ActiveFindings)
	}
	// Only the deploy finding reaches scoring. A listening port describes the
	// machine AITriage ran on, not the repository, so it is reported but never
	// scored — see computeHealthCheck.
	if state.HealthCheck.Breakdown.IgnoredFindings != 1 {
		t.Fatalf("ignored findings = %d; want 1 (the deploy finding; network findings are not scored)", state.HealthCheck.Breakdown.IgnoredFindings)
	}
	if state.HealthCheck.Score != 100 {
		t.Fatalf("score = %d; want 100", state.HealthCheck.Score)
	}
	if !state.HealthCheck.Verdict.Passed {
		t.Fatalf("verdict failed for false positives: %+v", state.HealthCheck.Verdict)
	}
}

func TestComputeHealthCheckAppliesAgentPolicyToUndisposedFindings(t *testing.T) {
	state := &AgentState{
		Policy: healthcheck.PolicyForProfile(healthcheck.PolicyStrict),
		DeployFindings: []deployaudit.DeployFinding{
			{Issue: "dockerfile_root_user", Severity: "HIGH", File: "Dockerfile", Line: 3},
		},
	}

	enrichFindings(state)
	computeHealthCheck(state)

	if state.HealthCheck.Breakdown.ActiveFindings != 1 {
		t.Fatalf("active findings = %d; want 1", state.HealthCheck.Breakdown.ActiveFindings)
	}
	if state.HealthCheck.Verdict.Passed {
		t.Fatalf("strict verdict passed; want failure: %+v", state.HealthCheck.Verdict)
	}
	if len(state.HealthCheck.Verdict.BlockingReasons) == 0 {
		t.Fatal("strict verdict has no blocking reasons")
	}
}

// A port that happens to be open on the operator's machine must not change a
// repository's security score. The pilot saw "Port 8080 open" reported against
// his codebase; it was AITriage's own dev server.
func TestNetworkFindingsDoNotAffectTheRepositoryScore(t *testing.T) {
	withNetwork := &AgentState{
		NetworkFindings: []network.NetworkFinding{
			{Port: 8080, Severity: "HIGH", Service: "HTTP (alt)"},
			{Port: 5432, Severity: "HIGH", Service: "postgres"},
		},
	}
	enrichFindings(withNetwork)
	computeHealthCheck(withNetwork)

	clean := &AgentState{}
	enrichFindings(clean)
	computeHealthCheck(clean)

	if withNetwork.HealthCheck.Score != clean.HealthCheck.Score {
		t.Errorf("score with open ports = %d, without = %d; the environment must not move the repository score",
			withNetwork.HealthCheck.Score, clean.HealthCheck.Score)
	}
	if withNetwork.HealthCheck.Breakdown.ActiveFindings != 0 {
		t.Errorf("active findings = %d; network findings must not be scored", withNetwork.HealthCheck.Breakdown.ActiveFindings)
	}
}

// The gate used to say "active findings are not allowed" next to "0 true
// positives", which reads as a contradiction. It must name the unreviewed count.
func TestGateExplainsItselfWhenNothingIsConfirmed(t *testing.T) {
	result := healthcheck.Result{
		Breakdown: healthcheck.Breakdown{
			ActiveFindings:      25,
			ConfirmedFindings:   0,
			NeedsReviewFindings: 25,
			CountBySeverity:     map[string]int{"MEDIUM": 25},
		},
	}
	policy := healthcheck.Policy{Profile: healthcheck.PolicyBaseline, FailOn: healthcheck.FailOnAny}

	verdict := healthcheck.EvaluatePolicy(result, policy)

	if verdict.Passed {
		t.Fatal("unreviewed findings must still block a fail-on-any policy")
	}
	var message string
	for _, reason := range verdict.BlockingReasons {
		if reason.Code == "active_findings" {
			message = reason.Message
		}
	}
	if message == "" {
		t.Fatal("no active_findings blocking reason was produced")
	}
	if !strings.Contains(message, "not been reviewed") {
		t.Errorf("blocking reason = %q; it must explain that the findings are unreviewed, not proven", message)
	}
}

// Teams that triage on their own schedule can choose a policy where only
// confirmed findings block.
func TestFailOnConfirmedLetsUnreviewedFindingsPass(t *testing.T) {
	result := healthcheck.Result{
		Breakdown: healthcheck.Breakdown{
			ActiveFindings:      25,
			ConfirmedFindings:   0,
			NeedsReviewFindings: 25,
			CountBySeverity:     map[string]int{"MEDIUM": 25},
		},
	}
	policy := healthcheck.Policy{Profile: healthcheck.PolicyBaseline, FailOn: healthcheck.FailOnConfirmed}

	if verdict := healthcheck.EvaluatePolicy(result, policy); !verdict.Passed {
		t.Errorf("fail_on=confirmed blocked with nothing confirmed: %+v", verdict.BlockingReasons)
	}
}
