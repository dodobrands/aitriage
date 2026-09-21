package orchestrator

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// scanner.Scan sees only its own results, so the health check it returns covers
// the built-in engine alone. Without recomputing over every scanner, a project
// whose problems were all found by Semgrep or Trivy scored 100/100 and passed
// the gate while the finding list showed a live SQL injection.

func TestExternalFindingsReachTheScoreAndVerdict(t *testing.T) {
	result := llm.RichScanResult{
		Report: scanner.ScanReport{},
		External: []external.UnifiedFinding{
			{Source: "semgrep", RuleID: "php.tainted-sql-string", Severity: "HIGH", File: "app/index.php", Line: 3},
		},
	}

	applyFullHealthCheck(&result)

	if result.Report.SecurityScore == 100 {
		t.Error("a HIGH Semgrep finding left the score at a perfect 100")
	}
	if result.Report.HealthCheck.Breakdown.ActiveFindings != 1 {
		t.Errorf("active findings = %d; want the Semgrep finding to be counted",
			result.Report.HealthCheck.Breakdown.ActiveFindings)
	}
	if result.Report.HealthCheck.Verdict.Passed {
		t.Error("the gate passed with an active HIGH finding")
	}
}

func TestNFRAndDeployFindingsAreScored(t *testing.T) {
	result := llm.RichScanResult{
		NFR:    []nfr.NFRFinding{{RuleID: "NFR-ENV-002", Severity: "HIGH", Name: ".env exposed"}},
		Deploy: []deployaudit.DeployFinding{{Issue: "dockerfile_root_user", Severity: "HIGH", File: "Dockerfile", Line: 3}},
	}

	applyFullHealthCheck(&result)

	if got := result.Report.HealthCheck.Breakdown.ActiveFindings; got != 2 {
		t.Errorf("active findings = %d; want both the NFR and the deploy finding", got)
	}
	bySource := result.Report.HealthCheck.Breakdown.CountBySource
	if bySource["nfr"] != 1 || bySource["deploy"] != 1 {
		t.Errorf("count by source = %v; want one nfr and one deploy", bySource)
	}
}

// An open port describes the machine AITriage runs on, not the repository. The
// pilot saw "Port 8080 open" counted against his codebase; it was a dev server.
func TestNetworkFindingsStayOutOfTheRepositoryScore(t *testing.T) {
	withPorts := llm.RichScanResult{
		Network: []network.NetworkFinding{
			{Port: 8080, Severity: "HIGH", Service: "HTTP (alt)"},
			{Port: 5432, Severity: "CRITICAL", Service: "postgres"},
		},
	}
	applyFullHealthCheck(&withPorts)

	clean := llm.RichScanResult{}
	applyFullHealthCheck(&clean)

	if withPorts.Report.SecurityScore != clean.Report.SecurityScore {
		t.Errorf("score with open ports = %d, without = %d; the environment must not move the repository score",
			withPorts.Report.SecurityScore, clean.Report.SecurityScore)
	}
}

// Nothing is triaged in a deterministic scan, so every finding must be reported
// as needing review rather than as a confirmed vulnerability.
func TestDeterministicScanMarksEverythingUnreviewed(t *testing.T) {
	result := llm.RichScanResult{
		External: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "CVE-2026-0001", Severity: "MEDIUM", File: "composer.lock"},
			{Source: "gitleaks", RuleID: "generic-api-key", Severity: "CRITICAL", File: "app/config.php"},
		},
	}

	applyFullHealthCheck(&result)

	bd := result.Report.HealthCheck.Breakdown
	if bd.ConfirmedFindings != 0 {
		t.Errorf("confirmed = %d; a scan without triage confirms nothing", bd.ConfirmedFindings)
	}
	if bd.NeedsReviewFindings != 2 {
		t.Errorf("needs review = %d; want every finding of an untriaged scan", bd.NeedsReviewFindings)
	}
}

func TestPolicyChoiceIsPreserved(t *testing.T) {
	result := llm.RichScanResult{
		Report: scanner.ScanReport{
			HealthCheck: healthcheck.Result{Policy: healthcheck.Policy{
				Profile: healthcheck.PolicyBaseline,
				FailOn:  healthcheck.FailOnNever,
			}},
		},
		External: []external.UnifiedFinding{
			{Source: "semgrep", RuleID: "sqli", Severity: "CRITICAL", File: "a.php"},
		},
	}

	applyFullHealthCheck(&result)

	if !result.Report.HealthCheck.Verdict.Passed {
		t.Error("fail_on=never was discarded when the health check was recomputed")
	}
}
