package orchestrator

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
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

// reportOnlyScan is a full scan whose only findings are an IaC
// misconfiguration and code-quality findings of the built-in engine and the
// NFR checks, under a gate that blocks every finding.
func reportOnlyScan(policy healthcheck.Policy) llm.RichScanResult {
	policy.Profile, policy.FailOn = healthcheck.PolicyStrict, healthcheck.FailOnAny
	return llm.RichScanResult{
		Report: scanner.ScanReport{
			HealthCheck: healthcheck.Result{Policy: policy},
			Results: []core.CheckResult{
				{ID: "ENTR-12", Status: core.Absent, Severity: "LOW", File: "app/views.py", Line: 1, Subcategory: healthcheck.SubcategoryQuality},
				{ID: "FAST-SYNC-ASYNC", Status: core.Absent, Severity: "LOW", File: "app/routes.py", Line: 12, Subcategory: healthcheck.SubcategoryQuality},
			},
		},
		External: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, Kind: external.KindMisconfiguration},
		},
		NFR: []nfr.NFRFinding{{RuleID: "NFR-ENV-001", Severity: "LOW", Name: ".env.example Missing"}},
	}
}

// The full scan (Web UI, TUI, MCP, baseline, spec, and the agent before
// triage) applies iac_findings and quality_findings the way AI triage does:
// under report the findings change neither the score nor the gate, under
// block (the default of quality_findings) they do.
func TestFullScanReportsIaCAndQualityFindingsWithoutScoringThem(t *testing.T) {
	reported := reportOnlyScan(healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsReport})
	applyFullHealthCheck(&reported)
	hc := reported.Report.HealthCheck
	if !hc.Verdict.Passed || hc.Score != 100 || hc.Breakdown.ActiveFindings != 0 {
		t.Fatalf("under report: score %d, verdict %+v, breakdown %+v; want a pass at 100", hc.Score, hc.Verdict, hc.Breakdown)
	}
	if by := hc.Breakdown.ReportOnlyByKind; hc.Breakdown.ReportOnlyFindings != 4 || by[healthcheck.ReportOnlyIaC] != 1 || by[healthcheck.ReportOnlyQuality] != 3 {
		t.Fatalf("report-only = %d by kind %v, want 1 iac and 3 quality", hc.Breakdown.ReportOnlyFindings, by)
	}

	// A swallowed exception is not code quality: under report it gates.
	swallowed := reportOnlyScan(healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsReport})
	swallowed.External = append(swallowed.External, external.UnifiedFinding{Source: "bandit", RuleID: "B110", Severity: "LOW", File: "app/auth.py", Line: 14})
	applyFullHealthCheck(&swallowed)
	if hc := swallowed.Report.HealthCheck; hc.Verdict.Passed || hc.Breakdown.ActiveFindings != 1 || hc.Breakdown.CountByRule["b110"] != 1 {
		t.Fatalf("with Bandit B110 under report: verdict %+v, breakdown %+v; want the swallowed exception scored and gating", hc.Verdict, hc.Breakdown)
	}

	for _, tc := range []struct {
		name   string
		policy healthcheck.Policy
		active int
	}{
		{"iac_findings: block", healthcheck.Policy{IaCFindings: healthcheck.IaCFindingsBlock, QualityFindings: healthcheck.QualityFindingsReport}, 1},
		{"quality_findings: block", healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsBlock}, 3},
		{"quality_findings unset", healthcheck.Policy{}, 3},
	} {
		blocked := reportOnlyScan(tc.policy)
		applyFullHealthCheck(&blocked)
		hc := blocked.Report.HealthCheck
		if hc.Verdict.Passed || hc.Score == 100 || hc.Breakdown.ActiveFindings != tc.active {
			t.Errorf("%s: score %d, verdict passed %t, active %d; want %d gating findings", tc.name, hc.Score, hc.Verdict.Passed, hc.Breakdown.ActiveFindings, tc.active)
		}
	}
}

// A report-only finding and a gating report of the same defect count once,
// and the gating one wins: a Trivy DS-0002 and the deploy audit's root-user
// check on one Dockerfile gate under iac_findings: report.
func TestFullScanKeepsTheGatingReportOfOneDefect(t *testing.T) {
	result := llm.RichScanResult{
		Report: scanner.ScanReport{HealthCheck: healthcheck.Result{Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical}}},
		External: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "DS-0002", Severity: "HIGH", File: "Dockerfile", Kind: external.KindMisconfiguration},
		},
		Deploy: []deployaudit.DeployFinding{{Issue: "dockerfile_root_user", Severity: "HIGH", File: "Dockerfile", Line: 3}},
	}
	applyFullHealthCheck(&result)
	hc := result.Report.HealthCheck
	if hc.Verdict.Passed || hc.Breakdown.ActiveFindings != 1 || hc.Breakdown.ReportOnlyFindings != 0 {
		t.Fatalf("verdict passed %t, breakdown %+v; want the deploy report to gate", hc.Verdict.Passed, hc.Breakdown)
	}
}
