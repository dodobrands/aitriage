package main

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/spf13/cobra"
)

func TestScanPolicyFromFlagsDoesNotOverrideConfigWithDefaults(t *testing.T) {
	cmd := newScanPolicyTestCommand()
	failOn = healthcheck.FailOnCritical
	failScore = 0
	healthProfile = ""

	report := scanner.ScanReport{
		Config: &config.Config{
			HealthCheck: config.HealthCheckPolicyConfig{
				Profile: healthcheck.PolicyStandard,
				FailOn:  healthcheck.FailOnNever,
			},
		},
	}

	policy := scanPolicyFromFlags(cmd, report)
	if policy.Profile != healthcheck.PolicyStandard {
		t.Fatalf("profile = %q; want standard", policy.Profile)
	}
	if policy.FailOn != healthcheck.FailOnNever {
		t.Fatalf("fail_on = %q; want config never", policy.FailOn)
	}
}

func TestScanPolicyFromFlagsAppliesExplicitOverrides(t *testing.T) {
	cmd := newScanPolicyTestCommand()
	if err := cmd.Flags().Set("health-profile", healthcheck.PolicyStrict); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("fail-on", healthcheck.FailOnNever); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("fail-score", "0"); err != nil {
		t.Fatal(err)
	}
	failOn = healthcheck.FailOnNever
	failScore = 0
	healthProfile = healthcheck.PolicyStrict

	report := scanner.ScanReport{
		Config: &config.Config{
			HealthCheck: config.HealthCheckPolicyConfig{
				Profile:      healthcheck.PolicyBaseline,
				BlockSources: []string{"gitleaks"},
			},
		},
	}

	policy := scanPolicyFromFlags(cmd, report)
	if policy.Profile != healthcheck.PolicyStrict {
		t.Fatalf("profile = %q; want strict", policy.Profile)
	}
	if policy.FailOn != healthcheck.FailOnNever {
		t.Fatalf("fail_on = %q; want explicit never", policy.FailOn)
	}
	if policy.MinimumScore != 0 {
		t.Fatalf("minimum_score = %d; want explicit 0", policy.MinimumScore)
	}
	if len(policy.BlockSources) != 1 || policy.BlockSources[0] != "gitleaks" {
		t.Fatalf("block_sources = %#v", policy.BlockSources)
	}
}

// --quality-findings accepts report or block and overrides the
// configuration; the scan scores its final result under that policy, so a
// code-quality finding (ENTR-12) gates only under block.
func TestScanQualityFindingsFlag(t *testing.T) {
	previous := scanQualityFindings
	previousFailOn, previousProfile := failOn, healthProfile
	t.Cleanup(func() { scanQualityFindings, failOn, healthProfile = previous, previousFailOn, previousProfile })
	failOn, healthProfile = healthcheck.FailOnCritical, ""

	scanQualityFindings = "gate"
	if err := validateScanFlags(); err == nil || err.Error() != `invalid --quality-findings "gate": use report or block` {
		t.Fatalf("validateScanFlags() = %v, want the bad mode rejected", err)
	}
	scanQualityFindings = "block"
	if err := validateScanFlags(); err != nil {
		t.Fatalf("validateScanFlags() = %v, want block accepted", err)
	}

	// The fixture of ENTR-12: a file over 1,500 lines.
	report, err := scanner.Scan(t.Context(), "../../testdata/rules/ENTR-12/bad", scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report.Config = &config.Config{HealthCheck: config.HealthCheckPolicyConfig{Profile: healthcheck.PolicyStrict, QualityFindings: "report"}}

	reported := report
	policy := scanPolicyFromFlags(newScanPolicyTestCommand(), reported)
	if policy.QualityFindings != healthcheck.QualityFindingsReport || policy.FailOn != healthcheck.FailOnAny {
		t.Fatalf("policy = %+v, want the configured strict profile and quality_findings report", policy)
	}
	refreshScanHealthCheck(&reported, policy)
	if hc := reported.HealthCheck; hc.Breakdown.ReportOnlyByKind[healthcheck.ReportOnlyQuality] == 0 || hc.Breakdown.CountByRule["entr-12"] != 0 {
		t.Fatalf("breakdown = %+v, want ENTR-12 reported, not scored", hc.Breakdown)
	}

	cmd := newScanPolicyTestCommand()
	if err := cmd.Flags().Set("quality-findings", "block"); err != nil {
		t.Fatal(err)
	}
	blocked := report
	policy = scanPolicyFromFlags(cmd, blocked)
	if policy.QualityFindings != healthcheck.QualityFindingsBlock {
		t.Fatalf("policy quality_findings = %q, want the flag to override the configuration", policy.QualityFindings)
	}
	refreshScanHealthCheck(&blocked, policy)
	if hc := blocked.HealthCheck; hc.Verdict.Passed || hc.Breakdown.CountByRule["entr-12"] == 0 || hc.Score >= reported.HealthCheck.Score {
		t.Fatalf("under block: score %d (report: %d), verdict %+v; want ENTR-12 scored and gating", hc.Score, reported.HealthCheck.Score, hc.Verdict)
	}
	if blocked.SecurityScore != blocked.HealthCheck.Score {
		t.Fatalf("security score %d, health check %d; want one number", blocked.SecurityScore, blocked.HealthCheck.Score)
	}

	// Set nowhere, quality_findings is block: ENTR-12 gates as it did before
	// the setting existed.
	unset := report
	unset.Config = &config.Config{HealthCheck: config.HealthCheckPolicyConfig{Profile: healthcheck.PolicyStrict}}
	policy = scanPolicyFromFlags(newScanPolicyTestCommand(), unset)
	refreshScanHealthCheck(&unset, policy)
	if hc := unset.HealthCheck; policy.QualityFindings != healthcheck.QualityFindingsBlock || hc.Verdict.Passed || hc.Score != blocked.HealthCheck.Score {
		t.Fatalf("default: quality_findings %q, score %d (block: %d), verdict %+v; want the block gate", policy.QualityFindings, hc.Score, blocked.HealthCheck.Score, hc.Verdict)
	}
}

func newScanPolicyTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().String("health-profile", "", "")
	cmd.Flags().String("fail-on", healthcheck.FailOnCritical, "")
	cmd.Flags().Int("fail-score", 0, "")
	cmd.Flags().String("quality-findings", "", "")
	return cmd
}
