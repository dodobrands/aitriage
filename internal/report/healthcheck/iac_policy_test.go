package healthcheck

import "testing"

// A report-only finding (an IaC misconfiguration under iac_findings: report)
// is counted apart and changes neither the score nor any part of the
// verdict: not fail_on, not the thresholds, not block_sources, and not an
// incomplete triage.
func TestReportOnlyFindingsAreNeitherScoredNorGated(t *testing.T) {
	iac := Finding{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, Identity: "iac", ReportOnly: true}
	code := Finding{Source: "aitriage", Class: "FAST-SQLI", Severity: "MEDIUM", File: "app.py", Line: 7, Identity: "code", NeedsReview: true}

	withIaC := Evaluate(Input{Findings: []Finding{code, iac}})
	without := Evaluate(Input{Findings: []Finding{code}})
	if withIaC.Score != without.Score || withIaC.HasCriticalFailures {
		t.Fatalf("score with the report-only finding = %d (critical %v), without = %d", withIaC.Score, withIaC.HasCriticalFailures, without.Score)
	}
	bd := withIaC.Breakdown
	if bd.ReportOnlyFindings != 1 || bd.ActiveFindings != 1 || bd.CountBySeverity["HIGH"] != 0 || bd.CountBySource["trivy"] != 0 {
		t.Fatalf("breakdown = %+v, want the IaC finding counted only as report-only", bd)
	}

	strict := Policy{Profile: PolicyStrict, FailOn: FailOnCritical, MaxCritical: 0, MaxHigh: 0, MaxMedium: -1, BlockSources: []string{"trivy"}, BlockClasses: []string{"KSV-0012"}}
	if v := EvaluatePolicy(Evaluate(Input{Findings: []Finding{iac}}), strict); !v.Passed {
		t.Fatalf("verdict = %+v, want a report-only finding never to block", v.BlockingReasons)
	}

	failed := iac
	failed.TriageFailed, failed.NeedsReview, failed.Unclassified = true, true, true
	if res := Evaluate(Input{Findings: []Finding{failed}}); res.Breakdown.TriageFailedFindings != 0 || !EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed}).Passed {
		t.Fatalf("breakdown = %+v, want a report-only finding's triage outcome not to gate", res.Breakdown)
	}

	gating := iac
	gating.ReportOnly = false
	if v := EvaluatePolicy(Evaluate(Input{Findings: []Finding{gating}}), Policy{FailOn: FailOnCritical}); v.Passed {
		t.Fatal("the same finding without ReportOnly must block fail_on=critical")
	}
}

// When a duplicate of a report-only finding gates, the gating copy is kept.
func TestDeduplicationKeepsTheGatingCopy(t *testing.T) {
	reported := Finding{Source: "trivy", Class: "DS-0002", Severity: "HIGH", File: "Dockerfile", ReportOnly: true}
	gating := Finding{Source: "core", Class: "DOCKER-NO-USER", Severity: "HIGH", File: "Dockerfile"}
	for _, order := range [][]Finding{{reported, gating}, {gating, reported}} {
		bd := Evaluate(Input{Findings: order}).Breakdown
		if bd.ActiveFindings != 1 || bd.ReportOnlyFindings != 0 || bd.DedupedFindings != 1 {
			t.Fatalf("breakdown = %+v, want the gating copy kept", bd)
		}
	}
}

func TestIaCFindingsPolicyValues(t *testing.T) {
	for value, want := range map[string]string{"": IaCFindingsReport, "report": IaCFindingsReport, " BLOCK ": IaCFindingsBlock, "blok": IaCFindingsBlock} {
		if got := NormalizeIaCFindings(value); got != want {
			t.Errorf("NormalizeIaCFindings(%q) = %q, want %q", value, got, want)
		}
	}
	if _, ok := ParseIaCFindings("blok"); ok {
		t.Error("ParseIaCFindings accepted a typo")
	}
	if got := NormalizePolicy(Policy{}).IaCFindings; got != IaCFindingsReport {
		t.Errorf("default iac_findings = %q, want report", got)
	}
}
