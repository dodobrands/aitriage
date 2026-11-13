package healthcheck

import (
	"fmt"
	"strings"
	"testing"
)

// One scanner report is IaC only with the scanner's own marker, and code
// quality only by its rule's subcategory or a listed check of a known
// scanner: never by a rule id alone.
func TestOriginKind(t *testing.T) {
	cases := []struct {
		origin Origin
		want   string
	}{
		{Origin{Type: "external", Source: "trivy", RuleID: "KSV-0012", Kind: "misconfiguration"}, ReportOnlyIaC},
		{Origin{Type: "external", Source: " Trivy ", RuleID: "DS-0002", Kind: "Misconfiguration"}, ReportOnlyIaC},
		{Origin{Type: "external", Source: "trivy", RuleID: "CVE-2026-0001"}, ""},
		{Origin{Type: "external", Source: "semgrep", RuleID: "x", Kind: "misconfiguration"}, ""},
		{Origin{Type: "core", Source: "core", RuleID: "ENTR-12", Subcategory: "quality"}, ReportOnlyQuality},
		{Origin{Type: "core", Source: "aitriage", RuleID: "ENTR-12"}, ""},
		{Origin{Type: "core", Source: "core", RuleID: "FAST-SQLI", Subcategory: "vuln"}, ""},
		{Origin{Type: "core", Source: "core", RuleID: "DOCKER-NO-USER", Subcategory: "policy"}, ""},
		{Origin{Type: "external", Source: "bandit", RuleID: "B110"}, ReportOnlyQuality},
		{Origin{Type: "external", Source: "bandit", RuleID: "b112"}, ReportOnlyQuality},
		{Origin{Type: "external", Source: "bandit", RuleID: "B105"}, ""},
		{Origin{Type: "external", Source: "semgrep", RuleID: "B110"}, ""},
		{Origin{Type: "nfr", Source: "aitriage", RuleID: "NFR-ENV-001"}, ReportOnlyQuality},
		{Origin{Type: "nfr", Source: "nfr", RuleID: "NFR-ENV-001"}, ReportOnlyQuality},
		{Origin{Type: "nfr", Source: "nfr", RuleID: "NFR-ENV-002"}, ""},
		{Origin{Type: "nfr", Source: "nfr", RuleID: "NFR-API-003"}, ""},
		{Origin{Type: "core", Source: "aitriage", RuleID: "NFR-ENV-001"}, ""},
	}
	for _, tc := range cases {
		if got := OriginKind(tc.origin); got != tc.want {
			t.Errorf("OriginKind(%+v) = %q, want %q", tc.origin, got, tc.want)
		}
	}
}

// A finding is report-only only when every report behind it is of one
// report-only kind and the policy reports that kind.
func TestReportOnlyKindNeedsEveryOriginOfOneKind(t *testing.T) {
	quality := Origin{Type: "external", Source: "bandit", RuleID: "B110"}
	qualityRule := Origin{Type: "core", Source: "aitriage", RuleID: "FAST-LAZY-EXC", Subcategory: SubcategoryQuality}
	security := Origin{Type: "core", Source: "aitriage", RuleID: "PY-SUBPROCESS", Subcategory: "audit"}
	iac := Origin{Type: "external", Source: "trivy", RuleID: "DS-0002", Kind: "misconfiguration"}
	dockerRule := Origin{Type: "core", Source: "aitriage", RuleID: "DOCKER-NO-USER", Subcategory: "policy"}

	defaults := Policy{}
	blockQuality := Policy{QualityFindings: QualityFindingsBlock}
	blockIaC := Policy{IaCFindings: IaCFindingsBlock}
	cases := []struct {
		name    string
		policy  Policy
		origins []Origin
		want    string
	}{
		{"no origins", defaults, nil, ""},
		{"quality", defaults, []Origin{quality}, ReportOnlyQuality},
		{"quality reports of two detectors", defaults, []Origin{qualityRule, quality}, ReportOnlyQuality},
		{"quality merged with a security rule", defaults, []Origin{quality, security}, ""},
		{"quality under block", blockQuality, []Origin{quality}, ""},
		{"quality under iac block", blockIaC, []Origin{quality}, ReportOnlyQuality},
		{"iac", defaults, []Origin{iac}, ReportOnlyIaC},
		{"iac merged with a built-in rule", defaults, []Origin{iac, dockerRule}, ""},
		{"iac under block", blockIaC, []Origin{iac}, ""},
		{"iac under quality block", blockQuality, []Origin{iac}, ReportOnlyIaC},
		{"iac merged with quality", defaults, []Origin{iac, quality}, ""},
		{"typo is the strict reading", Policy{QualityFindings: "reprot"}, []Origin{quality}, ""},
	}
	for _, tc := range cases {
		if got := ReportOnlyKind(tc.policy, tc.origins); got != tc.want {
			t.Errorf("%s: ReportOnlyKind = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// qualityInput is a project with one unreviewed security finding and, apart
// from it, findings that are nothing but code quality or IaC.
func qualityInput() Input {
	return Input{Findings: []Finding{
		{Source: "core", Class: "FAST-SQLI", Severity: "MEDIUM", File: "app/db.py", Line: 9, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "FAST-SQLI", Subcategory: "vuln"}}},
		{Source: "core", Class: "ENTR-12", Severity: "LOW", File: "app/views.py", Line: 1, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "ENTR-12", Subcategory: SubcategoryQuality}}},
		{Source: "bandit", Class: "B110", Severity: "LOW", File: "app/jobs.py", Line: 12, NeedsReview: true},
		{Source: "bandit", Class: "B112", Severity: "LOW", File: "app/jobs.py", Line: 30, NeedsReview: true},
		{Source: "nfr", Class: "NFR-ENV-001", Severity: "LOW", NeedsReview: true,
			Origins: []Origin{{Type: "nfr", Source: "nfr", RuleID: "NFR-ENV-001"}}},
		{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, NeedsReview: true,
			Origins: []Origin{{Type: "external", Source: "trivy", RuleID: "KSV-0012", Kind: "misconfiguration"}}},
	}}
}

// Under report, findings that are nothing but code quality or IaC change
// neither the score nor the verdict, and the breakdown counts them per kind.
// Under block they score and gate like any other finding.
func TestAssessKeepsReportOnlyFindingsOutOfTheScoreAndGate(t *testing.T) {
	full := qualityInput()
	securityOnly := Input{Findings: full.Findings[:1]}
	gate := Policy{FailOn: FailOnCritical, MaxCritical: 0, MaxHigh: 0, MaxMedium: 0, Profile: PolicyStrict}

	reported := Assess(full, gate)
	baseline := Assess(securityOnly, gate)
	if reported.Score != baseline.Score || reported.Verdict.Passed != baseline.Verdict.Passed || len(reported.Verdict.BlockingReasons) != len(baseline.Verdict.BlockingReasons) {
		t.Fatalf("with report-only findings: score %d, verdict %+v; without: score %d, verdict %+v",
			reported.Score, reported.Verdict, baseline.Score, baseline.Verdict)
	}
	bd := reported.Breakdown
	if bd.ActiveFindings != 1 || bd.ReportOnlyFindings != 5 || bd.ReportOnlyByKind[ReportOnlyQuality] != 4 || bd.ReportOnlyByKind[ReportOnlyIaC] != 1 {
		t.Fatalf("breakdown = %+v, want 1 active, 5 report-only (4 quality, 1 iac)", bd)
	}
	if bd.CountBySource["bandit"] != 0 || bd.CountByRule["entr-12"] != 0 || bd.CountBySeverity["HIGH"] != 0 {
		t.Fatalf("breakdown = %+v, want report-only findings in no other count", bd)
	}

	blocked := Assess(full, Policy{FailOn: gate.FailOn, MaxCritical: 0, MaxHigh: 0, MaxMedium: 0, Profile: PolicyStrict,
		QualityFindings: QualityFindingsBlock, IaCFindings: IaCFindingsBlock})
	if blocked.Score >= reported.Score || blocked.Breakdown.ActiveFindings != 6 || blocked.Breakdown.ReportOnlyFindings != 0 || blocked.Breakdown.ReportOnlyByKind != nil {
		t.Fatalf("under block: score %d (report: %d), breakdown %+v; want every finding scored", blocked.Score, reported.Score, blocked.Breakdown)
	}
}

// A project with nothing but code-quality findings passes a gate that blocks
// every finding under report, and fails it under block.
func TestAssessQualityFindingsGateOnlyUnderBlock(t *testing.T) {
	in := Input{Findings: qualityInput().Findings[1:5]}
	strict := Policy{Profile: PolicyStrict, FailOn: FailOnAny}
	if res := Assess(in, strict); !res.Verdict.Passed || res.Score != 100 || res.Policy.QualityFindings != QualityFindingsReport {
		t.Fatalf("under report: score %d, verdict %+v, policy %+v; want a pass at 100", res.Score, res.Verdict, res.Policy)
	}
	strict.QualityFindings = QualityFindingsBlock
	if res := Assess(in, strict); res.Verdict.Passed || res.Score == 100 {
		t.Fatalf("under block: score %d, verdict %+v; want the findings to block", res.Score, res.Verdict)
	}
}

func TestQualityFindingsPolicyValues(t *testing.T) {
	for value, want := range map[string]string{"": QualityFindingsReport, "report": QualityFindingsReport, " BLOCK ": QualityFindingsBlock, "blok": QualityFindingsBlock} {
		if got := NormalizeQualityFindings(value); got != want {
			t.Errorf("NormalizeQualityFindings(%q) = %q, want %q", value, got, want)
		}
	}
	if _, ok := ParseQualityFindings("blok"); ok {
		t.Error("ParseQualityFindings accepted a typo")
	}
	if got, ok := ParseQualityFindings(" Report "); !ok || got != QualityFindingsReport {
		t.Errorf("ParseQualityFindings(Report) = %q, %t", got, ok)
	}
	if got := NormalizePolicy(Policy{}).QualityFindings; got != QualityFindingsReport {
		t.Errorf("default quality_findings = %q, want report", got)
	}
}

// NeedsReviewPenalty is the share of the penalty unreviewed findings cause.
func TestEvaluateAttributesThePenaltyToUnreviewedFindings(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{
		{Source: "semgrep", Class: "a", Severity: "MEDIUM", File: "a.py", Line: 1, NeedsReview: true},
		{Source: "semgrep", Class: "b", Severity: "MEDIUM", File: "b.py", Line: 1},
	}})
	bd := res.Breakdown
	if bd.Penalty == 0 || 2*bd.NeedsReviewPenalty < bd.Penalty-1 || 2*bd.NeedsReviewPenalty > bd.Penalty+1 {
		t.Fatalf("penalty %d, unreviewed share %d; want about half", bd.Penalty, bd.NeedsReviewPenalty)
	}
	if clean := Evaluate(Input{}); clean.Breakdown.NeedsReviewPenalty != 0 {
		t.Fatalf("clean project: unreviewed share %d, want 0", clean.Breakdown.NeedsReviewPenalty)
	}
}

func unreviewedFindings(n int, severity string) Input {
	in := Input{}
	for i := 0; i < n; i++ {
		in.Findings = append(in.Findings, Finding{Source: "semgrep", Class: fmt.Sprintf("rule-%d", i), Severity: severity, File: "app.py", Line: i + 1, NeedsReview: true})
	}
	return in
}

// A gate that passes next to a low score says why: unreviewed findings count
// in full, but the gate does not block on them.
func TestUnreviewedScoreNote(t *testing.T) {
	confirmed := Assess(unreviewedFindings(3, "HIGH"), Policy{FailOn: FailOnConfirmed, ConfirmedMinSeverity: SeverityMedium})
	want := fmt.Sprintf("Score %d/100: 3 finding(s) await review and count in full (all %d penalty points), but `fail_on: confirmed` blocks only confirmed findings at or above MEDIUM.",
		confirmed.Score, confirmed.Breakdown.Penalty)
	if got := UnreviewedScoreNote(confirmed); got != want {
		t.Fatalf("note = %q\nwant   %q", got, want)
	}
	// A confirmed LOW finding below the floor: the unreviewed ones still
	// cause most of the penalty, and the note says how much.
	mixed := unreviewedFindings(3, "HIGH")
	mixed.Findings = append(mixed.Findings, Finding{Source: "semgrep", Class: "confirmed", Severity: "LOW", File: "lib.py", Line: 1})
	partly := Assess(mixed, Policy{FailOn: FailOnConfirmed, ConfirmedMinSeverity: SeverityMedium})
	wantShare := fmt.Sprintf("(%d of the %d penalty points)", partly.Breakdown.NeedsReviewPenalty, partly.Breakdown.Penalty)
	if got := UnreviewedScoreNote(partly); partly.Breakdown.NeedsReviewPenalty >= partly.Breakdown.Penalty || !strings.Contains(got, wantShare) {
		t.Fatalf("note = %q, want the share %s", got, wantShare)
	}

	lowFloor := Assess(unreviewedFindings(2, "MEDIUM"), Policy{FailOn: FailOnConfirmed})
	if got := UnreviewedScoreNote(lowFloor); !strings.Contains(got, "but `fail_on: confirmed` blocks only confirmed findings.") {
		t.Fatalf("note = %q, want the confirmed gate without a floor", got)
	}
	critical := Assess(unreviewedFindings(4, "MEDIUM"), Policy{FailOn: FailOnCritical, MinimumScore: 10, Profile: PolicyStandard, MaxMedium: -1})
	wantCritical := fmt.Sprintf("but `fail_on: critical` blocks only CRITICAL and HIGH findings, and %d meets `minimum_score: 10`.", critical.Score)
	if got := UnreviewedScoreNote(critical); !critical.Verdict.Passed || !strings.Contains(got, wantCritical) {
		t.Fatalf("verdict %+v, note = %q, want %q", critical.Verdict, got, wantCritical)
	}
	never := Assess(unreviewedFindings(1, "CRITICAL"), Policy{FailOn: FailOnNever})
	if got := UnreviewedScoreNote(never); !strings.Contains(got, "but `fail_on: never` never blocks.") {
		t.Fatalf("note = %q, want the disabled gate named", got)
	}

	// Nothing to explain: the gate failed, nothing awaits review, or
	// confirmed findings cause most of the penalty.
	failed := Assess(unreviewedFindings(2, "HIGH"), Policy{FailOn: FailOnCritical})
	if got := UnreviewedScoreNote(failed); got != "" {
		t.Errorf("failed gate: note = %q, want none", got)
	}
	if got := UnreviewedScoreNote(Assess(Input{}, Policy{FailOn: FailOnConfirmed})); got != "" {
		t.Errorf("clean project: note = %q, want none", got)
	}
	mostlyConfirmed := Input{Findings: []Finding{
		{Source: "semgrep", Class: "a", Severity: "HIGH", File: "a.py", Line: 1},
		{Source: "semgrep", Class: "b", Severity: "LOW", File: "b.py", Line: 1, NeedsReview: true},
	}}
	if got := UnreviewedScoreNote(Assess(mostlyConfirmed, Policy{FailOn: FailOnNever})); got != "" {
		t.Errorf("confirmed findings drive the penalty: note = %q, want none", got)
	}
}
