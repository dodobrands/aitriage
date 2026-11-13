package healthcheck

import (
	"fmt"
	"reflect"
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
		{Origin{Type: "core", Source: "aitriage", RuleID: "FAST-SYNC-ASYNC", Subcategory: "quality"}, ReportOnlyQuality},
		{Origin{Type: "external", Source: "bandit", RuleID: "B105"}, ""},
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
// report-only kind and the policy reports that kind. Code-quality findings
// are reported only under an explicit quality_findings: report.
func TestReportOnlyKindNeedsEveryOriginOfOneKind(t *testing.T) {
	quality := Origin{Type: "nfr", Source: "nfr", RuleID: "NFR-ENV-001"}
	qualityRule := Origin{Type: "core", Source: "aitriage", RuleID: "ENTR-12", Subcategory: SubcategoryQuality}
	security := Origin{Type: "core", Source: "aitriage", RuleID: "PY-SUBPROCESS", Subcategory: "audit"}
	swallowed := Origin{Type: "external", Source: "bandit", RuleID: "B110"}
	iac := Origin{Type: "external", Source: "trivy", RuleID: "DS-0002", Kind: "misconfiguration"}
	dockerRule := Origin{Type: "core", Source: "aitriage", RuleID: "DOCKER-NO-USER", Subcategory: "policy"}

	defaults := Policy{}
	reportQuality := Policy{QualityFindings: QualityFindingsReport}
	blockQuality := Policy{QualityFindings: QualityFindingsBlock}
	blockIaC := Policy{IaCFindings: IaCFindingsBlock, QualityFindings: QualityFindingsReport}
	cases := []struct {
		name    string
		policy  Policy
		origins []Origin
		want    string
	}{
		{"no origins", reportQuality, nil, ""},
		{"quality", reportQuality, []Origin{quality}, ReportOnlyQuality},
		{"quality by default", defaults, []Origin{quality}, ""},
		{"quality reports of two detectors", reportQuality, []Origin{qualityRule, quality}, ReportOnlyQuality},
		{"quality merged with a security rule", reportQuality, []Origin{quality, security}, ""},
		{"a swallowed exception", reportQuality, []Origin{swallowed}, ""},
		{"quality under block", blockQuality, []Origin{quality}, ""},
		{"quality under iac block", blockIaC, []Origin{quality}, ReportOnlyQuality},
		{"iac", defaults, []Origin{iac}, ReportOnlyIaC},
		{"iac merged with a built-in rule", defaults, []Origin{iac, dockerRule}, ""},
		{"iac under block", blockIaC, []Origin{iac}, ""},
		{"iac under quality block", blockQuality, []Origin{iac}, ReportOnlyIaC},
		{"iac merged with quality", reportQuality, []Origin{iac, quality}, ""},
		{"typo is the strict reading", Policy{QualityFindings: "reprot"}, []Origin{quality}, ""},
	}
	for _, tc := range cases {
		f := Finding{Severity: "LOW", Origins: tc.origins}
		if got := ReportOnlyKind(tc.policy, f); got != tc.want {
			t.Errorf("%s: ReportOnlyKind = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// qualityOnlyInput is a project whose only findings are code quality: a
// file over 1,500 lines, a TypeScript @ts-ignore, a blocking call in an
// async route and no .env.example, none of them reviewed.
func qualityOnlyInput() Input {
	return Input{Findings: []Finding{
		{Source: "core", Class: "ENTR-12", Severity: "LOW", File: "app/views.py", Line: 1, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "ENTR-12", Subcategory: SubcategoryQuality}}},
		{Source: "core", Class: "ENTR-07", Severity: "LOW", File: "web/src/api.ts", Line: 3, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "ENTR-07", Subcategory: SubcategoryQuality}}},
		{Source: "core", Class: "FAST-SYNC-ASYNC", Severity: "LOW", File: "app/routes.py", Line: 20, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "FAST-SYNC-ASYNC", Subcategory: SubcategoryQuality}}},
		{Source: "nfr", Class: "NFR-ENV-001", Severity: "LOW", NeedsReview: true,
			Origins: []Origin{{Type: "nfr", Source: "nfr", RuleID: "NFR-ENV-001"}}},
	}}
}

// With quality_findings unset, code-quality findings score and gate exactly
// as in v1.14.0, before the setting existed: making report the default
// would let these gates pass for configurations that never asked for it.
// The expected results are v1.14.0's ApplyPolicy(Evaluate(in), policy) for
// the same findings. Under an explicit quality_findings: report they are
// reported only.
func TestQualityFindingsDefaultKeepsTheGateOfV114(t *testing.T) {
	unreviewed := "4 finding(s) have not been reviewed yet. None are confirmed exploitable, but this policy requires every finding to be triaged (confirmed, or dismissed as a false positive / accepted risk) before the gate can pass"
	failed := func(profile string, reason BlockingReason) Verdict {
		return Verdict{Status: "failed", Summary: fmt.Sprintf("Security policy %q failed with 1 blocking reason(s)", profile), BlockingReasons: []BlockingReason{reason}}
	}
	cases := []struct {
		name    string
		policy  Policy
		verdict Verdict
	}{
		{"fail_on: any", Policy{FailOn: FailOnAny},
			failed(PolicyBaseline, BlockingReason{Code: "active_findings", Message: unreviewed, Count: 4})},
		{"block_classes: [ENTR-12]", Policy{BlockClasses: []string{"ENTR-12"}},
			failed(PolicyBaseline, BlockingReason{Code: "blocked_class", Message: `Findings with class "entr-12" are blocked by policy`, Class: "entr-12", Count: 1})},
		{"block_sources: [nfr]", Policy{BlockSources: []string{"nfr"}},
			failed(PolicyBaseline, BlockingReason{Code: "blocked_source", Message: `Findings from source "nfr" are blocked by policy`, Source: "nfr", Count: 1})},
		{"profile: strict", PolicyForProfile(PolicyStrict),
			failed(PolicyStrict, BlockingReason{Code: "active_findings", Message: unreviewed, Count: 4})},
		{"minimum_score: 95", Policy{MinimumScore: 95},
			failed(PolicyBaseline, BlockingReason{Code: "minimum_score", Message: "Health Check score is below the required minimum", Count: 94, Threshold: 95})},
		{"defaults", Policy{}, Verdict{Passed: true, Status: "passed", Summary: `Security policy "baseline" passed`}},
	}
	for _, tc := range cases {
		res := Assess(qualityOnlyInput(), tc.policy)
		if res.Score != 94 || res.Grade != "A" || !reflect.DeepEqual(res.Verdict, tc.verdict) {
			t.Errorf("%s: score %d (%s), verdict %+v; want v1.14.0's score 94 (A), verdict %+v", tc.name, res.Score, res.Grade, res.Verdict, tc.verdict)
		}
		if bd := res.Breakdown; bd.ActiveFindings != 4 || bd.ReportOnlyFindings != 0 || res.Policy.QualityFindings != QualityFindingsBlock {
			t.Errorf("%s: breakdown %+v, quality_findings %q; want every finding scored under the default block", tc.name, bd, res.Policy.QualityFindings)
		}
	}

	for _, policy := range []Policy{{FailOn: FailOnAny}, PolicyForProfile(PolicyStrict), {MinimumScore: 95}} {
		policy.QualityFindings = QualityFindingsReport
		res := Assess(qualityOnlyInput(), policy)
		if !res.Verdict.Passed || res.Score != 100 || res.Breakdown.ActiveFindings != 0 || res.Breakdown.ReportOnlyByKind[ReportOnlyQuality] != 4 {
			t.Errorf("%+v: score %d, verdict %+v, breakdown %+v; want the findings reported only", policy, res.Score, res.Verdict, res.Breakdown)
		}
	}
}

// An explicit block_classes or block_sources entry beats report: a finding
// it names (by class, by a rule behind it, an earlier id of a split rule
// included, or by a scanner that reported it) is scored and gates, whether
// it is code quality under quality_findings: report or an IaC
// misconfiguration under the default iac_findings: report. The other
// findings stay reported only.
func TestExplicitBlockEntriesBeatReportOnly(t *testing.T) {
	reportQuality := func(p Policy) Policy {
		p.QualityFindings = QualityFindingsReport
		return p
	}
	// A finding as AI triage builds it, with the rules and scanners behind it.
	triaged := Finding{Source: "aitriage", Class: "ENTR-07", Severity: "LOW", File: "web/src/api.ts", Line: 3, NeedsReview: true,
		Rules: []string{"ENTR-07"}, Sources: []string{"aitriage"},
		Origins: []Origin{{Type: "core", Source: "aitriage", RuleID: "ENTR-07", Subcategory: SubcategoryQuality}}}
	// No quality rule has been split yet: the fixture labels one quality to
	// show that an entry naming its earlier id (ruleSuccessors) beats report.
	split := Finding{Source: "deploy", Class: "compose_default_credential", Severity: "LOW", File: "compose.yaml", Line: 3, NeedsReview: true,
		Origins: []Origin{{Type: "deploy", Source: "deploy", RuleID: "compose_default_credential", Subcategory: SubcategoryQuality}}}
	iac := Finding{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, NeedsReview: true,
		Origins: []Origin{{Type: "external", Source: "trivy", RuleID: "KSV-0012", Kind: kindMisconfiguration}}}
	cases := []struct {
		name     string
		findings []Finding
		policy   Policy
		gating   int
		reported int
	}{
		{"a rule id", qualityOnlyInput().Findings, reportQuality(Policy{BlockClasses: []string{"ENTR-12"}}), 1, 3},
		{"a scanner", qualityOnlyInput().Findings, reportQuality(Policy{BlockSources: []string{"nfr"}}), 1, 3},
		{"a rule behind a triaged finding", []Finding{triaged}, reportQuality(Policy{BlockClasses: []string{"ENTR-07"}}), 1, 0},
		{"a scanner behind a triaged finding", []Finding{triaged}, reportQuality(Policy{BlockSources: []string{"aitriage"}}), 1, 0},
		{"the earlier id of a split rule", []Finding{split}, reportQuality(Policy{BlockClasses: []string{"compose_hardcoded_secret"}}), 1, 0},
		{"entries that name nothing", qualityOnlyInput().Findings, reportQuality(Policy{BlockClasses: []string{"sql_injection"}, BlockSources: []string{"semgrep"}}), 0, 4},
		{"iac by scanner", []Finding{iac}, Policy{BlockSources: []string{"trivy"}}, 1, 0},
		{"iac by check", []Finding{iac}, Policy{BlockClasses: []string{"KSV-0012"}}, 1, 0},
		{"iac by class", []Finding{iac}, Policy{BlockClasses: []string{"k8s-container-runs-as-root"}}, 1, 0},
		{"iac by entries that name nothing", []Finding{iac}, Policy{BlockClasses: []string{"KSV-0017"}, BlockSources: []string{"gitleaks"}}, 0, 1},
	}
	for _, tc := range cases {
		res := Assess(Input{Findings: tc.findings}, tc.policy)
		bd := res.Breakdown
		if bd.ActiveFindings != tc.gating || bd.ReportOnlyFindings != tc.reported {
			t.Errorf("%s: %d gating, %d reported only; want %d and %d (breakdown %+v)", tc.name, bd.ActiveFindings, bd.ReportOnlyFindings, tc.gating, tc.reported, bd)
		}
		if blocked := !res.Verdict.Passed; blocked != (tc.gating > 0) || (blocked && res.Score == 100) {
			t.Errorf("%s: score %d, verdict %+v; want the named findings scored and blocking", tc.name, res.Score, res.Verdict)
		}
	}
}

// The quality kind covers LOW and INFO findings only. A rule pack can label
// a severe rule quality; its findings are scored and gate like any other.
// IaC misconfigurations are reported whatever their severity, as before.
func TestQualityKindCoversOnlyLowAndInfoFindings(t *testing.T) {
	packRule := func(severity string) Finding {
		return Finding{Source: "core", Class: "PACK-QUALITY-CHECK", Severity: severity, File: "app/main.py", Line: 3, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "PACK-QUALITY-CHECK", Subcategory: SubcategoryQuality}}}
	}
	policy := Policy{FailOn: FailOnCritical, QualityFindings: QualityFindingsReport}
	for severity, reported := range map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "": true, "LOW": false, "info": false} {
		if got := ReportOnlyKind(policy, packRule(severity)); (got == "") != reported {
			t.Errorf("severity %q: ReportOnlyKind = %q", severity, got)
		}
	}
	for _, severity := range []string{"CRITICAL", "HIGH"} {
		res := Assess(Input{Findings: []Finding{packRule(severity)}}, policy)
		if res.Verdict.Passed || res.Score == 100 || res.Breakdown.ReportOnlyFindings != 0 || res.Breakdown.CountBySeverity[severity] != 1 {
			t.Errorf("%s quality finding: score %d, verdict %+v, breakdown %+v; want it scored and blocking fail_on: critical", severity, res.Score, res.Verdict, res.Breakdown)
		}
	}
	iac := Finding{Source: "trivy", Class: "KSV-0017", Severity: "CRITICAL", File: "k8s/app.yaml", Line: 4,
		Origins: []Origin{{Type: "external", Source: "trivy", RuleID: "KSV-0017", Kind: kindMisconfiguration}}}
	if got := ReportOnlyKind(policy, iac); got != ReportOnlyIaC {
		t.Errorf("CRITICAL IaC misconfiguration: ReportOnlyKind = %q, want %q", got, ReportOnlyIaC)
	}
}

// A swallowed exception is not code quality: `except Exception: pass` around
// a token check turns a failed check into a pass. Bandit's B110 and B112 and
// the FastAPI rule (FAST-LAZY-EXC, subcategory audit as in v1.14.0) are
// scored and gate under quality_findings: report exactly as under block, with
// v1.14.0's score.
func TestSwallowedExceptionsGateUnderQualityReport(t *testing.T) {
	for _, origin := range []Origin{
		{Type: "external", Source: "bandit", RuleID: "B110"},
		{Type: "external", Source: "bandit", RuleID: "b112"},
		{Type: "core", Source: "aitriage", RuleID: "FAST-LAZY-EXC", Subcategory: "audit"},
	} {
		if got := OriginKind(origin); got != "" {
			t.Errorf("OriginKind(%+v) = %q, want no report-only kind", origin, got)
		}
	}
	// One swallowed exception both detectors reported, as the full scan
	// passes it in.
	in := Input{Findings: []Finding{
		{Source: "bandit", Class: "B110", Severity: "LOW", File: "app/auth.py", Line: 14, NeedsReview: true},
		{Source: "core", Class: "FAST-LAZY-EXC", Severity: "LOW", File: "app/auth.py", Line: 14, NeedsReview: true,
			Origins: []Origin{{Type: "core", Source: "core", RuleID: "FAST-LAZY-EXC", Subcategory: "audit"}}},
	}}
	for _, mode := range []string{QualityFindingsReport, QualityFindingsBlock, ""} {
		res := Assess(in, Policy{FailOn: FailOnAny, QualityFindings: mode})
		if res.Verdict.Passed || res.Score != 98 || res.Breakdown.ActiveFindings != 1 || res.Breakdown.ReportOnlyFindings != 0 {
			t.Errorf("quality_findings %q: score %d, verdict %+v, breakdown %+v; want v1.14.0's 98 and a failed gate", mode, res.Score, res.Verdict, res.Breakdown)
		}
	}
}

// qualityInput is a project with one unreviewed security finding and, apart
// from it, findings that are nothing but code quality or IaC.
func qualityInput() Input {
	findings := []Finding{{Source: "core", Class: "FAST-SQLI", Severity: "MEDIUM", File: "app/db.py", Line: 9, NeedsReview: true,
		Origins: []Origin{{Type: "core", Source: "core", RuleID: "FAST-SQLI", Subcategory: "vuln"}}}}
	findings = append(findings, qualityOnlyInput().Findings...)
	return Input{Findings: append(findings, Finding{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, NeedsReview: true,
		Origins: []Origin{{Type: "external", Source: "trivy", RuleID: "KSV-0012", Kind: "misconfiguration"}}})}
}

// Under report (the default for IaC, an opt-in for code quality), findings
// that are nothing but code quality or IaC change neither the score nor the
// verdict, and the breakdown counts them per kind. Under block they score
// and gate like any other finding.
func TestAssessKeepsReportOnlyFindingsOutOfTheScoreAndGate(t *testing.T) {
	full := qualityInput()
	securityOnly := Input{Findings: full.Findings[:1]}
	gate := Policy{FailOn: FailOnCritical, MaxCritical: 0, MaxHigh: 0, MaxMedium: 0, Profile: PolicyStrict, QualityFindings: QualityFindingsReport}

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
	if bd.CountBySource["nfr"] != 0 || bd.CountByRule["entr-12"] != 0 || bd.CountBySeverity["HIGH"] != 0 {
		t.Fatalf("breakdown = %+v, want report-only findings in no other count", bd)
	}

	blocked := Assess(full, Policy{FailOn: gate.FailOn, MaxCritical: 0, MaxHigh: 0, MaxMedium: 0, Profile: PolicyStrict,
		QualityFindings: QualityFindingsBlock, IaCFindings: IaCFindingsBlock})
	if blocked.Score >= reported.Score || blocked.Breakdown.ActiveFindings != 6 || blocked.Breakdown.ReportOnlyFindings != 0 || blocked.Breakdown.ReportOnlyByKind != nil {
		t.Fatalf("under block: score %d (report: %d), breakdown %+v; want every finding scored", blocked.Score, reported.Score, blocked.Breakdown)
	}
}

// A project with nothing but code-quality findings passes a gate that blocks
// every finding only under an explicit quality_findings: report; unset, as
// under block, the findings block.
func TestAssessQualityFindingsGateUnlessReported(t *testing.T) {
	in := qualityOnlyInput()
	strict := Policy{Profile: PolicyStrict, FailOn: FailOnAny, QualityFindings: QualityFindingsReport}
	if res := Assess(in, strict); !res.Verdict.Passed || res.Score != 100 || res.Policy.QualityFindings != QualityFindingsReport {
		t.Fatalf("under report: score %d, verdict %+v, policy %+v; want a pass at 100", res.Score, res.Verdict, res.Policy)
	}
	for _, mode := range []string{"", QualityFindingsBlock} {
		strict.QualityFindings = mode
		if res := Assess(in, strict); res.Verdict.Passed || res.Score == 100 || res.Policy.QualityFindings != QualityFindingsBlock {
			t.Fatalf("quality_findings %q: score %d, verdict %+v, policy %+v; want the findings to block", mode, res.Score, res.Verdict, res.Policy)
		}
	}
}

func TestQualityFindingsPolicyValues(t *testing.T) {
	for value, want := range map[string]string{"": QualityFindingsBlock, "report": QualityFindingsReport, " BLOCK ": QualityFindingsBlock, "blok": QualityFindingsBlock, "reprot": QualityFindingsBlock} {
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
	if got := NormalizePolicy(Policy{}).QualityFindings; got != QualityFindingsBlock {
		t.Errorf("default quality_findings = %q, want block", got)
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
