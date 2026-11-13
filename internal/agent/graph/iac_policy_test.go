package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// iacPolicyState is a project with two IaC misconfigurations only Trivy
// reported (a Kubernetes container running as root, an open security group)
// and a Dockerfile without USER that both Trivy (DS-0002) and the built-in
// DOCKER-NO-USER rule reported.
func iacPolicyState(t *testing.T, policy healthcheck.Policy, withMixed bool) *AgentState {
	t.Helper()
	root := writeProjectFiles(t, map[string]string{
		"k8s/app.yaml":  strings.Repeat("# filler\n", 20),
		"infra/main.tf": strings.Repeat("# filler\n", 20),
		"Dockerfile":    "FROM python:3.12-slim\nCMD [\"python\", \"main.py\"]\n",
	})
	state := &AgentState{
		ProjectPath: root,
		ExternalFindings: []external.UnifiedFinding{
			{Kind: external.KindMisconfiguration, Source: "trivy", RuleID: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, Message: "Container 'app' should set runAsNonRoot"},
			{Kind: external.KindMisconfiguration, Source: "trivy", RuleID: "AWS-0107", Severity: "HIGH", File: "infra/main.tf", Line: 12, Message: "Security group allows ingress from 0.0.0.0/0"},
		},
		Policy: policy,
	}
	if withMixed {
		state.ExternalFindings = append(state.ExternalFindings, external.UnifiedFinding{Kind: external.KindMisconfiguration, Source: "trivy", RuleID: "DS-0002", Severity: "HIGH", File: "Dockerfile", Message: "Image user should not be 'root'"})
		state.CoreFindings = []core.CheckResult{{ID: "DOCKER-NO-USER", Name: "Missing USER Instruction", Status: core.Absent, Severity: "HIGH", Evidence: "Required pattern not found"}}
	}
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	return state
}

// iac_findings: report (the default) keeps findings that are nothing but IaC
// misconfigurations out of the score and the gate, while they are still
// triaged and reported. A finding another detector also reported gates as it
// always did.
func TestIaCFindingsReportModeDoesNotGateOrScore(t *testing.T) {
	state := iacPolicyState(t, healthcheck.Policy{FailOn: healthcheck.FailOnCritical}, false)
	hc := state.HealthCheck
	if !hc.Verdict.Passed || hc.Score != 100 || hc.Breakdown.ActiveFindings != 0 || hc.Breakdown.ReportOnlyFindings != 2 {
		t.Fatalf("health check = score %d, verdict %+v, breakdown %+v; want two reported IaC findings that neither score nor gate", hc.Score, hc.Verdict, hc.Breakdown)
	}
	if hc.Policy.IaCFindings != healthcheck.IaCFindingsReport {
		t.Fatalf("policy iac_findings = %q, want the default report", hc.Policy.IaCFindings)
	}
	if !strings.Contains(state.SummaryMarkdown, "_2 IaC misconfiguration finding(s) reported, not gating (set `iac_findings: block` to enforce)._") {
		t.Fatalf("summary lacks the report-only line:\n%s", state.SummaryMarkdown)
	}
	// Still triaged and shown: in the summary's issues and the artifact.
	for _, rule := range []string{"k8s/app.yaml:10", "infra/main.tf:12"} {
		if !strings.Contains(state.SummaryMarkdown, rule) {
			t.Fatalf("summary does not show the IaC finding at %s:\n%s", rule, state.SummaryMarkdown)
		}
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(artifact)
	if len(artifact.Findings) != 2 || !strings.Contains(string(data), `"kind":"misconfiguration"`) || !strings.Contains(string(data), `"report_only_findings":2`) ||
		!strings.Contains(string(data), `"report_only_by_kind":{"iac":2}`) {
		t.Fatalf("triage-findings.json does not carry the IaC findings and their kind:\n%s", data)
	}

	// A merged finding with a detector that gated before keeps gating.
	mixed := iacPolicyState(t, healthcheck.Policy{FailOn: healthcheck.FailOnCritical}, true)
	bd := mixed.HealthCheck.Breakdown
	if mixed.HealthCheck.Verdict.Passed || bd.ActiveFindings != 1 || bd.ReportOnlyFindings != 2 || bd.CountByRule["docker-no-user"] != 1 {
		t.Fatalf("verdict = %+v, breakdown = %+v; want the Dockerfile finding (DS-0002 merged with DOCKER-NO-USER) to gate", mixed.HealthCheck.Verdict, bd)
	}
	if mixed.HealthCheck.Score >= 100 {
		t.Fatalf("score = %d, want the gating finding scored", mixed.HealthCheck.Score)
	}
}

// iac_findings: block scores and gates IaC misconfigurations like any other
// finding.
func TestIaCFindingsBlockModeGates(t *testing.T) {
	state := iacPolicyState(t, healthcheck.Policy{FailOn: healthcheck.FailOnCritical, IaCFindings: healthcheck.IaCFindingsBlock}, false)
	hc := state.HealthCheck
	if hc.Verdict.Passed || hc.Score >= 100 || hc.Breakdown.ActiveFindings != 2 || hc.Breakdown.ReportOnlyFindings != 0 || hc.Breakdown.CountBySource["trivy"] != 2 {
		t.Fatalf("health check = score %d, verdict %+v, breakdown %+v; want both IaC findings gating", hc.Score, hc.Verdict, hc.Breakdown)
	}
	if strings.Contains(state.SummaryMarkdown, "not gating") {
		t.Fatalf("summary reports IaC findings as not gating under block:\n%s", state.SummaryMarkdown)
	}
	if !strings.Contains(state.SummaryMarkdown, "`iac_findings=block`") {
		t.Fatalf("summary does not name the policy:\n%s", state.SummaryMarkdown)
	}
}

// Only the scanner's explicit marker makes a finding an IaC misconfiguration,
// not its rule id: a Trivy report without the marker gates.
func TestIaCFindingsAreRecognisedByTheMarkerOnly(t *testing.T) {
	kindOf := func(f EnrichedFinding) string {
		return healthcheck.OriginKind(healthOrigin(originOf(f), nil))
	}
	marked := EnrichedFinding{ID: "AWS-0107", Type: "external", Source: "trivy", Kind: external.KindMisconfiguration}
	unmarked := EnrichedFinding{ID: "AWS-0107", Type: "external", Source: "trivy"}
	other := EnrichedFinding{ID: "x", Type: "external", Source: "semgrep", Kind: external.KindMisconfiguration}
	if kindOf(marked) != healthcheck.ReportOnlyIaC || kindOf(unmarked) != "" || kindOf(other) != "" {
		t.Fatalf("origin kinds = %q / %q / %q, want iac only for the marked Trivy report",
			kindOf(marked), kindOf(unmarked), kindOf(other))
	}
}

// qualityPolicyState is a project whose findings are nothing but code
// quality: a file over 1,500 lines and two blocking database commits in
// async routes. The model left every finding for manual review.
func qualityPolicyState(t *testing.T, policy healthcheck.Policy) *AgentState {
	t.Helper()
	root := writeProjectFiles(t, map[string]string{
		"app/views.py":  strings.Repeat("# filler\n", 40),
		"app/routes.py": strings.Repeat("# filler\n", 40),
	})
	state := &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "ENTR-12", Name: "God File Detected", Status: core.Absent, Severity: "LOW", File: "app/views.py", Line: 1, Evidence: "File exceeds 1500 lines", Subcategory: healthcheck.SubcategoryQuality},
			{ID: "FAST-SYNC-ASYNC", Name: "Blocking Database Commit in Async Function", Status: core.Absent, Severity: "LOW", File: "app/routes.py", Line: 12, Evidence: "session.commit()", Subcategory: healthcheck.SubcategoryQuality},
			{ID: "FAST-SYNC-ASYNC", Name: "Blocking Database Commit in Async Function", Status: core.Absent, Severity: "LOW", File: "app/routes.py", Line: 30, Evidence: "session.commit()", Subcategory: healthcheck.SubcategoryQuality},
		},
		Policy: policy,
	}
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "Needs Manual Review")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	return state
}

// quality_findings: report (an opt-in) keeps findings that are nothing but
// code quality out of the score and the gate, even under a gate that blocks
// every finding; they are still triaged and listed, and the summary names
// the setting.
func TestQualityFindingsReportModeDoesNotGateOrScore(t *testing.T) {
	state := qualityPolicyState(t, healthcheck.Policy{Profile: healthcheck.PolicyStrict, FailOn: healthcheck.FailOnAny, QualityFindings: healthcheck.QualityFindingsReport})
	hc := state.HealthCheck
	if !hc.Verdict.Passed || hc.Score != 100 || hc.Breakdown.ActiveFindings != 0 || hc.Breakdown.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 3 {
		t.Fatalf("health check = score %d, verdict %+v, breakdown %+v; want three reported quality findings that neither score nor gate", hc.Score, hc.Verdict, hc.Breakdown)
	}
	if hc.Policy.QualityFindings != healthcheck.QualityFindingsReport {
		t.Fatalf("policy quality_findings = %q, want report", hc.Policy.QualityFindings)
	}
	summary := state.SummaryMarkdown
	if !strings.Contains(summary, "_3 code-quality finding(s) reported, not scored and not gating (set `quality_findings: block` to enforce)._") {
		t.Fatalf("summary lacks the quality line:\n%s", summary)
	}
	if !strings.Contains(summary, "`quality_findings=report`") {
		t.Fatalf("summary does not name the policy:\n%s", summary)
	}
	if strings.Contains(summary, "IaC misconfiguration") {
		t.Fatalf("summary counts quality findings as IaC:\n%s", summary)
	}
	for _, location := range []string{"app/views.py:1", "app/routes.py:12", "app/routes.py:30"} {
		if !strings.Contains(summary, location) {
			t.Fatalf("summary does not show the finding at %s:\n%s", location, summary)
		}
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := json.Marshal(artifact.HealthCheck); !strings.Contains(string(data), `"report_only_by_kind":{"quality":3}`) || !strings.Contains(string(data), `"quality_findings":"report"`) {
		t.Fatalf("triage-findings.json health check lacks the quality counts:\n%s", data)
	}
}

// quality_findings: block, the default, scores and gates code-quality
// findings like any other finding, as before the setting existed; the
// summary does not name a setting left at its default.
func TestQualityFindingsBlockModeGates(t *testing.T) {
	for _, mode := range []string{"", healthcheck.QualityFindingsBlock} {
		state := qualityPolicyState(t, healthcheck.Policy{Profile: healthcheck.PolicyStrict, FailOn: healthcheck.FailOnAny, QualityFindings: mode})
		hc := state.HealthCheck
		if hc.Verdict.Passed || hc.Score >= 100 || hc.Breakdown.ActiveFindings != 3 || hc.Breakdown.ReportOnlyFindings != 0 || hc.Breakdown.CountByRule["fast-sync-async"] != 2 {
			t.Fatalf("quality_findings %q: health check = score %d, verdict %+v, breakdown %+v; want every quality finding gating", mode, hc.Score, hc.Verdict, hc.Breakdown)
		}
		if hc.Policy.QualityFindings != healthcheck.QualityFindingsBlock {
			t.Fatalf("quality_findings %q: policy quality_findings = %q, want block", mode, hc.Policy.QualityFindings)
		}
		if strings.Contains(state.SummaryMarkdown, "code-quality finding(s) reported") || strings.Contains(state.SummaryMarkdown, "quality_findings=") {
			t.Fatalf("quality_findings %q: summary reports quality findings as not gating or names the default:\n%s", mode, state.SummaryMarkdown)
		}
	}
}

// The summary and the report count IaC and code-quality findings apart.
func TestReportOnlyLinesCountEachKind(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{
		"k8s/app.yaml": strings.Repeat("# filler\n", 20),
		"app/views.py": strings.Repeat("# filler\n", 40),
	})
	state := &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "ENTR-12", Name: "God File Detected", Status: core.Absent, Severity: "LOW", File: "app/views.py", Line: 1, Evidence: "File exceeds 1500 lines", Subcategory: healthcheck.SubcategoryQuality},
		},
		NFRFindings: []nfr.NFRFinding{
			{RuleID: "NFR-ENV-001", Name: ".env.example Missing", Severity: "LOW", Message: "No .env.example documents the environment variables"},
		},
		ExternalFindings: []external.UnifiedFinding{
			{Kind: external.KindMisconfiguration, Source: "trivy", RuleID: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, Message: "Container 'app' should set runAsNonRoot"},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical, QualityFindings: healthcheck.QualityFindingsReport},
	}
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	bd := state.HealthCheck.Breakdown
	if bd.ReportOnlyFindings != 3 || bd.ReportOnlyByKind[healthcheck.ReportOnlyIaC] != 1 || bd.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 2 {
		t.Fatalf("breakdown = %+v, want 1 iac and 2 quality report-only findings", bd)
	}
	for _, line := range []string{
		"_1 IaC misconfiguration finding(s) reported, not gating (set `iac_findings: block` to enforce)._",
		"_2 code-quality finding(s) reported, not scored and not gating (set `quality_findings: block` to enforce)._",
	} {
		if !strings.Contains(state.SummaryMarkdown, line) {
			t.Fatalf("summary lacks %q:\n%s", line, state.SummaryMarkdown)
		}
	}
	report := deterministicGateSection(state)
	for _, line := range []string{
		"- **IaC misconfigurations**: 1 reported, not gating and not scored (`iac_findings: report`)",
		"- **Code-quality findings**: 2 reported, not gating and not scored (`quality_findings: report`)",
	} {
		if !strings.Contains(report, line) {
			t.Fatalf("report lacks %q:\n%s", line, report)
		}
	}
}

// A gate that passes next to a low score says why in the summary and the
// report, without the model: unreviewed findings count in full, and the gate
// blocks only confirmed findings from the configured severity.
func TestSummaryExplainsALowScoreUnderAPassingGate(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{"app/handlers.py": strings.Repeat("# filler\n", 60)})
	state := &AgentState{ProjectPath: root, Policy: healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed, ConfirmedMinSeverity: healthcheck.SeverityMedium}}
	for i, severity := range []string{"HIGH", "HIGH", "MEDIUM"} {
		state.ExternalFindings = append(state.ExternalFindings, external.UnifiedFinding{
			Source: "semgrep", RuleID: "example.rules.check-" + string(rune('a'+i)), Severity: severity, File: "app/handlers.py", Line: 10 * (i + 1), Message: "example finding",
		})
	}
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "Needs Manual Review")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	hc := state.HealthCheck
	note := healthcheck.UnreviewedScoreNote(hc)
	if !hc.Verdict.Passed || hc.Score >= 100 || note == "" {
		t.Fatalf("score %d, verdict %+v, note %q; want a passing gate, a lower score and a note", hc.Score, hc.Verdict, note)
	}
	if !strings.Contains(note, "3 finding(s) await review and count in full") || !strings.Contains(note, "`fail_on: confirmed` blocks only confirmed findings at or above MEDIUM") {
		t.Fatalf("note = %q, want the unreviewed count and the gate's floor", note)
	}
	if !strings.Contains(state.SummaryMarkdown, "_"+note+"_") {
		t.Fatalf("summary lacks the note:\n%s", state.SummaryMarkdown)
	}
	if report := deterministicGateSection(state); !strings.Contains(report, "- **Score note**: "+note) {
		t.Fatalf("report lacks the note:\n%s", report)
	}

	// Once the findings are confirmed the gate blocks, and there is nothing
	// left to explain.
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if state.HealthCheck.Verdict.Passed || healthcheck.UnreviewedScoreNote(state.HealthCheck) != "" {
		t.Fatalf("verdict %+v, note %q; want a failed gate and no note", state.HealthCheck.Verdict, healthcheck.UnreviewedScoreNote(state.HealthCheck))
	}
}

// quality_findings changes the score and gate a cached report narrates, so
// a run under report never reuses entries stored under block.
func TestVerdictCacheNamespaceSeparatesReportOnlySettings(t *testing.T) {
	namespace := func(policy healthcheck.Policy) string {
		ctx := defaultVerdictCacheKeyContext("model")
		withVerdictCachePolicy(policy)(&ctx)
		return ctx.namespace()
	}
	defaults := namespace(healthcheck.Policy{})
	if explicit := namespace(healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsBlock}); explicit != defaults {
		t.Fatal("an explicit quality_findings: block changed the cache namespace")
	}
	if namespace(healthcheck.Policy{QualityFindings: healthcheck.QualityFindingsReport}) == defaults {
		t.Fatal("quality_findings: report shares the namespace of block")
	}
	if namespace(healthcheck.Policy{IaCFindings: healthcheck.IaCFindingsBlock}) == defaults {
		t.Fatal("iac_findings: block shares the namespace of report")
	}
}
