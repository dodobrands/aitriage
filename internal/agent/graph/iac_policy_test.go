package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
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
	if len(artifact.Findings) != 2 || !strings.Contains(string(data), `"kind":"misconfiguration"`) || !strings.Contains(string(data), `"report_only_findings":2`) {
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
	marked := EnrichedFinding{ID: "AWS-0107", Type: "external", Source: "trivy", Kind: external.KindMisconfiguration}
	unmarked := EnrichedFinding{ID: "AWS-0107", Type: "external", Source: "trivy"}
	other := EnrichedFinding{ID: "x", Type: "external", Source: "semgrep", Kind: external.KindMisconfiguration}
	if !misconfigurationOnly(marked) || misconfigurationOnly(unmarked) || misconfigurationOnly(other) {
		t.Fatalf("misconfigurationOnly = %v / %v / %v, want true only for the marked Trivy report",
			misconfigurationOnly(marked), misconfigurationOnly(unmarked), misconfigurationOnly(other))
	}
}
