package graph

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// scoreWithModelVerdict decides the findings a recorded decision covers, gives
// every other finding the model verdict, and computes the health check.
func scoreWithModelVerdict(state *AgentState, disposition string) {
	preset := deterministicDispositions(state)
	state.FindingDispositions = nil
	for i, f := range state.EnrichedFindings {
		d, decided := preset[i]
		if !decided {
			d = FindingDisposition{FindingIndex: i, FindingID: f.VulnID, Disposition: disposition, DispositionSource: dispositionSourceLLM, Fingerprint: Fingerprint(f)}
		}
		state.FindingDispositions = append(state.FindingDispositions, d)
	}
	computeHealthCheck(state)
}

func dispositionOfRule(t *testing.T, state *AgentState, rule string) FindingDisposition {
	t.Helper()
	for _, d := range state.FindingDispositions {
		if state.EnrichedFindings[d.FindingIndex].ID == rule {
			return d
		}
	}
	t.Fatalf("no disposition for %s in %+v", rule, state.FindingDispositions)
	return FindingDisposition{}
}

// A monorepo: a FastAPI backend without authentication and a static Next.js
// frontend whose missing middleware the team dismissed. The decision about
// the frontend (audit log), and one about the NFR check removed before
// triage, must not dismiss the backend's missing authentication.
func TestProjectLevelDecisionCoversOnlyItsOwnRule(t *testing.T) {
	state := &AgentState{
		ProjectPath: t.TempDir(),
		CoreFindings: []core.CheckResult{
			{ID: "FAST-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "No authentication mechanisms found."},
			{ID: "NEXT-AUTH", Name: "Missing Auth Middleware", Status: core.Absent, Severity: "HIGH", Evidence: "Missing Next.js middleware.", AuditStatus: core.AuditStatusIgnored},
		},
		Suppressions: SuppressionSummary{
			Total: 1,
			Reports: []DismissedReport{{
				ReportRef: ReportRef{Type: "nfr", Source: "aitriage", RuleID: "NFR-API-003"},
				Decision:  SuppressionDecision{Reason: SuppressionReasonAcceptedRisk, Note: "gateway authenticates"},
			}},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("findings = %+v, want FAST-AUTH and NEXT-AUTH kept apart", state.EnrichedFindings)
	}
	scoreWithModelVerdict(state, "True Positive")

	if d := dispositionOfRule(t, state, "NEXT-AUTH"); d.DispositionSource != dispositionSourceSuppressed || strings.Contains(d.Rationale, "covers every detector") {
		t.Fatalf("NEXT-AUTH disposition = %+v, want its own dismissal only", d)
	}
	if d := dispositionOfRule(t, state, "FAST-AUTH"); d.Disposition != "True Positive" || d.DispositionSource != dispositionSourceLLM {
		t.Fatalf("FAST-AUTH disposition = %+v, want it triaged, not dismissed", d)
	}
	bd := state.HealthCheck.Breakdown
	if bd.ActiveFindings != 1 || bd.IgnoredFindings != 1 || bd.CountByRule["fast-auth"] != 1 {
		t.Fatalf("breakdown = %+v, want FAST-AUTH active and only NEXT-AUTH ignored", bd)
	}
	if state.HealthCheck.Verdict.Passed || !hasBlockingReason(state.HealthCheck.Verdict, "critical_or_high_findings") {
		t.Fatalf("verdict = %+v, want the gate blocked by FastAPI's missing authentication", state.HealthCheck.Verdict)
	}
}

// Every stack's project-level defect counts for the max_* thresholds.
func TestProjectLevelRulesOfOneClassCountSeparately(t *testing.T) {
	state := &AgentState{
		ProjectPath: t.TempDir(),
		CoreFindings: []core.CheckResult{
			{ID: "FAST-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "none"},
			{ID: "EXPRESS-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "none"},
		},
		NFRFindings: []nfr.NFRFinding{{RuleID: "NFR-API-003", Name: "Authentication Middleware Missing", Severity: "HIGH", Message: "none"}},
		Policy:      healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed, MaxCritical: -1, MaxHigh: 2, MaxMedium: -1},
	}
	enrichFindings(state)
	scoreWithModelVerdict(state, "Needs Manual Review")
	if got := state.HealthCheck.Breakdown.CountBySeverity["HIGH"]; got != 3 {
		t.Fatalf("HIGH count = %d, want 3: one per rule", got)
	}
	if !hasBlockingReason(state.HealthCheck.Verdict, "high_threshold") {
		t.Fatalf("verdict = %+v, want max_high=2 exceeded by three missing-authentication rules", state.HealthCheck.Verdict)
	}
}

// One Kubernetes manifest declares two containers that run as root. A
// decision about one container (its Trivy report was removed before triage)
// does not cover the other, and the deploy check for a third line is its own
// finding: the class is line-scoped. Dockerfile checks stay file-scoped.
func TestKubernetesRunAsRootIsOneFindingPerContainer(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{
		"k8s/app.yaml": strings.Repeat("# filler\n", 60),
		"Dockerfile":   "FROM python:3.12-slim\nUSER root\nCMD [\"python\", \"main.py\"]\n",
	})
	state := &AgentState{
		ProjectPath: root,
		ExternalFindings: []external.UnifiedFinding{
			{Source: "trivy", RuleID: "KSV012", Severity: "MEDIUM", File: "k8s/app.yaml", Line: 40, Message: "Container 'payments' of Deployment 'payments' should set 'securityContext.runAsNonRoot' to true"},
			{Source: "trivy", RuleID: "DS002", Severity: "HIGH", File: "Dockerfile", Message: "Image user should not be 'root'"},
		},
		DeployFindings: []deployaudit.DeployFinding{
			{File: "k8s/app.yaml", Line: 52, Issue: "k8s_run_as_root", Severity: "HIGH", Advice: "Do not run as root"},
			{File: "Dockerfile", Line: 2, Issue: "dockerfile_root_user", Severity: "HIGH", Advice: "Add USER nonroot"},
		},
		Suppressions: SuppressionSummary{
			Total: 1,
			Reports: []DismissedReport{{
				ReportRef: ReportRef{Type: "external", Source: "trivy", RuleID: "KSV012", File: "k8s/app.yaml", Line: 10},
				Decision:  SuppressionDecision{Reason: SuppressionReasonAcceptedRisk, Note: "debug sidecar"},
			}},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 3 {
		t.Fatalf("findings = %+v, want two k8s containers and one Dockerfile defect", state.EnrichedFindings)
	}
	for _, f := range state.EnrichedFindings {
		want := healthcheck.ClassK8sContainerRunsAsRoot
		if f.File == "Dockerfile" {
			want = healthcheck.ClassContainerRunsAsRoot
			if len(f.Origins) != 2 {
				t.Fatalf("Dockerfile finding origins = %+v, want Trivy and the deploy check merged", f.Origins)
			}
		}
		if f.Class != want || !strings.HasPrefix(f.VulnID, "CS-ROOT-") {
			t.Fatalf("%s %s:%d class = %q id = %s, want %s", f.ID, f.File, f.Line, f.Class, f.VulnID, want)
		}
	}

	scoreWithModelVerdict(state, "True Positive")
	for _, d := range state.FindingDispositions {
		if d.DispositionSource == dispositionSourceSuppressed {
			f := state.EnrichedFindings[d.FindingIndex]
			t.Fatalf("%s at %s:%d dismissed by the decision about the container on line 10", f.ID, f.File, f.Line)
		}
	}
	if bd := state.HealthCheck.Breakdown; bd.ActiveFindings != 3 || bd.IgnoredFindings != 0 {
		t.Fatalf("breakdown = %+v, want all three run-as-root findings active", bd)
	}

	// The decision does cover a report of the same container (same line).
	state.ExternalFindings[0].Line = 10
	enrichFindings(state)
	scoreWithModelVerdict(state, "True Positive")
	if d := dispositionOfRule(t, state, "KSV012"); d.DispositionSource != dispositionSourceSuppressed {
		t.Fatalf("KSV012 on line 10 disposition = %+v, want the recorded decision applied", d)
	}
}

// A swallowed exception the FastAPI rule and Bandit both reported is one
// finding, and it is not code quality: `except Exception: pass` around a
// token check turns a failed check into a pass. Under quality_findings:
// report it is scored and gates, also when a custom rule labels
// FAST-LAZY-EXC quality: a finding is reported only when every detector
// behind it is a quality check, and Bandit's B110 is not one. Of the NFR
// checks, a missing .env.example is code quality and a missing
// authentication middleware is not.
func TestSwallowedExceptionGatesUnderQualityReport(t *testing.T) {
	build := func(subcategory string) *AgentState {
		state := &AgentState{
			ProjectPath: t.TempDir(),
			CoreFindings: []core.CheckResult{
				{ID: "FAST-LAZY-EXC", Name: "Exception Silently Swallowed", Status: core.Absent, Severity: "LOW", File: "main.py", Line: 13, Evidence: "except: pass", Subcategory: subcategory},
			},
			ExternalFindings: []external.UnifiedFinding{
				{Source: "bandit", RuleID: "B110", Severity: "LOW", File: "main.py", Line: 13, Message: "try_except_pass"},
			},
			NFRFindings: []nfr.NFRFinding{
				{RuleID: "NFR-ENV-001", Name: ".env.example Missing", Severity: "LOW", Message: "No .env.example documents the environment variables"},
				{RuleID: "NFR-API-003", Name: "Authentication Middleware Missing", Severity: "MEDIUM", Message: "No authentication middleware detected"},
			},
			Policy: healthcheck.Policy{FailOn: healthcheck.FailOnAny, QualityFindings: healthcheck.QualityFindingsReport},
		}
		enrichFindings(state)
		scoreWithModelVerdict(state, "True Positive")
		return state
	}

	// audit is the catalog's subcategory of FAST-LAZY-EXC.
	for _, subcategory := range []string{"audit", healthcheck.SubcategoryQuality} {
		state := build(subcategory)
		if len(state.EnrichedFindings) != 3 {
			t.Fatalf("findings = %+v, want the exception merged and both NFR checks", state.EnrichedFindings)
		}
		hc := state.HealthCheck
		bd := hc.Breakdown
		if hc.Verdict.Passed || bd.ActiveFindings != 2 || bd.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 1 ||
			bd.CountByRule["b110"] != 1 || bd.CountByRule["fast-lazy-exc"] != 1 || bd.CountByRule["nfr-api-003"] != 1 {
			t.Fatalf("FAST-LAZY-EXC subcategory %q: verdict %+v, breakdown %+v; want the exception and the missing authentication gating, .env.example reported only",
				subcategory, hc.Verdict, bd)
		}
	}
}
