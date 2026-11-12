package healthcheck

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

func TestClassifyRuleMapsEveryDetectorOfADefectToOneClass(t *testing.T) {
	cases := []struct {
		ref  RuleRef
		want string
	}{
		{RuleRef{Type: "core", Source: "aitriage", RuleID: "SECRET-ASSIGN"}, ClassHardcodedSecret},
		{RuleRef{Type: "external", Source: "bandit", RuleID: "B105"}, ClassHardcodedSecret},
		{RuleRef{Type: "external", Source: "gitleaks", RuleID: "generic-api-key"}, ClassHardcodedSecret},
		{RuleRef{Type: "external", Source: "semgrep", RuleID: "generic.secrets.security.detected-generic-secret.detected-generic-secret"}, ClassHardcodedSecret},
		{RuleRef{Type: "core", Source: "aitriage", RuleID: "FAST-SUBPROCESS"}, ClassCommandInjection},
		{RuleRef{Type: "core", Source: "aitriage", RuleID: "PY-SUBPROCESS"}, ClassCommandInjection},
		{RuleRef{Type: "external", Source: "bandit", RuleID: "B602"}, ClassCommandInjection},
		{RuleRef{Type: "external", Source: "semgrep", RuleID: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"}, ClassCommandInjection},
		{RuleRef{Type: "core", Source: "aitriage", RuleID: "DOCKER-NO-USER"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "semgrep", RuleID: "dockerfile.security.missing-user.missing-user"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "DS-0002"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "AVD-DS-0002"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "DS002"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "deploy", Source: "aitriage", RuleID: "dockerfile_root_user"}, ClassContainerRunsAsRoot},
		{RuleRef{Type: "deploy", Source: "aitriage", RuleID: "k8s_run_as_root"}, ClassK8sContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "KSV012"}, ClassK8sContainerRunsAsRoot},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "AVD-KSV-0012"}, ClassK8sContainerRunsAsRoot},
		{RuleRef{Type: "core", Source: "aitriage", RuleID: "FAST-LAZY-EXC"}, ClassExceptionSwallow},
		{RuleRef{Type: "external", Source: "bandit", RuleID: "B110"}, ClassExceptionSwallow},
		{RuleRef{Type: "external", Source: "trivy", RuleID: "CVE-2023-50447", Package: "pillow"}, ClassVulnerableDependency},
	}
	for _, tc := range cases {
		class, ok := ClassifyRule(tc.ref)
		if !ok || class.Key != tc.want {
			t.Errorf("ClassifyRule(%s/%s) = %q (%t), want %q", tc.ref.Source, tc.ref.RuleID, class.Key, ok, tc.want)
		}
	}
	for _, ref := range []RuleRef{
		{Type: "deploy", Source: "aitriage", RuleID: "nginx_missing_csp"},
		{Type: "external", Source: "trivy", RuleID: "AWS-0086"},
		{Type: "external", Source: "trivy", RuleID: "CVE-2023-50447"},
		{Type: "network", Source: "aitriage", RuleID: "port-53"},
		{Type: "core", Source: "aitriage", RuleID: "ENTR-02"},
	} {
		if class, ok := ClassifyRule(ref); ok {
			t.Errorf("ClassifyRule(%s/%s) = %q, want no class", ref.Source, ref.RuleID, class.Key)
		}
	}
	if c, ok := LookupClass("hardcoded-secret"); !ok || c.Key != ClassHardcodedSecret {
		t.Errorf("LookupClass(hardcoded-secret) = %+v, %t", c, ok)
	}
}

// D1 for the core-only scan: two built-in rules on one shell=True call are
// one defect for the score and the gate.
func TestCoreOnlyHealthCheckCountsOneDefectOnce(t *testing.T) {
	results := []core.CheckResult{
		{ID: "FAST-SUBPROCESS", Status: core.Absent, Severity: "CRITICAL", File: "/work/app/main.py", Line: 11},
		{ID: "PY-SUBPROCESS", Status: core.Absent, Severity: "CRITICAL", File: "/work/app/main.py", Line: 11},
		{ID: "FAST-SQLI", Status: core.Absent, Severity: "CRITICAL", File: "/work/app/main.py", Line: 11},
	}
	res := Evaluate(FromCoreResults(results))
	bd := res.Breakdown
	if bd.ActiveFindings != 2 || bd.DedupedFindings != 1 {
		t.Fatalf("breakdown = %+v, want the command injection counted once and SQL injection apart", bd)
	}
	if bd.CountByClass[ClassCommandInjection] != 1 || bd.CountByRule["py-subprocess"] != 1 || bd.CountByRule["fast-subprocess"] != 1 {
		t.Fatalf("counts by class = %v, by rule = %v, want the defect under its class and both rules", bd.CountByClass, bd.CountByRule)
	}
	// A policy naming the rule whose report was collapsed still blocks.
	for _, rule := range []string{"PY-SUBPROCESS", "FAST-SUBPROCESS"} {
		if v := EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed, BlockClasses: []string{rule}}); v.Passed {
			t.Fatalf("block_classes [%s] stopped blocking once its report was collapsed", rule)
		}
	}
}

// Only Dockerfile checks are file-scoped: a Kubernetes manifest declares many
// containers, so its run-as-root checks are one finding per line.
func TestOnlyDockerfileRunAsRootIsFileScoped(t *testing.T) {
	for _, rule := range []string{"DOCKER-NO-USER", "dockerfile_root_user", "DS-0002"} {
		if class, ok := ClassifyRule(RuleRef{Source: "trivy", RuleID: rule}); !ok || class.Scope != ScopeFile {
			t.Errorf("%s: class %+v, want a file-scoped class", rule, class)
		}
	}
	for _, rule := range []string{"k8s_run_as_root", "KSV-0012"} {
		if class, ok := ClassifyRule(RuleRef{Source: "trivy", RuleID: rule}); !ok || class.Scope != ScopeLine {
			t.Errorf("%s: class %+v, want a line-scoped class", rule, class)
		}
	}
	in := Input{Findings: []Finding{
		{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 10, Ignored: true},
		{Source: "trivy", Class: "KSV-0012", Severity: "HIGH", File: "k8s/app.yaml", Line: 40},
	}}
	if bd := Evaluate(in).Breakdown; bd.ActiveFindings != 1 || bd.IgnoredFindings != 1 || bd.DedupedFindings != 0 {
		t.Fatalf("breakdown = %+v, want the two containers counted apart", bd)
	}
}

// The core-only scan path counts project-level findings the way the triage
// graph does: one finding per rule. The same rule reported for two stacks is
// one finding; two rules of one class are two, a dismissal of one never hides
// the other, and the max_* thresholds see every one of them.
func TestCoreOnlyHealthCheckCountsProjectLevelFindingsPerRule(t *testing.T) {
	results := []core.CheckResult{
		{ID: "FAST-AUTH", Status: core.Absent, Severity: "HIGH"},
		{ID: "EXPRESS-AUTH", Status: core.Absent, Severity: "HIGH"},
		{ID: "NEXT-AUTH", Status: core.Absent, Severity: "HIGH", AuditStatus: core.AuditStatusIgnored},
		{ID: "ENTR-02", Status: core.Absent, Severity: "HIGH", Evidence: "No lockfile for npm in web"},
		{ID: "ENTR-02", Status: core.Absent, Severity: "HIGH", Evidence: "No lockfile for pip in api"},
	}
	res := Evaluate(FromCoreResults(results))
	bd := res.Breakdown
	if bd.ActiveFindings != 3 || bd.IgnoredFindings != 1 || bd.DedupedFindings != 1 {
		t.Fatalf("breakdown = %+v, want FAST-AUTH, EXPRESS-AUTH and ENTR-02 active and NEXT-AUTH ignored", bd)
	}
	if bd.CountByRule["fast-auth"] != 1 || bd.CountByRule["express-auth"] != 1 || bd.CountByClass["missing_authentication"] != 2 {
		t.Fatalf("counts by rule = %v, by class = %v", bd.CountByRule, bd.CountByClass)
	}
	verdict := EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed, MaxCritical: -1, MaxHigh: 2, MaxMedium: -1})
	if verdict.Passed {
		t.Fatal("max_high=2 passed with three active HIGH project-level findings")
	}
}

// Advisories are never collapsed, even when they share a manifest and have no
// line.
func TestAdvisoriesInOneManifestAreNeverCollapsed(t *testing.T) {
	in := Input{Findings: []Finding{
		{Source: "trivy", Class: ClassVulnerableDependency, Severity: "HIGH", File: "requirements.txt", Rules: []string{"CVE-2023-50447"}},
		{Source: "trivy", Class: ClassVulnerableDependency, Severity: "HIGH", File: "requirements.txt", Rules: []string{"CVE-2022-22817"}},
		{Source: "trivy", Class: ClassVulnerableDependency, Severity: "HIGH", File: "requirements.txt"},
		{Source: "trivy", Class: ClassVulnerableDependency, Severity: "HIGH", File: "requirements.txt"},
	}}
	if bd := Evaluate(in).Breakdown; bd.ActiveFindings != 4 || bd.DedupedFindings != 0 {
		t.Fatalf("breakdown = %+v, want four advisories", bd)
	}
}

// block_classes accepts a canonical class in either spelling and, as before
// detectors were merged, a rule id.
func TestBlockClassesMatchesClassesAndRules(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{{
		Source: "aitriage", Class: ClassHardcodedSecret, Severity: "LOW", File: "core/fns.py", Line: 3,
		Identity: "hardcoded_secret|core/fns.py|3", Rules: []string{"SECRET-ASSIGN", "B105"}, Sources: []string{"aitriage", "bandit"},
		NeedsReview: true,
	}}})
	// fail_on=confirmed with nothing confirmed: only block_* can block.
	for _, blocked := range []string{"hardcoded_secret", "hardcoded-secret", "B105", "SECRET-ASSIGN"} {
		if v := EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed, BlockClasses: []string{blocked}}); v.Passed {
			t.Errorf("block_classes [%s] did not block the merged finding", blocked)
		}
	}
	if v := EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed, BlockClasses: []string{"sql_injection"}}); !v.Passed {
		t.Errorf("block_classes [sql_injection] blocked a hardcoded secret: %+v", v.BlockingReasons)
	}
	if v := EvaluatePolicy(res, Policy{FailOn: FailOnConfirmed, BlockSources: []string{"bandit"}}); v.Passed {
		t.Error("block_sources [bandit] did not block a finding bandit reported")
	}
}
