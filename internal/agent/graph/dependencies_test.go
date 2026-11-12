package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

func dependencyState() *AgentState {
	advisory := func(id, severity, pkg, installed, fixed string) external.UnifiedFinding {
		return external.UnifiedFinding{
			Source: "trivy", RuleID: id, Severity: severity, File: "requirements.txt",
			Message: pkg + ": advisory " + id, Package: pkg, InstalledVersion: installed, FixedVersion: fixed,
		}
	}
	return &AgentState{
		CoreFindings: []core.CheckResult{
			{ID: "FAST-EVAL", Name: "Dangerous Eval/Exec", Status: core.Absent, Severity: "CRITICAL", File: "app.py", Line: 4, Evidence: "eval"},
		},
		ExternalFindings: []external.UnifiedFinding{
			advisory("CVE-2022-22817", "CRITICAL", "pillow", "9.0.0", "9.0.1"),
			advisory("CVE-2023-50447", "CRITICAL", "pillow", "9.0.0", "10.2.0"),
			advisory("CVE-2022-45198", "HIGH", "pillow", "9.0.0", ""),
			advisory("CVE-2020-28493", "MEDIUM", "jinja2", "2.11.2", "2.11.3, 3.0.0a1"),
		},
	}
}

// D2: the summary header and Top Critical Issues show one line per package,
// while the score and the gate still count every advisory.
func TestSummaryGroupsDependencyAdvisoriesPerPackage(t *testing.T) {
	state := dependencyState()
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	summary := state.SummaryMarkdown

	header := summarySection(summary, "### Vulnerable Dependencies")
	for _, want := range []string{
		"pillow 9.0.0 → 10.2.0 (no fix for 1): 2 CRITICAL, 1 HIGH",
		"jinja2 2.11.2 → 2.11.3: 1 MEDIUM",
	} {
		if !strings.Contains(header, want) {
			t.Fatalf("dependency header lacks %q:\n%s", want, header)
		}
	}
	top := summarySection(summary, "Top Critical Issues")
	if n := strings.Count(top, "pillow"); n != 1 {
		t.Fatalf("Top Critical Issues lists pillow %d times, want one line for the package:\n%s", n, top)
	}
	if strings.Contains(top, "CVE-") {
		t.Fatalf("Top Critical Issues lists single advisories:\n%s", top)
	}
	if !strings.Contains(top, "`app.py:4`") {
		t.Fatalf("Top Critical Issues lost the code finding:\n%s", top)
	}

	// Owner decision: the score and the gate count each advisory.
	if bd := state.HealthCheck.Breakdown; bd.ActiveFindings != 5 || bd.ConfirmedFindings != 5 {
		t.Fatalf("breakdown = %+v, want 4 advisories and 1 code finding counted", bd)
	}

	// The package fields reach the canonical artifact.
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(artifact.Findings)
	for _, want := range []string{`"package":"pillow"`, `"installed_version":"9.0.0"`, `"fixed_version":"10.2.0"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("triage findings lack %s", want)
		}
	}
}

func TestMinimalFixChoosesTheLowestFixAboveTheInstalledVersion(t *testing.T) {
	cases := []struct {
		fixed, installed, want string
	}{
		{"10.2.0", "9.0.0", "10.2.0"},
		{"2.11.3, 3.0.0a1", "2.11.2", "2.11.3"},
		{"3.0.0a1, 2.11.3", "2.11.2", "2.11.3"},
		{">= 1.4.2", "1.4.0", "1.4.2"},
		{"", "1.0.0", ""},
		{"1.2.3", "", "1.2.3"},
	}
	for _, tc := range cases {
		if got := minimalFix(tc.fixed, tc.installed); got != tc.want {
			t.Errorf("minimalFix(%q, %q) = %q, want %q", tc.fixed, tc.installed, got, tc.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"1.0.0rc1", "1.0.0", "1.0.1", "1.2", "1.10.0", "2.0.0-beta.1", "2.0.0", "v2.0.1", "13.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		if c := compareVersions(ordered[i], ordered[i+1]); c >= 0 {
			t.Errorf("compareVersions(%q, %q) = %d, want < 0", ordered[i], ordered[i+1], c)
		}
		if c := compareVersions(ordered[i+1], ordered[i]); c <= 0 {
			t.Errorf("compareVersions(%q, %q) = %d, want > 0", ordered[i+1], ordered[i], c)
		}
	}
	if c := compareVersions("1.0", "1.0"); c != 0 {
		t.Errorf("compareVersions(1.0, 1.0) = %d, want 0", c)
	}
}
