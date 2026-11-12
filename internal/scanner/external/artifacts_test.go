package external

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestGeneratedArtifactPath(t *testing.T) {
	for _, path := range []string{
		"aitriage-reports/run/report.md",
		"/workspace/aitriage-reports/run/scan.json",
		`C:\repo\.aitriage\history\audit.json`,
		"nested/.aitriage-cache/data",
	} {
		if !isGeneratedArtifactPath(path) {
			t.Errorf("generated path not recognized: %q", path)
		}
	}
	for _, path := range []string{"src/report.go", "docs/aitriage-reports.md", "aitriage-reports-backup/file"} {
		if isGeneratedArtifactPath(path) {
			t.Errorf("ordinary path incorrectly excluded: %q", path)
		}
	}
}

func TestGitleaksConfigExtendsDefaultsAndExcludesGeneratedArtifacts(t *testing.T) {
	path, cleanup, err := newGitleaksConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary config mode = %o, want 600", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	for _, want := range []string{"useDefault = true", "aitriage-reports", "[.]aitriage", "[.]aitriage-cache"} {
		if !strings.Contains(content, want) {
			t.Errorf("config missing %q:\n%s", want, content)
		}
	}
}

func TestParserFiltersGeneratedArtifacts(t *testing.T) {
	semgrep := semgrepOutput{}
	semgrep.Results = append(semgrep.Results, struct {
		RuleID string `json:"check_id"`
		Extra  struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
		Path  string `json:"path"`
		Start struct {
			Line int `json:"line"`
		} `json:"start"`
	}{Path: "aitriage-reports/run/report.md"})
	if !isGeneratedArtifactPath(semgrep.Results[0].Path) {
		t.Fatal("parser defense must recognize generated Semgrep path")
	}
}

func TestFilterTestLikeFindingsKeepsProductionSubstringNames(t *testing.T) {
	input := []UnifiedFinding{
		{RuleID: "B101", File: "/workspace/tests/test_security.py"},
		{RuleID: "B105", File: "/workspace/testdata/dummy_token.py"},
		{RuleID: "B110", File: "/workspace/contest.go"},
	}
	got := FilterTestLikeFindings(input)
	if len(got) != 1 || got[0].File != "/workspace/contest.go" {
		t.Fatalf("filtered findings = %#v, want only contest.go", got)
	}
}
