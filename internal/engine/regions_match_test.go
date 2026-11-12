package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/models"
)

// runRule scans one file with one rule and returns the reported lines.
func runRule(t *testing.T, rule models.Rule, name, src string) []int {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := core.NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	resolveSeverity(&rule, false)
	e := &Engine{}
	e.compileRule(&rule)
	e.Rules = []models.Rule{rule}
	var lines []int
	for _, r := range e.Run(&core.ProjectContext{RootPath: dir, ScanRoot: dir, Files: ws.Files, Stack: "unknown", Config: ws.Config}) {
		if r.ID == rule.ID {
			lines = append(lines, r.Line)
		}
	}
	return lines
}

func TestRegionsSkipCommentsAndStrings(t *testing.T) {
	src := "# os.system(cmd) explained here\nmsg = \"call os.system(cmd) carefully\"\nos.system(cmd)\n"
	rule := models.Rule{ID: "T-SHELL", Stack: "universal", Extensions: []string{".py"}, Target: "all", Pattern: `os\.system\(`, Severity: "HIGH"}

	rule.Regions = RegionsCode
	if got := runRule(t, rule, "app.py", src); len(got) != 1 || got[0] != 3 {
		t.Errorf("code: got lines %v, want [3]", got)
	}
	rule.Regions = RegionsCodeAndStrings
	if got := runRule(t, rule, "app.py", src); len(got) != 1 || got[0] != 2 {
		t.Errorf("code_and_strings: got lines %v, want [2]", got)
	}
	rule.Regions = RegionsComments
	if got := runRule(t, rule, "app.py", src); len(got) != 1 || got[0] != 1 {
		t.Errorf("comments: got lines %v, want [1]", got)
	}
	rule.Regions = RegionsAll
	if got := runRule(t, rule, "app.py", src); len(got) != 1 || got[0] != 1 {
		t.Errorf("all: got lines %v, want [1]", got)
	}
}

func TestRegionsIgnoredFirstMatchDoesNotHideLaterOnes(t *testing.T) {
	src := "os.system(a)  # aitriage-ignore: T-SHELL reviewed\nx = 1\nos.system(b)\n"
	rule := models.Rule{ID: "T-SHELL", Stack: "universal", Extensions: []string{".py"}, Target: "all", Regions: RegionsCode, Pattern: `os\.system\(`, Severity: "HIGH"}
	if got := runRule(t, rule, "app.py", src); len(got) != 1 || got[0] != 3 {
		t.Errorf("got lines %v, want [3]", got)
	}
}

func TestRegionsConditionsIgnoreComments(t *testing.T) {
	rule := models.Rule{ID: "T-TIMEOUT", Stack: "universal", Extensions: []string{".py"}, Target: "all", Regions: RegionsCode,
		Pattern: `requests\.get\(`, Condition: "not_contains:timeout=|timeout =", Severity: "LOW"}
	if got := runRule(t, rule, "a.py", "# TODO add timeout= later\nrequests.get(url)\n"); len(got) != 1 {
		t.Errorf("a comment must not satisfy not_contains: got %v", got)
	}
	if got := runRule(t, rule, "a.py", "requests.get(url, timeout=5)\n"); len(got) != 0 {
		t.Errorf("token in code must suppress: got %v", got)
	}
	rule.Condition = "contains:'use client'|\"use client\""
	if got := runRule(t, rule, "a.py", "// 'use client'\nrequests.get(url)\n"); len(got) != 1 {
		// .py has "#" comments, so the "//" line is code here.
		t.Errorf("contains in code: got %v", got)
	}
	if got := runRule(t, rule, "a.py", "# 'use client'\nrequests.get(url)\n"); len(got) != 0 {
		t.Errorf("contains only in a comment must not enable the rule: got %v", got)
	}
}

func TestPatternNotIsEvaluatedSeparately(t *testing.T) {
	rule := models.Rule{ID: "T-NOT", Stack: "universal", Extensions: []string{".py"}, Target: "all",
		Pattern: `torch\.load\(`, PatternNot: `weights_only\s*=\s*True`, Severity: "HIGH"}
	if got := runRule(t, rule, "m.py", "torch.load(path)\n"); len(got) != 1 {
		t.Errorf("legacy target: got %v, want one finding", got)
	}
	if got := runRule(t, rule, "m.py", "torch.load(path, weights_only=True)\n"); len(got) != 0 {
		t.Errorf("legacy target with pattern-not present: got %v", got)
	}
	rule.Regions = RegionsCode
	if got := runRule(t, rule, "m.py", "torch.load(path)\n"); len(got) != 1 {
		t.Errorf("regions: got %v, want one finding", got)
	}
}

func TestASTRuleHonoursInlineIgnore(t *testing.T) {
	src := "package main\n\nimport \"net/http\"\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil) // aitriage-ignore: T-AST local tool\n\t_ = 1\n\thttp.ListenAndServe(\":9090\", nil)\n}\n"
	rule := models.Rule{ID: "T-AST", Stack: "universal", Extensions: []string{".go"}, Target: "ast", Severity: "MEDIUM",
		Pattern: `(call_expression function: (selector_expression field: (field_identifier) @f (#eq? @f "ListenAndServe")))`}
	if got := runRule(t, rule, "main.go", src); len(got) != 1 || got[0] != 8 {
		t.Errorf("got lines %v, want [8]", got)
	}
}

func TestExtensionsAcceptBaseNameGlobs(t *testing.T) {
	entries := []string{"Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile"}
	for _, tc := range []struct {
		base string
		want bool
	}{
		{"Dockerfile", true}, {"dockerfile", true}, {"Dockerfile.prod", true}, {"api.Dockerfile", true},
		{"Containerfile", true}, {"Dockerfile-notes.md", false}, {"main.go", false},
	} {
		if got := matchesFileName(entries, filepath.Ext(tc.base), tc.base); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.base, got, tc.want)
		}
	}
}

func TestRegionsMultiLineMatchInCommentDoesNotHideLiveCode(t *testing.T) {
	src := "import tarfile\n# old: tarfile.open(path)\ntar = tarfile.open(path)\ntar.extractall(dest)\n"
	rule := models.Rule{ID: "T-TAR", Stack: "universal", Extensions: []string{".py"}, Target: "all", Regions: RegionsCode,
		Pattern: `(?s)tarfile\.open\(.*?\.extractall\(`, Severity: "HIGH"}
	if got := runRule(t, rule, "x.py", src); len(got) != 1 || got[0] != 3 {
		t.Errorf("got lines %v, want [3]", got)
	}
}

func TestFindingsCarryRuleMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("os.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := core.NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	rule := models.Rule{ID: "T-META", Stack: "universal", Extensions: []string{".py"}, Target: "all", Regions: RegionsCode,
		Pattern: `os\.system\(`, Severity: "HIGH", Metadata: map[string]string{"cwe": "CWE-78", "owasp": "A05:2025"}}
	e := &Engine{}
	e.compileRule(&rule)
	e.Rules = []models.Rule{rule}
	res := e.Run(&core.ProjectContext{RootPath: dir, ScanRoot: dir, Files: ws.Files, Stack: "unknown", Config: ws.Config})
	if len(res) != 1 || res[0].CWE != "CWE-78" || res[0].OWASPMapping != "A05:2025" {
		t.Errorf("results = %+v", res)
	}
}
