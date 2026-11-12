package external_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/rules"
)

// runTaintConfig runs the trusted taint config (as a full audit would) over
// one fixture directory under testdata/xss and returns every finding.
func runTaintConfig(t *testing.T, sub string) []external.UnifiedFinding {
	t.Helper()
	if !external.IsInstalled("semgrep") {
		t.Skip("semgrep not installed; skipping real-Semgrep taint test")
	}

	dir := t.TempDir()
	cfg, ids, err := rules.WriteTaintConfig(dir)
	if err != nil {
		t.Fatalf("WriteTaintConfig: %v", err)
	}

	target := filepath.Join("testdata", "xss", filepath.FromSlash(sub))
	findings, err := external.RunSemgrepConfigs(context.Background(), target, ids, cfg)
	if err != nil {
		t.Fatalf("RunSemgrepConfigs(%s): %v", sub, err)
	}
	return findings
}

// byFileFor keeps the findings of ruleID whose path contains pathPart, keyed by
// base filename.
func byFileFor(findings []external.UnifiedFinding, ruleID, pathPart string) map[string][]external.UnifiedFinding {
	byFile := map[string][]external.UnifiedFinding{}
	for _, f := range findings {
		if f.RuleID != ruleID || !strings.Contains(filepath.ToSlash(f.File), pathPart) {
			continue
		}
		byFile[filepath.Base(f.File)] = append(byFile[filepath.Base(f.File)], f)
	}
	return byFile
}

// runXSS returns the FAST-XSS findings for testdata/xss/<sub>.
func runXSS(t *testing.T, sub string) map[string][]external.UnifiedFinding {
	t.Helper()
	return byFileFor(runTaintConfig(t, sub), "FAST-XSS", "")
}

type taintCase struct {
	file string
	min  int
	what string
}

// checkTaintCases asserts each file has at least min findings of ruleID and
// that every finding carries the canonical id and the semgrep source.
func checkTaintCases(t *testing.T, ruleID string, byFile map[string][]external.UnifiedFinding, cases []taintCase) {
	t.Helper()
	for _, c := range cases {
		if got := len(byFile[c.file]); got < c.min {
			t.Errorf("%s: expected >=%d %s finding(s) (%s), got %d", c.file, c.min, ruleID, c.what, got)
		}
	}
	for _, f := range byFile {
		for _, finding := range f {
			if finding.Source != "semgrep" {
				t.Errorf("expected source 'semgrep', got %q", finding.Source)
			}
			if finding.RuleID != ruleID {
				t.Errorf("expected canonical rule id %s, got %q", ruleID, finding.RuleID)
			}
		}
	}
}

// TestFastXSS_Unsafe_RealSemgrep drives the real bundled Semgrep over the unsafe
// fixtures and asserts every reflected-XSS variant is caught with the canonical
// FAST-XSS id: direct, through a local variable / f-string / % / .format(), via
// query_params / Query() / Form(), request.form() / cookies / headers, and
// Markup().
func TestFastXSS_Unsafe_RealSemgrep(t *testing.T) {
	byFile := runXSS(t, "unsafe")
	checkTaintCases(t, "FAST-XSS", byFile, []taintCase{
		{"direct.py", 1, "direct reflected XSS in HTMLResponse f-string"},
		{"via_var.py", 1, "taint through local variable, concat and %-format"},
		{"query_params.py", 1, "request.query_params.get via .format()"},
		{"query_dep.py", 2, "Query() and Form() parameters into HTML sinks"},
		{"custom_escape.py", 1, "a user-defined function named escape is not a trusted sanitizer"},
		{"response_class.py", 1, "route decorator response_class=HTMLResponse"},
		{"response_charset.py", 1, "HTML Response media type with charset parameter"},
		{"request_sources.py", 3, "await request.form(), request.cookies and request.headers"},
		{"markup.py", 1, "Markup() built from a route parameter"},
	})
}

// TestFastXSS_Safe_RealSemgrep asserts no false positives: escaped flows
// (html.escape, markupsafe.escape, `from html import escape`), a static page,
// JSONResponse, dependencies and framework objects, int-typed parameters, a
// tainted status_code, autoescaping template rendering (TemplateResponse,
// get_template().render, a render() helper), and a function behind a
// non-route decorator.
func TestFastXSS_Safe_RealSemgrep(t *testing.T) {
	byFile := runXSS(t, "safe")
	if len(byFile) != 0 {
		t.Errorf("expected zero FAST-XSS findings on safe fixtures, got %v", byFile)
	}
}

// TestFastAPITaintRules_RealSemgrep covers the SQL injection, path traversal,
// SSRF and open redirect taint rules: every unsafe fixture is reported with
// the canonical id, and the safe fixtures (bound parameters, int(), allowlists,
// basename/is_relative_to checks, url_for, int-typed parameters, dict.get)
// stay silent.
func TestFastAPITaintRules_RealSemgrep(t *testing.T) {
	tests := []struct {
		rule  string
		cases []taintCase
	}{
		{"FAST-SQLI", []taintCase{
			{"fstring_text.py", 1, "f-string inside text()"},
			{"percent_concat.py", 2, "% formatting and + concatenation"},
			{"via_variable.py", 1, "SQL built in a variable from request.json()"},
		}},
		{"FAST-PATH-TRAVERSAL", []taintCase{
			{"join_concat.py", 3, "os.path.join, + and f-string into FileResponse/open/os.remove"},
		}},
		{"FAST-SSRF", []taintCase{
			{"client_get.py", 2, "httpx client.get and requests.post with a route parameter"},
		}},
		{"FAST-OPEN-REDIRECT", []taintCase{
			{"next_param.py", 2, "route parameter and query_params into RedirectResponse"},
		}},
	}
	// One Semgrep run over testdata/xss/taint/<RULE>/{unsafe,safe}; a rule
	// must not fire on another rule's fixtures' safe directory either.
	findings := runTaintConfig(t, "taint")
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			checkTaintCases(t, tc.rule, byFileFor(findings, tc.rule, "/"+tc.rule+"/unsafe/"), tc.cases)
			if safe := byFileFor(findings, tc.rule, "/safe/"); len(safe) != 0 {
				t.Errorf("expected zero %s findings on safe fixtures, got %v", tc.rule, safe)
			}
		})
	}
}
