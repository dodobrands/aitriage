package graph

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func writeProjectFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	project := t.TempDir()
	for name, content := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return project
}

// mitigationFixture is a small project whose flagged statements sit below the
// code a model might cite as their mitigation.
func mitigationFixture(t *testing.T) string {
	t.Helper()
	far := []string{"cmd = shlex.quote(cmd)"}
	for len(far) < 30 {
		far = append(far, "pass")
	}
	far = append(far,
		"subprocess.call(cmd, shell=True)", // line 31: 30 lines below line 1
		"subprocess.call(cmd, shell=True)", // line 32: 31 lines below line 1
	)
	return writeProjectFiles(t, map[string]string{
		"app.py": strings.Join([]string{
			"import os",                      // 1
			"import shlex",                   // 2
			"TOKEN = 'placeholder-value'",    // 3
			"def run(cmd, user, name, uid):", // 4
			"    # input sanitized by validate_input() upstream",        // 5
			"    x = 1  # input sanitized by validate_input() upstream", // 6
			`    note = "validate_input(cmd) is called upstream"`,       // 7
			`    """Docstring: cmd is validated upstream."""`,           // 8
			"    if not user.is_admin: abort(403)",                      // 9
			"    self.audit = True",                                     // 10
			"    cmd = shlex.quote(cmd)",                                // 11
			"    subprocess.call(cmd, shell=True)",                      // 12 flagged
			"    self.runner.call(name, shell=True)",                    // 13 flagged
			"    result = eval(os.environ['EXPR'])",                     // 14 flagged
			"    uid = int(uid)",                                        // 15
			`    cursor.execute(f"SELECT * FROM t WHERE id = {uid}")`,   // 16 flagged
			"    cmd = shlex.quote(cmd)",                                // 17
			"    subprocess.run(",                                       // 18 flagged
			"        cmd,",                                              // 19
			"        shell=True,",                                       // 20
			"    )",                                                     // 21
			"    return load_profile(user)",                             // 22 flagged
		}, "\n"),
		"far.py": strings.Join(far, "\n"),
		"web/app.ts": strings.Join([]string{
			"const html = req.query.name;",                    // 1
			"// sanitized by middleware",                      // 2
			"const clean = DOMPurify.sanitize(html); // safe", // 3
			"/* legacy:",                     // 4
			" * escapeHtml(clean) used here", // 5
			" */",                            // 6
			"el.innerHTML = clean;",          // 7 flagged
			"el.title = `<b>${clean}</b>`;",  // 8 flagged
		}, "\n"),
		"main.go": strings.Join([]string{
			"package main",
			"// validate(input) is called by the router",
			"func handle(input string) {",
			"\tif !validate(input) { return }",
			"\texec.Command(\"sh\", \"-c\", input).Run()", // 5 flagged
			"}",
		}, "\n"),
		"db/schema.sql": strings.Join([]string{
			"-- only admins can call this",
			"GRANT SELECT ON t TO app_reader;",
			"SELECT * FROM t WHERE name = 'x' || @input;", // 3 flagged
		}, "\n"),
		"site/index.html": strings.Join([]string{
			"<!-- escaped by the template engine -->",
			"<div>{{ user_input | escape }}</div>", // 2 flagged
		}, "\n"),
		"plugin/run.php":   "<?php\neval($_GET['code']);\n",
		"plugin/hello.php": "<?php\n$name = htmlspecialchars($_GET['name']);\necho $name;\n",
		"plugin/greet.php": "<?php\n$name = $_GET['name'];\n$name = htmlspecialchars($name);\necho $name;\n",
		"web/render.ts": strings.Join([]string{
			"export function render(el: HTMLElement, html: string): void {", // 1
			"  html = DOMPurify.sanitize(html);",                            // 2
			"  el.innerHTML = html;",                                        // 3 flagged
			"}",                                                             // 4
		}, "\n"),
		"build/task.gradle": "def cmd = sanitize(input)\nexec(cmd)\n",
		"docker-compose.yml": strings.Join([]string{
			"# Local smoke test only - NOT for production.",
			"services:",
			"  db:",
			"    environment:",
			"      POSTGRES_PASSWORD: example",
		}, "\n"),
		"config/settings.yaml": "debug: false\nallowed_hosts: [example.com]\n",
		"tests/test_app.py":    "import os\n\nresult = eval(os.environ['EXPR'])\n",
	})
}

func mitFinding(file, severity string, line int) EnrichedFinding {
	return EnrichedFinding{ID: "R", VulnID: "CS-MISC-001", Type: "core", Severity: severity, File: file, Line: line}
}

// E1: code_mitigation evidence must be code only, sit a few lines above the
// flagged line in the same source file, name a variable or function of the
// flagged statement, and be a guard of it or a re-assignment of it through a
// call. It never dismisses a CRITICAL finding or a hardcoded secret: a person
// decides those.
func TestCodeMitigationEvidenceValidation(t *testing.T) {
	project := mitigationFixture(t)
	const needsPerson = "a person must decide"

	cases := []struct {
		name       string
		finding    EnrichedFinding
		basis      string // defaults to code_mitigation
		evidLine   int
		observed   string
		wantReject string // substring of the rejection; empty means accepted
	}{
		// A CRITICAL finding or a hardcoded secret is never dismissed by
		// code_mitigation, however plausible the cited code.
		{name: "critical eval citing an unrelated assignment", finding: mitFinding("app.py", "CRITICAL", 14), evidLine: 3, observed: "TOKEN =", wantReject: needsPerson},
		{name: "critical eval citing related code", finding: mitFinding("app.py", "CRITICAL", 14), evidLine: 11, observed: "shlex.quote(cmd)", wantReject: needsPerson},
		{name: "critical go exec citing a validation check", finding: mitFinding("main.go", "CRITICAL", 5), evidLine: 4, observed: "validate(input)", wantReject: needsPerson},
		{name: "hardcoded secret by rule (bandit B105)", finding: EnrichedFinding{ID: "B105", Type: "external", Source: "bandit", Severity: "LOW", File: "app.py", Line: 3}, evidLine: 1, observed: "import os", wantReject: needsPerson},
		{name: "hardcoded secret by merged class", finding: EnrichedFinding{ID: "R", Class: "hardcoded_secret", Severity: "MEDIUM", File: "app.py", Line: 12}, evidLine: 11, observed: "shlex.quote(cmd)", wantReject: needsPerson},
		{name: "hardcoded secret by semgrep rule", finding: EnrichedFinding{ID: "generic.secrets.security.detected-generic-api-key", Type: "external", Source: "semgrep", Severity: "HIGH", File: "app.py", Line: 12}, evidLine: 11, observed: "shlex.quote(cmd)", wantReject: needsPerson},
		{name: "hardcoded secret reported by gitleaks", finding: EnrichedFinding{ID: "generic-api-key", Type: "external", Source: "gitleaks", Severity: "HIGH", File: "app.py", Line: 12}, evidLine: 11, observed: "shlex.quote(cmd)", wantReject: needsPerson},
		// test_only evidence keeps its behaviour, also for CRITICAL findings.
		{name: "critical test-only finding", finding: mitFinding("tests/test_app.py", "CRITICAL", 3), basis: "test_only", evidLine: 3},

		// The flagged line is never its own mitigation.
		{name: "php eval citing itself (HIGH)", finding: mitFinding("plugin/run.php", "HIGH", 2), evidLine: 2, observed: "eval($_GET['code'])", wantReject: "flagged line itself"},
		{name: "php eval citing itself (MEDIUM)", finding: mitFinding("plugin/run.php", "MEDIUM", 2), evidLine: 2, observed: "eval($_GET['code']);", wantReject: "flagged line itself"},
		{name: "py shell call citing itself (LOW)", finding: mitFinding("app.py", "LOW", 12), evidLine: 12, observed: "subprocess.call(cmd, shell=True)", wantReject: "flagged line itself"},
		// The mitigation must run before the flagged statement, close to it.
		{name: "py mitigation after the flagged line", finding: mitFinding("app.py", "HIGH", 12), evidLine: 17, observed: "shlex.quote(cmd)", wantReject: "after the flagged line"},
		{name: "py mitigation 31 lines above", finding: mitFinding("far.py", "HIGH", 32), evidLine: 1, observed: "shlex.quote(cmd)", wantReject: "more than 30 lines above"},
		{name: "py mitigation 30 lines above", finding: mitFinding("far.py", "HIGH", 31), evidLine: 1, observed: "shlex.quote(cmd)"},
		{name: "finding without a line", finding: mitFinding("app.py", "HIGH", 0), evidLine: 11, observed: "shlex.quote(cmd)", wantReject: "no line"},
		// Every non-whitespace byte of the cited text must be code.
		{name: "py comment", finding: mitFinding("app.py", "HIGH", 12), evidLine: 5, observed: "input sanitized by validate_input() upstream", wantReject: "inside a comment"},
		{name: "py code followed by a comment", finding: mitFinding("app.py", "HIGH", 12), evidLine: 6, observed: "1  # input sanitized by validate_input() upstream", wantReject: "inside a comment"},
		{name: "py trailing comment text", finding: mitFinding("app.py", "HIGH", 12), evidLine: 6, observed: "# input sanitized", wantReject: "inside a comment"},
		{name: "py string literal", finding: mitFinding("app.py", "MEDIUM", 12), evidLine: 7, observed: "validate_input(cmd) is called upstream", wantReject: "inside a string literal"},
		{name: "py code followed by a string literal", finding: mitFinding("app.py", "MEDIUM", 12), evidLine: 7, observed: `note = "validate_input(cmd)`, wantReject: "inside a string literal"},
		{name: "py docstring", finding: mitFinding("app.py", "MEDIUM", 12), evidLine: 8, observed: "cmd is validated upstream", wantReject: "inside a string literal"},
		{name: "ts line comment", finding: mitFinding("web/app.ts", "HIGH", 7), evidLine: 2, observed: "sanitized by middleware", wantReject: "inside a comment"},
		{name: "ts block comment continuation", finding: mitFinding("web/app.ts", "HIGH", 7), evidLine: 5, observed: "escapeHtml(clean)", wantReject: "inside a comment"},
		{name: "ts call followed by a comment", finding: mitFinding("web/app.ts", "HIGH", 7), evidLine: 3, observed: "clean = DOMPurify.sanitize(html); // safe", wantReject: "inside a comment"},
		{name: "go comment", finding: mitFinding("main.go", "HIGH", 5), evidLine: 2, observed: "validate(input)", wantReject: "inside a comment"},
		{name: "sql comment", finding: mitFinding("db/schema.sql", "MEDIUM", 3), evidLine: 1, observed: "only admins can call this", wantReject: "inside a comment"},
		{name: "html comment", finding: mitFinding("site/index.html", "MEDIUM", 2), evidLine: 1, observed: "escaped by the template engine", wantReject: "inside a comment"},
		// Prose without code tokens is not a mitigation.
		{name: "py import statement", finding: mitFinding("app.py", "LOW", 12), evidLine: 2, observed: "import shlex", wantReject: "no code tokens"},
		// The cited code must name a variable or function of the flagged
		// statement; keywords, receiver names and cut-off names do not count.
		{name: "py unrelated assignment", finding: mitFinding("app.py", "HIGH", 12), evidLine: 3, observed: "TOKEN =", wantReject: "shares no identifier"},
		{name: "py receiver name only", finding: mitFinding("app.py", "HIGH", 13), evidLine: 10, observed: "self.audit = True", wantReject: "shares no identifier"},
		{name: "py cut-off identifiers", finding: mitFinding("app.py", "HIGH", 12), evidLine: 11, observed: "lex.quote(cm", wantReject: "shares no identifier"},
		{name: "ts sanitizer call without the flagged variable", finding: mitFinding("web/app.ts", "HIGH", 7), evidLine: 3, observed: "DOMPurify.sanitize(html)", wantReject: "shares no identifier"},
		{name: "sql grant sharing only keywords", finding: mitFinding("db/schema.sql", "MEDIUM", 3), evidLine: 2, observed: "GRANT SELECT ON t TO app_reader", wantReject: "shares no identifier"},
		// Configuration and data files contain no code that mitigates; a file
		// in an unrecognised language cannot be checked for comments and strings.
		{name: "compose comment", finding: mitFinding("docker-compose.yml", "MEDIUM", 5), evidLine: 1, observed: "# Local smoke test only - NOT for production.", wantReject: "configuration or data file"},
		{name: "yaml setting", finding: mitFinding("config/settings.yaml", "LOW", 2), evidLine: 1, observed: "debug: false", wantReject: "configuration or data file"},
		{name: "unrecognised language", finding: mitFinding("build/task.gradle", "MEDIUM", 2), evidLine: 1, observed: "cmd = sanitize(input)", wantReject: "not a recognised source language"},

		// A sanitiser whose result gets a new name is not x = f(x): the line
		// cannot be told apart from the assignment that produces tainted data
		// (`cmd = request.args.get("dir")`), so it is left for review.
		{name: "ts sanitizer result under a new name", finding: mitFinding("web/app.ts", "HIGH", 7), evidLine: 3, observed: "clean = DOMPurify.sanitize(html)", wantReject: "does not pass clean through a call"},
		{name: "ts template literal interpolation of the new name", finding: mitFinding("web/app.ts", "MEDIUM", 8), evidLine: 3, observed: "clean = DOMPurify.sanitize(html)", wantReject: "does not pass clean through a call"},
		// Without a grammar the function cannot be checked: a HIGH finding is
		// left for a person, a lower one needs a guard or x = f(x).
		{name: "php escaping assignment, HIGH, no grammar", finding: mitFinding("plugin/hello.php", "HIGH", 3), evidLine: 2, observed: "$name = htmlspecialchars(", wantReject: needsPerson},
		{name: "php escaping of another value, MEDIUM", finding: mitFinding("plugin/hello.php", "MEDIUM", 3), evidLine: 2, observed: "$name = htmlspecialchars(", wantReject: "neither a guard nor a re-assignment"},
		{name: "php escaping quoted with its string argument", finding: mitFinding("plugin/hello.php", "HIGH", 3), evidLine: 2, observed: "$name = htmlspecialchars($_GET['name'])", wantReject: "part of it lies inside a string literal"},
		{name: "php taint source, MEDIUM", finding: mitFinding("plugin/greet.php", "MEDIUM", 4), evidLine: 2, observed: "$name = $_GET", wantReject: "neither a guard nor a re-assignment"},

		// Real mitigations tied to the flagged statement are accepted.
		{name: "py quoting before the call", finding: mitFinding("app.py", "HIGH", 12), evidLine: 11, observed: "shlex.quote(cmd)"},
		{name: "py authorization check", finding: mitFinding("app.py", "HIGH", 22), evidLine: 9, observed: "user.is_admin"},
		{name: "py cast before an f-string query", finding: mitFinding("app.py", "MEDIUM", 16), evidLine: 15, observed: "uid = int(uid)"},
		{name: "py quoting before a multi-line call", finding: mitFinding("app.py", "HIGH", 18), evidLine: 17, observed: "shlex.quote(cmd)"},
		{name: "ts sanitizer re-assignment", finding: mitFinding("web/render.ts", "HIGH", 3), evidLine: 2, observed: "html = DOMPurify.sanitize(html)"},
		{name: "go validation check", finding: mitFinding("main.go", "HIGH", 5), evidLine: 4, observed: "validate(input)"},
		{name: "php escaping re-assignment, MEDIUM", finding: mitFinding("plugin/greet.php", "MEDIUM", 4), evidLine: 3, observed: "$name = htmlspecialchars($name)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			basis := tc.basis
			if basis == "" {
				basis = "code_mitigation"
			}
			evidence := &DispositionEvidence{Basis: basis, File: tc.finding.File, Line: tc.evidLine, Observed: tc.observed}
			err := validateFalsePositiveEvidence(project, tc.finding, evidence)
			switch {
			case tc.wantReject == "" && err != nil:
				t.Fatalf("evidence rejected: %v", err)
			case tc.wantReject != "" && err == nil:
				t.Fatalf("evidence accepted, want rejection containing %q", tc.wantReject)
			case tc.wantReject != "" && !strings.Contains(err.Error(), tc.wantReject):
				t.Fatalf("rejection = %q, want it to contain %q", err, tc.wantReject)
			}
		})
	}
}

// The classification prompt states the window the validator enforces.
func TestClassificationPromptStatesTheMitigationWindow(t *testing.T) {
	if want := fmt.Sprintf("at most %d", maxMitigationDistance); !strings.Contains(prompts.ClassificationSystemPrompt, want) {
		t.Fatalf("classification prompt does not state %q", want)
	}
}

// A policy downgrade is distinguishable from an invalid citation.
func TestPersonOnlyRejectionIsMarked(t *testing.T) {
	project := mitigationFixture(t)
	evidence := &DispositionEvidence{Basis: "code_mitigation", File: "app.py", Line: 11, Observed: "shlex.quote(cmd)"}
	if err := validateFalsePositiveEvidence(project, mitFinding("app.py", "CRITICAL", 12), evidence); !errors.Is(err, errPersonMustDecide) {
		t.Fatalf("CRITICAL finding error = %v, want errPersonMustDecide", err)
	}
	unrelated := &DispositionEvidence{Basis: "code_mitigation", File: "app.py", Line: 3, Observed: "TOKEN ="}
	if err := validateFalsePositiveEvidence(project, mitFinding("app.py", "HIGH", 12), unrelated); err == nil || errors.Is(err, errPersonMustDecide) {
		t.Fatalf("unrelated evidence error = %v, want a plain rejection", err)
	}
}

// E1, end to end: a CRITICAL finding the model dismisses with code_mitigation
// evidence stays Needs Manual Review, the fail_on=critical gate blocks it, and
// the audit says why. This is the reproduction from review: eval on line 2
// "mitigated" by an unrelated assignment on line 3.
func TestRunKeepsCriticalFindingDismissedByCodeMitigationForReview(t *testing.T) {
	hermeticRun(t)
	project := writeProjectFiles(t, map[string]string{"app.py": "import os\nresult = eval(os.environ['EXPR'])\nTOKEN = 'placeholder-value'\n"})
	state := &AgentState{
		ProjectPath: project,
		CoreFindings: []core.CheckResult{
			{ID: "PY-EVAL", Name: "Code evaluation", Status: core.Absent, Evidence: "eval of environment input", Severity: "CRITICAL", File: "app.py", Line: 2},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnCritical},
	}
	stub := newStageLLM(t)
	stub.classify = func(_ int, batch []classificationPromptFinding) (string, error) {
		return dismissAll(batch, `{"basis":"code_mitigation","file":"app.py","line":3,"observed":"TOKEN ="}`), nil
	}

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want a complete triage", err)
	}
	d := state.FindingDispositions[0]
	if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceLLM || !strings.Contains(d.Rationale, "a person must decide") {
		t.Fatalf("disposition = %+v, want the dismissal kept for manual review", d)
	}
	if state.HealthCheck.Verdict.Passed || !hasBlockingReason(state.HealthCheck.Verdict, "critical_or_high_findings") {
		t.Fatalf("verdict = %+v, want fail_on=critical to block the CRITICAL finding", state.HealthCheck.Verdict)
	}
	if !auditMentions(state.ClassificationAudit, "a person must decide") {
		t.Fatalf("audit = %+v, want the downgrade recorded", state.ClassificationAudit)
	}
	if got := stub.count("classification"); got != 1 {
		t.Fatalf("classification calls = %d, want 1: a policy downgrade is an answer, not a reason to retry", got)
	}
}

// E1, end to end: a HIGH finding dismissed with code unrelated to it stays in
// the report, and the rejection reason is in the audit.
func TestClassifyFindingsRejectsUnrelatedCodeMitigation(t *testing.T) {
	pinConcurrency(t)
	project := writeProjectFiles(t, map[string]string{"app.py": "import os\nresult = eval(os.environ['EXPR'])\nTOKEN = 'placeholder-value'\nos.system(TOKEN)\n"})
	findings := []EnrichedFinding{
		{ID: "PY-EVAL", VulnID: "CS-EVAL-001", Type: "core", Severity: "HIGH", File: "app.py", Line: 2, Message: "eval"},
		{ID: "PY-SYSTEM", VulnID: "CS-CMDI-001", Type: "core", Severity: "HIGH", File: "app.py", Line: 4, Message: "os.system"},
	}
	mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		var entries []string
		for i, f := range batch {
			if f.ID == "PY-EVAL" {
				entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"False Positive","confidence":"high","rationale":"mitigated","evidence":{"basis":"code_mitigation","file":"app.py","line":3,"observed":"TOKEN ="}}`, i))
				continue
			}
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"True Positive","confidence":"high","rationale":"r"}`, i))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, nil
	}}
	var usage llm.Usage
	_, disps, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 40)
	if err != nil {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v", err)
	}
	if disps[0].Disposition != "Needs Manual Review" || disps[0].DispositionSource != dispositionSourceNRFallback {
		t.Fatalf("eval disposition = %+v, want the dismissal rejected", disps[0])
	}
	if disps[1].Disposition != "True Positive" {
		t.Fatalf("os.system disposition = %+v, want True Positive", disps[1])
	}
	if !auditMentions(audit, "after the flagged line") {
		t.Fatalf("audit = %+v, want the rejection reason recorded", audit)
	}
}

// E1: a cached dismissal is checked against the current rules before reuse.
func TestCachedCodeMitigationIsRevalidated(t *testing.T) {
	project := mitigationFixture(t)
	related := &DispositionEvidence{Basis: "code_mitigation", File: "app.py", Line: 11, Observed: "shlex.quote(cmd)"}
	unrelated := &DispositionEvidence{Basis: "code_mitigation", File: "app.py", Line: 3, Observed: "TOKEN ="}
	cases := []struct {
		name     string
		finding  EnrichedFinding
		evidence *DispositionEvidence
		usable   bool
	}{
		{"related mitigation of a HIGH finding", mitFinding("app.py", "HIGH", 12), related, true},
		{"unrelated code of a HIGH finding", mitFinding("app.py", "HIGH", 12), unrelated, false},
		{"related mitigation of a CRITICAL finding", mitFinding("app.py", "CRITICAL", 12), related, false},
		{"related mitigation of a hardcoded secret", EnrichedFinding{ID: "SECRET-ASSIGN", Type: "core", Source: "aitriage", Severity: "MEDIUM", File: "app.py", Line: 12}, related, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cached := FindingDisposition{Disposition: "False Positive", Confidence: "high", Evidence: tc.evidence}
			if got := cachedVerdictUsable(classifyRequest{projectPath: project}, tc.finding, cached); got != tc.usable {
				t.Fatalf("cachedVerdictUsable() = %v, want %v", got, tc.usable)
			}
		})
	}
}

// E1, end to end: a CRITICAL dismissal cached by an earlier run is not reused;
// the model is asked again.
func TestClassifyFindingsDoesNotReuseCachedCriticalCodeMitigation(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CACHE_DIR", t.TempDir())
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")
	project := mitigationFixture(t)
	findings := []EnrichedFinding{{ID: "PY-SUBPROCESS", VulnID: "CS-CMDI-001", Type: "core", Severity: "CRITICAL", File: "app.py", Line: 12, Message: "shell=True"}}
	cache := newVerdictCache("")
	cache.Set(verdictCacheKey(findings[0]), FindingDisposition{
		Disposition: "False Positive", Rationale: "quoted", Confidence: "high",
		Evidence: &DispositionEvidence{Basis: "code_mitigation", File: "app.py", Line: 11, Observed: "shlex.quote(cmd)"},
	})
	cache.Save()

	mock := &fakeLLM{t: t}
	var usage llm.Usage
	_, disps, _, stats, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 40)
	if err != nil {
		t.Fatal(err)
	}
	if mock.classifyCalls != 1 || disps[0].DispositionSource != dispositionSourceLLM || disps[0].Disposition != "True Positive" {
		t.Fatalf("disposition = %+v (classify calls %d), want the cached dismissal dropped and the model asked again", disps[0], mock.classifyCalls)
	}
	if stats.InvalidatedFalsePositives != 1 {
		t.Fatalf("cache stats = %+v, want the stale dismissal invalidated", stats)
	}
}

// E1, end to end: the classifier rejects a self-citing False Positive and
// records why in the classification audit. The other finding of the batch is
// classified, so the rejected one is an ordinary fallback.
func TestClassifyFindingsRejectsSelfCitingEvalFalsePositive(t *testing.T) {
	pinConcurrency(t)
	project := writeProjectFiles(t, map[string]string{"plugin/run.php": "<?php\neval($_GET['code']);\nsystem($_GET['cmd']);\n"})
	findings := []EnrichedFinding{
		{ID: "PHP-EVAL", VulnID: "CS-EXEC-001", Type: "core", Severity: "HIGH", File: "plugin/run.php", Line: 2, Message: "eval of request input"},
		{ID: "PHP-SYSTEM", VulnID: "CS-CMDI-001", Type: "core", Severity: "HIGH", File: "plugin/run.php", Line: 3, Message: "system of request input"},
	}
	mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		var entries []string
		for i, f := range batch {
			if f.ID == "PHP-EVAL" {
				entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"False Positive","confidence":"high","rationale":"path is excluded in .aitriage.yaml","evidence":{"basis":"code_mitigation","file":"plugin/run.php","line":2,"observed":"eval($_GET['code']);"}}`, i))
				continue
			}
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"True Positive","confidence":"high","rationale":"r"}`, i))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, nil
	}}
	var usage llm.Usage

	_, disps, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 40)
	if err != nil {
		t.Fatal(err)
	}
	if disps[0].Disposition != "Needs Manual Review" || disps[0].DispositionSource != dispositionSourceNRFallback {
		t.Fatalf("disposition = %+v, want the self-citing False Positive rejected", disps[0])
	}
	if !auditMentions(audit, "flagged line itself") {
		t.Fatalf("audit = %+v, want the rejection reason recorded", audit)
	}
}

// dismissAll answers every prompt finding with a False Positive carrying the
// given evidence JSON.
func dismissAll(batch []classificationPromptFinding, evidence string) string {
	var entries []string
	for i, f := range batch {
		entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"finding_id":%q,"fingerprint":%q,"disposition":"False Positive","confidence":"high","rationale":"mitigated","evidence":%s}`, i, f.FindingID, f.Fingerprint, evidence))
	}
	return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`
}

// auditMentions reports whether a rejection or downgrade in the audit
// contains text.
func auditMentions(audit []ClassificationAuditEntry, text string) bool {
	for _, entry := range audit {
		for _, r := range append(append([]AuditRejection(nil), entry.Rejected...), entry.Downgraded...) {
			if strings.Contains(r.Reason, text) {
				return true
			}
		}
	}
	return false
}

// E3: with fp_critical_requires_high_confidence, a CRITICAL finding is only
// dismissed with high confidence; anything less stays for manual review. Only
// test_only evidence can dismiss a CRITICAL finding at all.
func TestFPCriticalRequiresHighConfidencePolicy(t *testing.T) {
	project := writeProjectFiles(t, map[string]string{"tests/test_auth.py": "def test_handler(request):\n    verify_token(request)\n    return load(request)\n"})
	run := func(t *testing.T, severity, confidence string, policyOn bool) (FindingDisposition, []ClassificationAuditEntry) {
		t.Helper()
		pinConcurrency(t)
		findings := []EnrichedFinding{{ID: "R-1", VulnID: "CS-AUTH-001", Type: "core", Severity: severity, File: "tests/test_auth.py", Line: 3, Message: "missing auth"}}
		mock := &fakeLLM{t: t, classifyHandler: func(int, []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":` + strconv.Quote(confidence) + `,"rationale":"test fixture","evidence":{"basis":"test_only","file":"tests/test_auth.py","line":3}}]}`, nil
		}}
		var usage llm.Usage
		res, err := classifyFindings(context.Background(), classifyRequest{
			projectPath: project, findings: findings, client: mock, usage: &usage, batchSize: 40,
			policy: validationPolicy{fpCriticalRequiresHighConfidence: policyOn},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Dispositions[0], res.Audit
	}

	t.Run("critical medium confidence is kept for review", func(t *testing.T) {
		d, audit := run(t, "CRITICAL", "medium", true)
		if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceLLM || !strings.Contains(d.Rationale, "fp_critical_requires_high_confidence") {
			t.Fatalf("disposition = %+v, want Needs Manual Review explained by the policy", d)
		}
		if len(audit) == 0 || len(audit[0].Downgraded) != 1 {
			t.Fatalf("audit = %+v, want the downgrade recorded", audit)
		}
	})
	t.Run("critical high confidence is dismissed", func(t *testing.T) {
		if d, _ := run(t, "CRITICAL", "high", true); d.Disposition != "False Positive" {
			t.Fatalf("disposition = %+v, want False Positive", d)
		}
	})
	t.Run("policy off keeps the default behaviour", func(t *testing.T) {
		if d, _ := run(t, "CRITICAL", "medium", false); d.Disposition != "False Positive" {
			t.Fatalf("disposition = %+v, want False Positive", d)
		}
	})
	t.Run("non-critical findings are unaffected", func(t *testing.T) {
		if d, _ := run(t, "HIGH", "low", true); d.Disposition != "False Positive" {
			t.Fatalf("disposition = %+v, want False Positive", d)
		}
	})
	t.Run("a cached dismissal must satisfy the policy too", func(t *testing.T) {
		finding := EnrichedFinding{ID: "R-1", Severity: "CRITICAL", File: "tests/test_auth.py", Line: 3}
		cached := FindingDisposition{Disposition: "False Positive", Confidence: "medium", Evidence: &DispositionEvidence{Basis: "test_only", File: "tests/test_auth.py", Line: 3}}
		req := classifyRequest{projectPath: project, policy: validationPolicy{fpCriticalRequiresHighConfidence: true}}
		if cachedVerdictUsable(req, finding, cached) {
			t.Fatal("a cached medium-confidence dismissal of a CRITICAL finding must not be reused under the policy")
		}
	})
	t.Run("code_mitigation never dismisses a critical finding", func(t *testing.T) {
		pinConcurrency(t)
		auth := writeProjectFiles(t, map[string]string{"auth.py": "def handler(request):\n    verify_token(request)\n    return load(request)\n"})
		findings := []EnrichedFinding{{ID: "R-1", VulnID: "CS-AUTH-001", Type: "core", Severity: "CRITICAL", File: "auth.py", Line: 3, Message: "missing auth"}}
		mock := &fakeLLM{t: t, classifyHandler: func(int, []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"guard exists","evidence":{"basis":"code_mitigation","file":"auth.py","line":2,"observed":"verify_token(request)"}}]}`, nil
		}}
		var usage llm.Usage
		for _, policyOn := range []bool{false, true} {
			res, err := classifyFindings(context.Background(), classifyRequest{
				projectPath: auth, findings: findings, client: mock, usage: &usage, batchSize: 40,
				policy: validationPolicy{fpCriticalRequiresHighConfidence: policyOn},
			})
			if err != nil {
				t.Fatal(err)
			}
			if d := res.Dispositions[0]; d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceLLM {
				t.Fatalf("policy=%v disposition = %+v, want Needs Manual Review", policyOn, d)
			}
		}
	})
}

func TestFlexibleBoolDecodesModelShapes(t *testing.T) {
	cases := map[string]bool{
		`true`: true, `false`: false, `"true"`: true, `"FALSE"`: false,
		`"yes"`: true, `"no"`: false, `1`: true, `0`: false, `"1"`: true,
		`null`: false, `"partially"`: false, `{"a":1}`: false,
	}
	for input, want := range cases {
		var b FlexibleBool
		if err := b.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("%s: unexpected error %v", input, err)
		}
		if bool(b) != want {
			t.Errorf("%s decoded as %v, want %v", input, bool(b), want)
		}
	}
}

func TestDecodeThreatModelToleratesFieldShapes(t *testing.T) {
	reply := `{"component_overview": 7,
		"entry_points": [{"endpoint": "/upload", "type": "http", "trusted": "no", "validation": ["size", "mime"]}, "garbage", {"endpoint": "/admin", "trusted": "yes"}],
		"trust_boundaries": "none",
		"priority_areas": "uploads",
		"privileged_actions": {"action": "exec", "location": "worker.py", "guard": null}
	} trailing prose the model added`
	tm, err := decodeThreatModel(reply)
	if err != nil {
		t.Fatalf("decodeThreatModel() error = %v", err)
	}
	if tm.ComponentOverview != "7" || len(tm.EntryPoints) != 2 || bool(tm.EntryPoints[0].Trusted) || !bool(tm.EntryPoints[1].Trusted) {
		t.Fatalf("threat model = %+v, want the usable fields kept", tm)
	}
	if tm.EntryPoints[0].Validation != "size; mime" || len(tm.PriorityAreas) != 1 || tm.PriorityAreas[0] != "uploads" || len(tm.PrivilegedActions) != 1 {
		t.Fatalf("threat model = %+v, want lists and strings coerced", tm)
	}
	if _, err := decodeThreatModel(`{"priority_areas":["a"}}`); err == nil {
		t.Fatal("a reply that is not a JSON object must still be a parse error")
	}
}
