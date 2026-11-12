package graph

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// shapeFixture holds flagged statements below lines a model might cite as
// their mitigation, in languages with and without a grammar.
func shapeFixture(t *testing.T) string {
	t.Helper()
	return writeProjectFiles(t, map[string]string{
		"handler.py": strings.Join([]string{
			"import subprocess, logging",            // 1
			"",                                      // 2
			"def handler(request):",                 // 3
			`    cmd = "ls " + request.args["dir"]`, // 4 the taint source
			"    subprocess.call(cmd, shell=True)",  // 5 flagged
			"",                                      // 6
			"def logged(request):",                  // 7
			`    cmd = request.args.get("dir")`,     // 8 the taint source, through a call
			`    logging.info("running %s", cmd)`,   // 9 a log call
			"    subprocess.call(cmd, shell=True)",  // 10 flagged
		}, "\n"),
		"files.py": strings.Join([]string{
			"import os",                        // 1
			"",                                 // 2
			"def safe_read(path):",             // 3
			"    if not is_safe(path):",        // 4
			"        raise ValueError(path)",   // 5
			"    return open(path).read()",     // 6 flagged
			"",                                 // 7
			"def unsafe_read(path):",           // 8
			"    return open(path).read()",     // 9 flagged
			"",                                 // 10
			"def guarded_read(path):",          // 11
			"    if is_safe(path):",            // 12
			"        log(path)",                // 13
			"        data = open(path).read()", // 14 flagged, inside the check
			"    data = open(path).read()",     // 15 flagged, after it
			"    assert is_safe(path)",         // 16
			"    return open(path).read()",     // 17 flagged
			"",                                 // 18
			"def validated(path):",             // 19
			"    validate(path)",               // 20 a call whose result nobody checks
			"    return open(path).read()",     // 21 flagged
		}, "\n"),
		"srv.go": strings.Join([]string{
			"package srv",                     // 1
			"",                                // 2
			"func run(input string) {",        // 3
			"\tinput = filepath.Clean(input)", // 4
			"\texec.Command(\"sh\", \"-c\", input).Run()", // 5 flagged
			"}",                          // 6
			"",                           // 7
			"func other(input string) {", // 8
			"\texec.Command(\"sh\", \"-c\", input).Run()", // 9 flagged
			"}", // 10
		}, "\n"),
		"ui.js": strings.Join([]string{
			"function show(el, html) {",    // 1
			"  if (!isSafe(html)) return;", // 2
			"  el.innerHTML = html;",       // 3 flagged
			"}",                            // 4
			"function show2(el, html) {",   // 5
			"  console.log(html);",         // 6
			"  el.innerHTML = html;",       // 7 flagged
			"}",                            // 8
		}, "\n"),
		"App.java": strings.Join([]string{
			"class App {",                         // 1
			"  void run(String cmd) {",            // 2
			"    if (!isSafe(cmd)) { return; }",   // 3
			"    log.info(cmd);",                  // 4
			"    Runtime.getRuntime().exec(cmd);", // 5 flagged
			"  }",                                 // 6
			"}",                                   // 7
		}, "\n"),
		"service.py": strings.Join([]string{
			"class Store:",                         // 1
			"    def check(self, path):",           // 2
			"        if not is_safe(path):",        // 3
			"            raise ValueError(path)",   // 4
			"    def read(self, path):",            // 5
			"        if not is_safe(path): return", // 6
			"        return open(path).read()",     // 7 flagged
			"    def unsafe(self, path):",          // 8
			"        return open(path).read()",     // 9 flagged
		}, "\n"),
		"view.tsx": strings.Join([]string{
			"export const View = ({ html }: { html: string }) => {",        // 1
			"  html = sanitize(html);",                                     // 2
			"  return <div dangerouslySetInnerHTML={{ __html: html }} />;", // 3 flagged
			"};", // 4
		}, "\n"),
	})
}

// E1: the cited line must be a guard of a name the flagged statement uses (an
// if, elif or assert that checks it, or an early exit under such a check) or
// a re-assignment of that name through a call, in the same function. The
// review cases: the taint source, a log call and a check in the previous
// function were all accepted as mitigations of a HIGH finding.
func TestCodeMitigationMustBeAGuardOrReassignmentInTheSameFunction(t *testing.T) {
	project := shapeFixture(t)
	const needsPerson = "a person must decide"
	cases := []struct {
		name       string
		file       string
		severity   string
		flagged    int
		evidLine   int
		observed   string
		wantReject string // empty: accepted
	}{
		{"taint source by concatenation", "handler.py", "HIGH", 5, 4, "cmd =", "does not pass cmd through a call"},
		{"taint source through a getter call", "handler.py", "HIGH", 10, 8, `cmd = request.args.get(`, "does not pass cmd through a call"},
		{"log call naming the variable", "handler.py", "HIGH", 10, 9, "cmd)", "neither a guard nor a re-assignment"},
		{"guard of the previous function", "files.py", "HIGH", 9, 4, "is_safe(path)", "different function"},
		{"check that neither exits nor encloses", "files.py", "HIGH", 15, 12, "is_safe(path)", "neither exits early"},
		{"statement inside a check", "files.py", "HIGH", 15, 13, "log(path)", "neither a guard nor a re-assignment"},
		{"validator whose result is ignored", "files.py", "HIGH", 21, 20, "validate(path)", "neither a guard nor a re-assignment"},
		{"go re-assignment in another function", "srv.go", "HIGH", 9, 4, "filepath.Clean(input)", "different function"},
		{"js log call", "ui.js", "HIGH", 7, 6, "console.log(html)", "neither a guard nor a re-assignment"},
		{"HIGH finding in a language without a grammar", "App.java", "HIGH", 5, 3, "isSafe(cmd)", needsPerson},
		{"log call in a language without a grammar", "App.java", "MEDIUM", 5, 4, "log.info(cmd)", "neither a guard nor a re-assignment"},

		{"guard that exits early", "files.py", "HIGH", 6, 4, "is_safe(path)", ""},
		{"the early exit of the guard", "files.py", "HIGH", 6, 5, "ValueError(path)", ""},
		{"guard enclosing the flagged line", "files.py", "HIGH", 14, 12, "is_safe(path)", ""},
		{"assertion", "files.py", "HIGH", 17, 16, "is_safe(path)", ""},
		{"go re-assignment through a call", "srv.go", "HIGH", 5, 4, "filepath.Clean(input)", ""},
		{"js guard with an early return", "ui.js", "HIGH", 3, 2, "isSafe(html)", ""},
		{"guard in a language without a grammar, MEDIUM", "App.java", "MEDIUM", 5, 3, "isSafe(cmd)", ""},
		{"guard of another method", "service.py", "HIGH", 9, 6, "is_safe(path)", "different function"},
		{"guard of the method", "service.py", "HIGH", 7, 6, "is_safe(path)", ""},
		{"tsx re-assignment in an arrow function", "view.tsx", "HIGH", 3, 2, "html = sanitize(html)", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding := EnrichedFinding{ID: "R", VulnID: "CS-MISC-001", Type: "core", Severity: tc.severity, File: tc.file, Line: tc.flagged}
			err := validateFalsePositiveEvidence(project, finding, &DispositionEvidence{Basis: "code_mitigation", File: tc.file, Line: tc.evidLine, Observed: tc.observed})
			switch {
			case tc.wantReject == "" && err != nil:
				t.Fatalf("evidence rejected: %v", err)
			case tc.wantReject != "" && err == nil:
				t.Fatalf("evidence accepted, want rejection containing %q", tc.wantReject)
			case tc.wantReject != "" && !strings.Contains(err.Error(), tc.wantReject):
				t.Fatalf("rejection = %q, want it to contain %q", err, tc.wantReject)
			case tc.wantReject == needsPerson && !errors.Is(err, errPersonMustDecide):
				t.Fatalf("rejection = %v, want it kept for a person", err)
			}
		})
	}
}

// The review reproductions through the model-verdict validator: the dismissal
// is not accepted and the finding is not dismissed.
func TestModelDismissalCitingTheTaintSourceIsRejected(t *testing.T) {
	project := shapeFixture(t)
	finding := EnrichedFinding{ID: "B602", Type: "external", Source: "bandit", Severity: "HIGH", File: "handler.py", Line: 5, Message: "[bandit] subprocess call with shell=True", VulnID: "CS-CMDI-ABC123"}
	raw := rawDisposition{
		FindingID: finding.VulnID, Fingerprint: Fingerprint(finding), Disposition: "False Positive", Confidence: "high",
		Rationale: "cmd is built from a constant prefix",
		Evidence:  &DispositionEvidence{Basis: "code_mitigation", File: "handler.py", Line: 4, Observed: "cmd ="},
	}
	if d, reject, _ := validateLLMDisposition(project, finding, raw, validationPolicy{fpCriticalRequiresHighConfidence: true}); reject == "" || d.Disposition == "False Positive" {
		t.Fatalf("disposition = %+v, reject = %q: the tainted assignment was accepted as the mitigation", d, reject)
	}
}

// E6: a hardcoded secret is never dismissed automatically, by any evidence
// basis: a real credential committed to a test fixture is still exposed. A
// CRITICAL finding that is not a secret may still be dismissed as test-only.
func TestHardcodedSecretIsNeverDismissedAutomatically(t *testing.T) {
	project := writeProjectFiles(t, map[string]string{
		"tests/fixtures/aws.py": "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\"\n",
		"tests/test_eval.py":    "import os\n\nresult = eval(os.environ['EXPR'])\n",
	})
	testOnly := func(file string, line int) *DispositionEvidence {
		return &DispositionEvidence{Basis: "test_only", File: file, Line: line}
	}
	for _, tc := range []struct {
		name    string
		finding EnrichedFinding
	}{
		{"gitleaks CRITICAL in a test fixture", EnrichedFinding{ID: "aws-access-token", Type: "external", Source: "gitleaks", Severity: "CRITICAL", File: "tests/fixtures/aws.py", Line: 1}},
		{"bandit LOW in a test fixture", EnrichedFinding{ID: "B105", Type: "external", Source: "bandit", Severity: "LOW", File: "tests/fixtures/aws.py", Line: 1}},
		{"built-in SECRET rule", EnrichedFinding{ID: "SECRET-ASSIGN", Type: "core", Source: "aitriage", Severity: "HIGH", File: "tests/fixtures/aws.py", Line: 1}},
		{"merged finding with a secret detector", EnrichedFinding{ID: "R", Type: "core", Severity: "MEDIUM", File: "tests/fixtures/aws.py", Line: 1, Origins: []FindingOrigin{{Type: "external", Source: "gitleaks", RuleID: "generic-api-key"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFalsePositiveEvidence(project, tc.finding, testOnly(tc.finding.File, 1)); !errors.Is(err, errPersonMustDecide) {
				t.Fatalf("test_only error = %v, want the secret kept for a person", err)
			}
			if err := validateFalsePositiveEvidence(project, tc.finding, nil); !errors.Is(err, errPersonMustDecide) {
				t.Fatalf("no-evidence error = %v, want the secret kept for a person", err)
			}
		})
	}
	critical := EnrichedFinding{ID: "PY-EVAL", Type: "core", Source: "aitriage", Severity: "CRITICAL", File: "tests/test_eval.py", Line: 3}
	if err := validateFalsePositiveEvidence(project, critical, testOnly("tests/test_eval.py", 3)); err != nil {
		t.Fatalf("CRITICAL test-only finding rejected: %v", err)
	}

	// End to end: the model's test_only dismissal of the secret stays Needs
	// Manual Review, recorded as a downgrade, and is not asked again.
	pinConcurrency(t)
	secret := EnrichedFinding{ID: "aws-access-token", VulnID: "CS-SECRETS-001", Type: "external", Source: "gitleaks", Severity: "CRITICAL", File: "tests/fixtures/aws.py", Line: 1, Message: "[gitleaks] AWS secret"}
	mock := &fakeLLM{t: t, classifyHandler: func(int, []EnrichedFinding) (string, error) {
		return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"test fixture","evidence":{"basis":"test_only","file":"tests/fixtures/aws.py","line":1}}]}`, nil
	}}
	var usage llm.Usage
	res, err := classifyFindings(context.Background(), classifyRequest{
		projectPath: project, findings: []EnrichedFinding{secret}, client: mock, usage: &usage, batchSize: 40,
		policy: validationPolicy{fpCriticalRequiresHighConfidence: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := res.Dispositions[0]; d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceLLM || !strings.Contains(d.Rationale, "hardcoded secret") {
		t.Fatalf("disposition = %+v, want the dismissal kept for manual review", d)
	}
	if mock.classifyCalls != 1 || !auditMentions(res.Audit, "hardcoded secret") {
		t.Fatalf("classify calls = %d, audit = %+v; want one call and the downgrade recorded", mock.classifyCalls, res.Audit)
	}
}
