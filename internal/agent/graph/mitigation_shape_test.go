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
			_, err := validateFalsePositiveEvidence(project, finding, &DispositionEvidence{Basis: "code_mitigation", File: tc.file, Line: tc.evidLine, Observed: tc.observed})
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
		FindingID: finding.VulnID, Disposition: "False Positive", Confidence: "high",
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
			if _, err := validateFalsePositiveEvidence(project, tc.finding, testOnly(tc.finding.File, 1)); !errors.Is(err, errPersonMustDecide) {
				t.Fatalf("test_only error = %v, want the secret kept for a person", err)
			}
			if _, err := validateFalsePositiveEvidence(project, tc.finding, nil); !errors.Is(err, errPersonMustDecide) {
				t.Fatalf("no-evidence error = %v, want the secret kept for a person", err)
			}
		})
	}
	critical := EnrichedFinding{ID: "PY-EVAL", Type: "core", Source: "aitriage", Severity: "CRITICAL", File: "tests/test_eval.py", Line: 3}
	if _, err := validateFalsePositiveEvidence(project, critical, testOnly("tests/test_eval.py", 3)); err != nil {
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

// mitigationCase is a line cited as the code_mitigation of a finding.
type mitigationCase struct {
	name       string
	file       string
	severity   string // defaults to HIGH
	flagged    int
	evidLine   int
	observed   string
	wantReject string // a substring of the rejection; empty when accepted
}

func checkMitigationCases(t *testing.T, project string, cases []mitigationCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := tc.severity
			if severity == "" {
				severity = "HIGH"
			}
			finding := EnrichedFinding{ID: "R", VulnID: "CS-MISC-001", Type: "core", Severity: severity, File: tc.file, Line: tc.flagged}
			_, err := validateFalsePositiveEvidence(project, finding, &DispositionEvidence{Basis: "code_mitigation", File: tc.file, Line: tc.evidLine, Observed: tc.observed})
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

// dataFlowFixture holds flagged statements next to checks that share only
// a module, a package, a receiver, a member or a function name with them,
// and next to real mitigations of their data.
func dataFlowFixture(t *testing.T) string {
	t.Helper()
	return writeProjectFiles(t, map[string]string{
		"store.py": strings.Join([]string{
			"import os",                          // 1
			"import shlex",                       // 2
			"import subprocess",                  // 3
			"",                                   // 4
			`BASE = "/srv/files"`,                // 5
			`CONFIG = "/etc/files.conf"`,         // 6
			"",                                   // 7
			"",                                   // 8
			"def read_file(name):",               // 9
			"    if not os.path.isfile(CONFIG):", // 10 checks another value
			"        abort(500)",                 // 11
			"    return open(os.path.join(BASE, name)).read()", // 12 flagged
			"",                                     // 13
			"",                                     // 14
			"def read_named(path):",                // 15
			"    if not os.path.isdir(BASE):",      // 16 os.path is not the variable path
			"        abort(500)",                   // 17
			"    return open(path).read()",         // 18 flagged
			"",                                     // 19
			"",                                     // 20
			"def read_configured(path):",           // 21
			"    if not settings.path:",            // 22 a member named like the variable
			"        abort(500)",                   // 23
			"    return open(path).read()",         // 24 flagged
			"",                                     // 25
			"",                                     // 26
			"def page(template_name):",             // 27
			"    if not render(FALLBACK):",         // 28 only the called function is shared
			"        abort(500)",                   // 29
			"    return render(template_name)",     // 30 flagged
			"",                                     // 31
			"",                                     // 32
			"def dispatch(handler):",               // 33
			"    if not handler():",                // 34 calls the handler, does not check it
			"        abort(500)",                   // 35
			"    return run_later(handler)",        // 36 flagged
			"",                                     // 37
			"",                                     // 38
			"def read_checked(path):",              // 39
			"    if not is_safe(path):",            // 40
			"        raise ValueError(path)",       // 41
			"    return open(path).read()",         // 42 flagged
			"",                                     // 43
			"",                                     // 44
			"def read_stripped(path):",             // 45
			"    if not is_safe(path):",            // 46
			"        raise ValueError(path)",       // 47
			"    return open(path.strip()).read()", // 48 flagged: path is the receiver here
			"",                                     // 49
			"",                                     // 50
			"def run(cmd):",                        // 51
			"    cmd = shlex.quote(cmd)",           // 52
			"    return subprocess.call(cmd, shell=True)", // 53 flagged
			"",                  // 54
			"",                  // 55
			"def export(self):", // 56
			"    self.filename = secure_name(self.filename)",          // 57
			"    return send_file(os.path.join(BASE, self.filename))", // 58 flagged
			"",                                     // 59
			"",                                     // 60
			"def export_local(self, filename):",    // 61
			"    filename = secure_name(filename)", // 62 the local, not the attribute
			"    return send_file(os.path.join(BASE, self.filename))", // 63 flagged
		}, "\n"),
		"files.go": strings.Join([]string{
			"package files", // 1
			"",              // 2
			"func readFile(name string) ([]byte, error) {",       // 3
			"\tif _, err := os.Stat(configPath); err != nil {",   // 4 checks another value
			"\t\treturn nil, err",                                // 5
			"\t}",                                                // 6
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 7 flagged
			"}", // 8
			"",  // 9
			"func readChecked(name string) ([]byte, error) {", // 10
			"\tif !safeName(name) {",                          // 11
			"\t\treturn nil, errUnsafe",                       // 12
			"\t}",                                             // 13
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 14 flagged
			"}", // 15
			"",  // 16
			"func readCleaned(name string) ([]byte, error) {",    // 17
			"\tname = filepath.Base(name)",                       // 18
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 19 flagged
			"}", // 20
		}, "\n"),
		"files.js": strings.Join([]string{
			`const fs = require("fs");`,     // 1
			`const path = require("path");`, // 2
			"",                              // 3
			"function readFile(name) {",     // 4
			"  if (!fs.existsSync(CONFIG)) return null;",       // 5 checks another value
			"  return fs.readFileSync(path.join(BASE, name));", // 6 flagged
			"}",                                     // 7
			"",                                      // 8
			"function readChecked(name) {",          // 9
			"  if (!isSafeName(name)) return null;", // 10
			"  return fs.readFileSync(path.join(BASE, name));", // 11 flagged
			"}",                          // 12
			"",                           // 13
			"function greet(req, res) {", // 14
			"  if (!req.user) return res.sendStatus(401);", // 15 another member of the request
			`  res.send("Hello " + req.query.name);`,       // 16 flagged
			"}",                                            // 17
			"",                                             // 18
			"function greetChecked(req, res) {",            // 19
			"  if (!isPlainName(req.query.name)) return res.sendStatus(400);", // 20
			`  res.send("Hello " + req.query.name);`,                          // 21 flagged
			"}",                                                               // 22
			"",                                                                // 23
			"function show(el, html) {",                                       // 24
			"  html = DOMPurify.sanitize(html);",                              // 25
			"  el.innerHTML = html;",                                          // 26 flagged
			"}",                                                               // 27
		}, "\n"),
		"Store.java": strings.Join([]string{
			"class Store {", // 1
			"  byte[] read(String name) throws Exception {",         // 2
			"    if (!Files.exists(CONFIG)) { return null; }",       // 3 checks another value
			"    return Files.readAllBytes(Paths.get(BASE, name));", // 4 flagged
			"  }", // 5
			"  byte[] readChecked(String name) throws Exception {",  // 6
			"    if (!isSafeName(name)) { return null; }",           // 7
			"    return Files.readAllBytes(Paths.get(BASE, name));", // 8 flagged
			"  }", // 9
			"  void run(String cmd) throws Exception {", // 10
			"    if (config.cmd == null) { return; }",   // 11 a member named like the variable
			"    Runtime.getRuntime().exec(cmd);",       // 12 flagged
			"  }",                                       // 13
			"}",                                         // 14
		}, "\n"),
		"runner.php": strings.Join([]string{
			"<?php",                                  // 1
			"class Runner {",                         // 2
			"  function run($cmd) {",                 // 3
			"    $cmd = escapeshellarg($this->cmd);", // 4 escapes the member, not the argument
			"    system($cmd);",                      // 5 flagged
			"  }",                                    // 6
			"  function runEscaped($cmd) {",          // 7
			"    $cmd = escapeshellarg($cmd);",       // 8
			"    system($cmd);",                      // 9 flagged
			"  }",                                    // 10
			"}",                                      // 11
		}, "\n"),
	})
}

// A shared name ties a cited line to the flagged statement only when it is
// a variable of the statement's data flow. A module or package that only
// qualifies a member (os in os.path.join), a member of something else
// (os.path, settings.path, req.user) and a called function's name are not:
// `if not os.path.isfile(CONFIG): abort(500)` checks another value than
// `open(os.path.join(BASE, name))` reads, although both name os and path.
// A variable that is checked as an argument, assigned, or read as a whole
// access path still ties, also where the flagged statement only calls a
// method of it.
func TestSharedNameMustBeAVariableOfTheFlaggedStatement(t *testing.T) {
	project := dataFlowFixture(t)
	const unshared = "shares no identifier"
	checkMitigationCases(t, project, []mitigationCase{
		{name: "py module and package shared with the flagged call", file: "store.py", flagged: 12, evidLine: 10, observed: "if not os.path.isfile(CONFIG):", wantReject: unshared},
		{name: "py module member named like the flagged variable", file: "store.py", flagged: 18, evidLine: 16, observed: "if not os.path.isdir(BASE):", wantReject: unshared},
		{name: "py member of another object named like the flagged variable", file: "store.py", flagged: 24, evidLine: 22, observed: "if not settings.path:", wantReject: unshared},
		{name: "py called function shared with the flagged statement", file: "store.py", flagged: 30, evidLine: 28, observed: "if not render(FALLBACK):", wantReject: unshared},
		{name: "py check that calls the flagged variable", file: "store.py", flagged: 36, evidLine: 34, observed: "if not handler():", wantReject: "a condition that does not check handler"},
		{name: "py local named like the flagged attribute", file: "store.py", flagged: 63, evidLine: 62, observed: "filename = secure_name(filename)", wantReject: unshared},
		{name: "go package shared with the flagged call", file: "files.go", flagged: 7, evidLine: 4, observed: "os.Stat(configPath)", wantReject: unshared},
		{name: "js module shared with the flagged call", file: "files.js", flagged: 6, evidLine: 5, observed: "fs.existsSync(CONFIG)", wantReject: unshared},
		{name: "js another member of the same object", file: "files.js", flagged: 16, evidLine: 15, observed: "req.user", wantReject: unshared},
		{name: "text: class shared with the flagged call", file: "Store.java", severity: "MEDIUM", flagged: 4, evidLine: 3, observed: "Files.exists(CONFIG)", wantReject: unshared},
		{name: "text: member named like the flagged variable", file: "Store.java", severity: "MEDIUM", flagged: 12, evidLine: 11, observed: "config.cmd == null", wantReject: unshared},
		{name: "text: re-assignment from a member named like the variable", file: "runner.php", severity: "MEDIUM", flagged: 5, evidLine: 4, observed: "$cmd = escapeshellarg($this->cmd)", wantReject: "neither a guard nor a re-assignment"},

		{name: "py guard of an argument", file: "store.py", flagged: 42, evidLine: 40, observed: "if not is_safe(path):"},
		{name: "py guard of a variable the flagged statement calls a method of", file: "store.py", flagged: 48, evidLine: 46, observed: "is_safe(path)"},
		{name: "py re-assignment through a call", file: "store.py", flagged: 53, evidLine: 52, observed: "cmd = shlex.quote(cmd)"},
		{name: "py re-assignment of an attribute of self", file: "store.py", flagged: 58, evidLine: 57, observed: "self.filename = secure_name(self.filename)"},
		{name: "go guard of an argument", file: "files.go", flagged: 14, evidLine: 11, observed: "safeName(name)"},
		{name: "go re-assignment through a call", file: "files.go", flagged: 19, evidLine: 18, observed: "name = filepath.Base(name)"},
		{name: "js guard of an argument", file: "files.js", flagged: 11, evidLine: 10, observed: "isSafeName(name)"},
		{name: "js guard of the same access path", file: "files.js", flagged: 21, evidLine: 20, observed: "isPlainName(req.query.name)"},
		{name: "js re-assignment through a call", file: "files.js", flagged: 26, evidLine: 25, observed: "html = DOMPurify.sanitize(html)"},
		{name: "text: guard of an argument", file: "Store.java", severity: "MEDIUM", flagged: 8, evidLine: 7, observed: "isSafeName(name)"},
		{name: "text: re-assignment through a call", file: "runner.php", severity: "MEDIUM", flagged: 9, evidLine: 8, observed: "$cmd = escapeshellarg($cmd)"},
	})
}

// dominanceFixture holds flagged statements after checks that run on every
// path to them, and after checks that run only on some: in a branch the
// flagged statement is outside of, in an elif or else-if whose earlier
// branch falls through, in a loop body or in one case of a switch.
func dominanceFixture(t *testing.T) string {
	t.Helper()
	return writeProjectFiles(t, map[string]string{
		"branches.py": strings.Join([]string{
			"import os",                          // 1
			"import shlex",                       // 2
			"import subprocess",                  // 3
			"",                                   // 4
			`BASE = "/srv/files"`,                // 5
			"",                                   // 6
			"def download(name, legacy):",        // 7
			"    if legacy:",                     // 8
			"        if not safe_name(name):",    // 9 a sibling branch
			"            raise ValueError(name)", // 10
			"    return open(os.path.join(BASE, name)).read()", // 11 flagged
			"",                               // 12
			"",                               // 13
			"def download_checked(name):",    // 14
			"    if not safe_name(name):",    // 15
			"        raise ValueError(name)", // 16
			`    if name.endswith(".txt"):`,  // 17
			"        return open(os.path.join(BASE, name)).read()", // 18 flagged, in a block inside the guard's
			"    return None",              // 19
			"",                             // 20
			"",                             // 21
			"def download_enclosed(name):", // 22
			"    if safe_name(name):",      // 23
			"        return open(os.path.join(BASE, name)).read()", // 24 flagged, inside the check
			"    return None",                // 25
			"",                               // 26
			"",                               // 27
			"def download_elif(name, mode):", // 28
			`    if mode == "raw":`,          // 29
			"        log(mode)",              // 30
			"    elif not safe_name(name):",  // 31 runs only when mode is not raw
			"        raise ValueError(name)", // 32
			"    return open(os.path.join(BASE, name)).read()", // 33 flagged
			"",                               // 34
			"",                               // 35
			"def download_elif_exits(name):", // 36
			"    if not name:",               // 37
			"        raise ValueError(name)", // 38
			"    elif not safe_name(name):",  // 39 every earlier branch exits
			"        raise ValueError(name)", // 40
			"    return open(os.path.join(BASE, name)).read()", // 41 flagged
			"",                                // 42
			"",                                // 43
			"def download_last(names):",       // 44
			"    name = names[0]",             // 45
			"    for name in names:",          // 46
			"        if not safe_name(name):", // 47 inside a loop the flagged line follows
			"            break",               // 48
			"    return open(os.path.join(BASE, name)).read()", // 49 flagged
			"",                               // 50
			"",                               // 51
			"def run(cmd, quoted):",          // 52
			"    if quoted:",                 // 53
			"        cmd = shlex.quote(cmd)", // 54 a re-assignment in a branch
			"    return subprocess.call(cmd, shell=True)", // 55 flagged
			"",                             // 56
			"",                             // 57
			"def read(path, strict):",      // 58
			"    if strict:",               // 59
			"        assert is_safe(path)", // 60 an assertion in a branch
			"    return open(path).read()", // 61 flagged
		}, "\n"),
		"branches.go": strings.Join([]string{
			"package files", // 1
			"",              // 2
			"func download(name string, legacy bool) ([]byte, error) {", // 3
			"\tif legacy {",               // 4
			"\t\tif !safeName(name) {",    // 5 a sibling branch
			"\t\t\treturn nil, errUnsafe", // 6
			"\t\t}",                       // 7
			"\t}",                         // 8
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 9 flagged
			"}", // 10
			"",  // 11
			"func downloadChecked(name string) ([]byte, error) {",  // 12
			"\tif !safeName(name) {",                               // 13
			"\t\treturn nil, errUnsafe",                            // 14
			"\t}",                                                  // 15
			"\tif strings.HasSuffix(name, \".txt\") {",             // 16
			"\t\treturn os.ReadFile(filepath.Join(baseDir, name))", // 17 flagged
			"\t}",               // 18
			"\treturn nil, nil", // 19
			"}",                 // 20
			"",                  // 21
			"func downloadElse(name string, raw bool) ([]byte, error) {", // 22
			"\tif raw {",                    // 23
			"\t\tlog.Print(name)",           // 24
			"\t} else if !safeName(name) {", // 25 runs only when raw is false
			"\t\treturn nil, errUnsafe",     // 26
			"\t}",                           // 27
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 28 flagged
			"}", // 29
			"",  // 30
			"func downloadSwitch(name string, kind int) ([]byte, error) {", // 31
			"\tswitch kind {",             // 32
			"\tcase 1:",                   // 33
			"\t\tif !safeName(name) {",    // 34 one case of a switch
			"\t\t\treturn nil, errUnsafe", // 35
			"\t\t}",                       // 36
			"\t}",                         // 37
			"\treturn os.ReadFile(filepath.Join(baseDir, name))", // 38 flagged
			"}", // 39
		}, "\n"),
		"branches.js": strings.Join([]string{
			"function download(name, legacy) {",       // 1
			"  if (legacy) {",                         // 2
			"    if (!isSafeName(name)) return null;", // 3 a sibling branch
			"  }", // 4
			"  return fs.readFileSync(path.join(BASE, name));", // 5 flagged
			"}", // 6
			"",  // 7
			"function downloadBraceless(name, legacy) {",        // 8
			"  if (legacy) if (!isSafeName(name)) return null;", // 9 the body of another if, without braces
			"  return fs.readFileSync(path.join(BASE, name));",  // 10 flagged
			"}",                                     // 11
			"",                                      // 12
			"function downloadChecked(name) {",      // 13
			"  if (!isSafeName(name)) return null;", // 14
			`  if (name.endsWith(".txt")) {`,        // 15
			"    return fs.readFileSync(path.join(BASE, name));", // 16 flagged
			"  }",                               // 17
			"  return null;",                    // 18
			"}",                                 // 19
			"",                                  // 20
			"function downloadEnclosed(name) {", // 21
			"  if (isSafeName(name)) {",         // 22
			"    return fs.readFileSync(path.join(BASE, name));", // 23 flagged
			"  }",                                // 24
			"  return null;",                     // 25
			"}",                                  // 26
			"",                                   // 27
			"function downloadElse(name, raw) {", // 28
			"  if (raw) {",                       // 29
			"    console.log(name);",             // 30
			"  } else if (!isSafeName(name)) {",  // 31 runs only when raw is false
			"    return null;",                   // 32
			"  }",                                // 33
			"  return fs.readFileSync(path.join(BASE, name));", // 34 flagged
			"}",                                  // 35
			"",                                   // 36
			"function downloadElseExits(name) {", // 37
			"  if (!name) {",                     // 38
			"    return null;",                   // 39
			"  } else if (!isSafeName(name)) {",  // 40 every earlier branch exits
			"    return null;",                   // 41
			"  }",                                // 42
			"  return fs.readFileSync(path.join(BASE, name));", // 43 flagged
			"}",                                   // 44
			"",                                    // 45
			"function downloadCase(name, kind) {", // 46
			"  switch (kind) {",                   // 47
			`    case "file":`,                    // 48
			"      if (!isSafeName(name)) return null;", // 49 one case of a switch
			"      break;", // 50
			"  }",          // 51
			"  return fs.readFileSync(path.join(BASE, name));", // 52 flagged
			"}", // 53
		}, "\n"),
	})
}

// A mitigation that does not enclose the flagged statement must run on
// every path to it: its statement lies in the flagged statement's block or
// in a block around it. A check in a branch the flagged statement is
// outside of, in an elif or else-if whose earlier branch falls through, in
// a loop body the flagged statement follows, or in one case of a switch
// leaves the other paths unprotected.
func TestMitigationMustRunOnEveryPathToTheFlaggedLine(t *testing.T) {
	project := dominanceFixture(t)
	const someWays = "not on every path"
	checkMitigationCases(t, project, []mitigationCase{
		{name: "py guard in a sibling branch", file: "branches.py", flagged: 11, evidLine: 9, observed: "safe_name(name)", wantReject: someWays},
		{name: "py early exit of a guard in a sibling branch", file: "branches.py", flagged: 11, evidLine: 10, observed: "ValueError(name)", wantReject: someWays},
		{name: "py elif after a branch that falls through", file: "branches.py", flagged: 33, evidLine: 31, observed: "safe_name(name)", wantReject: someWays},
		{name: "py guard in a loop the flagged line follows", file: "branches.py", flagged: 49, evidLine: 47, observed: "safe_name(name)", wantReject: someWays},
		{name: "py re-assignment in a branch", file: "branches.py", flagged: 55, evidLine: 54, observed: "cmd = shlex.quote(cmd)", wantReject: someWays},
		{name: "py assertion in a branch", file: "branches.py", flagged: 61, evidLine: 60, observed: "is_safe(path)", wantReject: someWays},
		{name: "go guard in a sibling branch", file: "branches.go", flagged: 9, evidLine: 5, observed: "safeName(name)", wantReject: someWays},
		{name: "go else-if after a branch that falls through", file: "branches.go", flagged: 28, evidLine: 25, observed: "safeName(name)", wantReject: someWays},
		{name: "go guard in one case of a switch", file: "branches.go", flagged: 38, evidLine: 34, observed: "safeName(name)", wantReject: someWays},
		{name: "js guard in a sibling branch", file: "branches.js", flagged: 5, evidLine: 3, observed: "isSafeName(name)", wantReject: someWays},
		{name: "js guard as the body of an if without braces", file: "branches.js", flagged: 10, evidLine: 9, observed: "isSafeName(name)", wantReject: someWays},
		{name: "js else-if after a branch that falls through", file: "branches.js", flagged: 34, evidLine: 31, observed: "isSafeName(name)", wantReject: someWays},
		{name: "js guard in one case of a switch", file: "branches.js", flagged: 52, evidLine: 49, observed: "isSafeName(name)", wantReject: someWays},

		{name: "py guard in a block around the flagged line", file: "branches.py", flagged: 18, evidLine: 15, observed: "safe_name(name)"},
		{name: "py guard enclosing the flagged line", file: "branches.py", flagged: 24, evidLine: 23, observed: "safe_name(name)"},
		{name: "py elif after a branch that exits", file: "branches.py", flagged: 41, evidLine: 39, observed: "safe_name(name)"},
		{name: "go guard in a block around the flagged line", file: "branches.go", flagged: 17, evidLine: 13, observed: "safeName(name)"},
		{name: "js guard in a block around the flagged line", file: "branches.js", flagged: 16, evidLine: 14, observed: "isSafeName(name)"},
		{name: "js guard enclosing the flagged line", file: "branches.js", flagged: 23, evidLine: 22, observed: "isSafeName(name)"},
		{name: "js else-if after a branch that exits", file: "branches.js", flagged: 43, evidLine: 40, observed: "isSafeName(name)"},
	})
}

// What each name of a line of code does, in order: "key:role", or "-" for a
// member that names nothing comparable. Spread, variadic and type-assertion
// dots are not member access.
func TestNameAtClassifiesWhatANameDoes(t *testing.T) {
	roles := map[nameRole]string{nameData: "data", nameQualifier: "qualifier", nameCallee: "callee"}
	cases := map[string][]string{
		"open(os.path.join(BASE, name))":     {"open:callee", "os:qualifier", "-", "-", "BASE:data", "name:data"},
		"check(user.is_admin)":               {"check:callee", "user:qualifier", "user.is_admin:data"},
		"$cmd = escapeshellarg($this->cmd);": {"cmd:data", "escapeshellarg:callee", "this:qualifier", "this.cmd:data"},
		"Shell::quote(arg)":                  {"Shell:qualifier", "-", "arg:data"},
		"run(...args)":                       {"run:callee", "args:data"},
		"exec.Command(name, args...)":        {"exec:qualifier", "-", "name:data", "args:data"},
		"s := v.(string)":                    {"s:data", "v:data", "string:data"},
		"a?.b":                               {"a:qualifier", "a.b:data"},
		"get().name":                         {"get:callee", "-"},
		"items[0].name":                      {"items:data", "-"},
		"self . filename":                    {"self:qualifier", "self.filename:data"},
	}
	for code, want := range cases {
		var got []string
		for _, span := range identifierSpans(code) {
			key, role, ok := nameAt(code, span)
			if !ok {
				got = append(got, "-")
				continue
			}
			got = append(got, key+":"+roles[role])
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("nameAt over %q = %v, want %v", code, got, want)
		}
	}
}
