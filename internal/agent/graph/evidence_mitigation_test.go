package graph

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
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

// E1: code_mitigation evidence must point at code that is not the flagged
// statement itself, outside comments and string literals, in a code file.
func TestCodeMitigationEvidenceValidation(t *testing.T) {
	project := writeProjectFiles(t, map[string]string{
		"app.py": strings.Join([]string{
			"import subprocess",
			"def run(cmd):",
			"    subprocess.call(cmd, shell=True)",
			"# Local smoke test only - NOT for production.",
			"x = escape(y)  # sanitize",
			`query = "SELECT * FROM t WHERE id = %s"`,
			`"""Docstring: input is validated upstream."""`,
			"if not user.is_admin: abort(403)",
			"import shlex",
		}, "\n"),
		"web/app.ts": strings.Join([]string{
			"const html = req.query.name;",
			"// sanitized by middleware",
			"el.textContent = DOMPurify.sanitize(html); // safe",
			"/* legacy:",
			" * escapeHtml(html) used here",
			" */",
		}, "\n"),
		"main.go": strings.Join([]string{
			"package main",
			"// validate(input) is called by the router",
			"func handle(input string) {",
			"\tif !validate(input) { return }",
			"\texec.Command(\"sh\", \"-c\", input).Run()",
			"}",
		}, "\n"),
		"db/schema.sql": strings.Join([]string{
			"-- only admins can call this",
			"GRANT SELECT ON t TO app_reader;",
			"SELECT * FROM t WHERE name = 'x' || @input;",
		}, "\n"),
		"site/index.html": strings.Join([]string{
			"<!-- escaped by the template engine -->",
			"<div>{{ user_input | escape }}</div>",
		}, "\n"),
		"plugin/run.php": "<?php\neval($_GET['code']);\n",
		"docker-compose.yml": strings.Join([]string{
			"# Local smoke test only - NOT for production.",
			"services:",
			"  db:",
			"    environment:",
			"      POSTGRES_PASSWORD: example",
		}, "\n"),
		"config/settings.yaml": "debug: false\nallowed_hosts: [example.com]\n",
	})

	cases := []struct {
		name       string
		file       string
		severity   string
		findLine   int
		evidLine   int
		observed   string
		wantReject string // substring of the rejection; empty means accepted
	}{
		// The flagged line is never its own mitigation.
		{"php eval citing itself (HIGH)", "plugin/run.php", "HIGH", 2, 2, "eval($_GET['code'])", "flagged line itself"},
		{"php eval citing itself (MEDIUM)", "plugin/run.php", "MEDIUM", 2, 2, "eval($_GET['code']);", "flagged statement itself"},
		{"py shell call citing itself", "app.py", "LOW", 3, 3, "subprocess.call(cmd, shell=True)", "flagged statement itself"},
		{"go exec citing its own line (CRITICAL)", "main.go", "CRITICAL", 5, 5, `exec.Command("sh", "-c", input)`, "flagged line itself"},
		// Comments, docstrings and string literals are not code.
		{"py comment", "app.py", "HIGH", 3, 4, "Local smoke test only - NOT for production.", "inside a comment"},
		{"py trailing comment text", "app.py", "HIGH", 3, 5, "# sanitize", "inside a comment"},
		{"py string literal", "app.py", "MEDIUM", 3, 6, "SELECT * FROM t WHERE id = %s", "inside a string literal"},
		{"py docstring", "app.py", "MEDIUM", 3, 7, "input is validated upstream", "inside a string literal"},
		{"ts line comment", "web/app.ts", "HIGH", 1, 2, "sanitized by middleware", "inside a comment"},
		{"ts block comment continuation", "web/app.ts", "HIGH", 1, 5, "escapeHtml(html)", "inside a comment"},
		{"go comment", "main.go", "CRITICAL", 5, 2, "validate(input)", "inside a comment"},
		{"sql comment", "db/schema.sql", "MEDIUM", 3, 1, "only admins can call this", "inside a comment"},
		{"html comment", "site/index.html", "MEDIUM", 2, 1, "escaped by the template engine", "inside a comment"},
		// Prose without code tokens is not a mitigation.
		{"py import statement", "app.py", "LOW", 3, 9, "import shlex", "no code tokens"},
		// Configuration and data files contain no code that mitigates.
		{"compose comment", "docker-compose.yml", "MEDIUM", 5, 1, "# Local smoke test only - NOT for production.", "configuration or data file"},
		{"yaml setting", "config/settings.yaml", "LOW", 1, 2, "allowed_hosts: [example.com]", "configuration or data file"},
		// Real mitigations are accepted, also on a line with a trailing comment.
		{"py call with trailing comment", "app.py", "HIGH", 3, 5, "escape(y)", ""},
		{"py authorization check", "app.py", "HIGH", 3, 8, "user.is_admin", ""},
		{"ts sanitizer call", "web/app.ts", "HIGH", 1, 3, "DOMPurify.sanitize(html)", ""},
		{"go validation check", "main.go", "CRITICAL", 5, 4, "validate(input)", ""},
		{"sql grant", "db/schema.sql", "MEDIUM", 3, 2, "GRANT SELECT ON t TO app_reader", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding := EnrichedFinding{ID: "R", VulnID: "CS-MISC-001", Severity: tc.severity, File: tc.file, Line: tc.findLine}
			evidence := &DispositionEvidence{Basis: "code_mitigation", File: tc.file, Line: tc.evidLine, Observed: tc.observed}
			err := validateFalsePositiveEvidence(project, finding, evidence)
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

// E1, end to end: the classifier turns a self-citing False Positive into
// Needs Manual Review and records why in the classification audit.
func TestClassifyFindingsRejectsSelfCitingEvalFalsePositive(t *testing.T) {
	pinConcurrency(t)
	project := writeProjectFiles(t, map[string]string{"plugin/run.php": "<?php\neval($_GET['code']);\n"})
	findings := []EnrichedFinding{{ID: "PHP-EVAL", VulnID: "CS-EXEC-001", Type: "core", Severity: "HIGH", File: "plugin/run.php", Line: 2, Message: "eval of request input"}}
	mock := &fakeLLM{t: t, classifyHandler: func(int, []EnrichedFinding) (string, error) {
		return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"path is excluded in .aitriage.yaml","evidence":{"basis":"code_mitigation","file":"plugin/run.php","line":2,"observed":"eval($_GET['code']);"}}]}`, nil
	}}
	var usage llm.Usage

	_, disps, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 40)
	if err != nil {
		t.Fatal(err)
	}
	if disps[0].Disposition != "Needs Manual Review" {
		t.Fatalf("disposition = %+v, want the self-citing False Positive rejected", disps[0])
	}
	found := false
	for _, entry := range audit {
		for _, rejection := range entry.Rejected {
			if strings.Contains(rejection.Reason, "flagged line itself") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("audit = %+v, want the rejection reason recorded", audit)
	}
}

// E3: with fp_critical_requires_high_confidence, a CRITICAL finding is only
// dismissed with high confidence; anything less stays for manual review.
func TestFPCriticalRequiresHighConfidencePolicy(t *testing.T) {
	project := writeProjectFiles(t, map[string]string{"auth.py": "def handler(request):\n    verify_token(request)\n    return load(request)\n"})
	run := func(t *testing.T, severity, confidence string, policyOn bool) (FindingDisposition, []ClassificationAuditEntry) {
		t.Helper()
		pinConcurrency(t)
		findings := []EnrichedFinding{{ID: "R-1", VulnID: "CS-AUTH-001", Type: "core", Severity: severity, File: "auth.py", Line: 3, Message: "missing auth"}}
		mock := &fakeLLM{t: t, classifyHandler: func(int, []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":` + strconv.Quote(confidence) + `,"rationale":"guard exists","evidence":{"basis":"code_mitigation","file":"auth.py","line":2,"observed":"verify_token(request)"}}]}`, nil
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
		finding := EnrichedFinding{ID: "R-1", Severity: "CRITICAL", File: "auth.py", Line: 3}
		cached := FindingDisposition{Disposition: "False Positive", Confidence: "medium", Evidence: &DispositionEvidence{Basis: "code_mitigation", File: "auth.py", Line: 2, Observed: "verify_token(request)"}}
		req := classifyRequest{projectPath: project, policy: validationPolicy{fpCriticalRequiresHighConfidence: true}}
		if cachedVerdictUsable(req, finding, cached) {
			t.Fatal("a cached medium-confidence dismissal of a CRITICAL finding must not be reused under the policy")
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
