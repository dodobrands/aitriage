package external

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Semgrep exits 0 when a rule times out on a file; after repeated timeouts it
// stops analysing that file, and every finding in it is gone from the run. The
// errors list is the only signal, so it must reach the scan record.
func TestParseSemgrepOutputRecordsPartialFiles(t *testing.T) {
	out := `{
	  "results": [
	    {"check_id": "python.flask.security.open-redirect.open-redirect", "path": "/repo/site/views.py",
	     "start": {"line": 12}, "extra": {"message": "open redirect", "severity": "ERROR"}}
	  ],
	  "errors": [
	    {"code": 2, "level": "warn", "type": "Timeout", "rule_id": "python.boto3.security.hardcoded-token.hardcoded-token",
	     "message": "Timeout when running ... on /repo/site/app.py", "path": "/repo/site/app.py"},
	    {"code": 2, "level": "warn", "type": "Timeout", "rule_id": "python.lang.security.audit.formatted-sql-query",
	     "message": "Timeout when running ... on /repo/site/app.py", "path": "/repo/site/app.py"},
	    {"code": 3, "level": "warn", "type": ["PartialParsing", [{"path": "/repo/deploy.sh", "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9}}]],
	     "message": "Syntax error at line /repo/deploy.sh:3", "path": "/repo/deploy.sh"},
	    {"code": 3, "level": "warn", "type": "Syntax error", "message": "Syntax error",
	     "spans": [{"file": "/repo/templates/page.html", "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}}]},
	    {"code": 2, "level": "warn", "type": "Internal matching error", "rule_id": "yaml.github-actions.security.curl-eval.curl-eval",
	     "message": "Internal matching error", "path": "/repo/.github/workflows/publish.yaml"},
	    {"code": 7, "level": "error", "type": "Rule parse error", "message": "Invalid rule schema"}
	  ]
	}`
	scan, err := parseSemgrepOutput(out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 || scan.Findings[0].File != "/repo/site/views.py" {
		t.Fatalf("findings = %+v", scan.Findings)
	}
	want := []PartialFile{
		{File: "/repo/site/app.py", Reason: PartialTimeout, Count: 1},
		{File: "/repo/site/app.py", Reason: PartialTimeout, Count: 1},
		{File: "/repo/deploy.sh", Reason: PartialParseError, Count: 1},
		{File: "/repo/templates/page.html", Reason: PartialParseError, Count: 1},
		{File: "/repo/.github/workflows/publish.yaml", Reason: PartialError, Count: 1},
	}
	if !reflect.DeepEqual(scan.PartialFiles, want) {
		t.Fatalf("partial files =\n%+v\nwant\n%+v", scan.PartialFiles, want)
	}
}

func TestParseSemgrepOutputWithoutErrors(t *testing.T) {
	scan, err := parseSemgrepOutput(`{"results": []}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if scan.PartialFiles != nil {
		t.Fatalf("partial files = %+v, want none", scan.PartialFiles)
	}
}

func TestPartialReason(t *testing.T) {
	for kind, want := range map[string]string{
		"Timeout":                          PartialTimeout,
		"Fixpoint timeout":                 PartialTimeout,
		"PartialParsing":                   PartialParseError,
		"Syntax error":                     PartialParseError,
		"Other syntax error":               PartialParseError,
		"Lexical error":                    PartialParseError,
		"AST builder error":                PartialParseError,
		"Internal matching error":          PartialError,
		"Out of memory":                    PartialError,
		"Stack overflow":                   PartialError,
		"a kind added by a future version": PartialError,
		"":                                 PartialError,
	} {
		if got := partialReason(kind); got != want {
			t.Errorf("partialReason(%q) = %q, want %q", kind, got, want)
		}
	}
}

// Partial files leave the run project-relative and only for the audited
// application: the same scope the findings of the scan are held to.
func TestScopePartialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("build/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	got := ScopePartialFiles(root, []PartialFile{
		{File: abs("site/app.py"), Reason: PartialError, Count: 1},
		{File: abs("site/app.py"), Reason: PartialTimeout, Count: 1},
		{File: abs("site/app.py"), Reason: PartialTimeout, Count: 1},
		{File: abs("deploy.sh"), Reason: PartialParseError, Count: 1},
		{File: "/github/workspace/web/main.js", Reason: PartialTimeout, Count: 1},
		{File: abs("aitriage-reports/summary.md"), Reason: PartialParseError, Count: 1},
		{File: abs("node_modules/lib/index.js"), Reason: PartialTimeout, Count: 1},
		{File: abs("build/out.js"), Reason: PartialTimeout, Count: 1},
		{File: abs("tests/test_app.py"), Reason: PartialTimeout, Count: 1},
		{File: "", Reason: PartialError, Count: 1},
		// Errors about the scanner's own rule files outside the project.
		{File: "/tmp/aitriage-taint-1/rules.yaml", Reason: PartialError, Count: 1},
		{File: filepath.Join(t.TempDir(), "rules.yaml"), Reason: PartialError, Count: 1},
	})
	want := []PartialFile{
		{File: "site/app.py", Reason: PartialTimeout, Count: 2},
		{File: "web/main.js", Reason: PartialTimeout, Count: 1},
		{File: "deploy.sh", Reason: PartialParseError, Count: 1},
		{File: "site/app.py", Reason: PartialError, Count: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScopePartialFiles =\n%+v\nwant\n%+v", got, want)
	}
	if n := PartialFileCount(got); n != 3 {
		t.Errorf("PartialFileCount = %d, want 3", n)
	}
	if s := PartialFilesSummary(got); s != "2 with rule timeouts, 1 with parse errors, 1 with other scanner errors" {
		t.Errorf("PartialFilesSummary = %q", s)
	}
}

func TestScopePartialFilesEmpty(t *testing.T) {
	if got := ScopePartialFiles(t.TempDir(), nil); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
	if s := PartialFilesSummary(nil); s != "" {
		t.Fatalf("summary of nothing = %q", s)
	}
}

// The version comes from the output that carries the results: asking
// "semgrep --version" separately starts Semgrep a second time, which takes
// about five seconds and left the version empty when it ran out of time.
func TestParseSemgrepOutputVersion(t *testing.T) {
	scan, err := parseSemgrepOutput(`{"version": "1.170.1", "results": []}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Version != "1.170.1" {
		t.Fatalf("version = %q, want 1.170.1", scan.Version)
	}
	scan, err = parseSemgrepOutput(`{"results": []}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Version != "" {
		t.Fatalf("version = %q, want empty when Semgrep does not print one", scan.Version)
	}
}
