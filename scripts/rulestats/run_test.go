package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes a synthetic artifact, creating its directories.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// assertPrivate fails when a report shows anything of the scanned code: the
// fixtures put these markers into paths, ids, reasons and directory names.
func assertPrivate(t *testing.T, report string) {
	t.Helper()
	for _, marker := range []string{"canary", "/home", ".py", ".rb", "CS-", "fp-", "stable-", "svc-", "lstat", "raw_response"} {
		if strings.Contains(report, marker) {
			t.Errorf("report leaks %q:\n%s", marker, report)
		}
	}
}

func TestRulesReportUnchanged(t *testing.T) {
	for _, c := range []struct {
		format string
		min    int
		want   string
	}{
		{"md", 1, "Runs: 2\n\n" +
			"| rule | source | findings | runs | TP | FP | NR | nr-fallback | triage-failed | merged | precision |\n" +
			"|---|---|---|---|---|---|---|---|---|---|---|\n" +
			"| RULE-A | aitriage | 3 | 2 | 1 | 2 | 0 | 0 | 0 | 1 | 33% |\n" +
			"| B101 | bandit | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0% |\n" +
			"| RULE-B | semgrep | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | - |\n" +
			"| RULE-C | aitriage | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | - |\n"},
		{"tsv", 5, "rule\tsource\tfindings\truns\tTP\tFP\tNR\tnr-fallback\ttriage-failed\tmerged\tprecision\n" +
			"RULE-A\taitriage\t3\t2\t1\t2\t0\t0\t0\t1\t33%\n" +
			"B101\tbandit\t1\t1\t0\t1\t0\t0\t0\t1\t0%\n" +
			"RULE-B\tsemgrep\t1\t1\t0\t0\t1\t1\t0\t0\t-\n" +
			"RULE-C\taitriage\t1\t1\t0\t0\t1\t0\t1\t0\t-\n"},
	} {
		var out bytes.Buffer
		if err := run(&out, options{format: c.format, min: c.min}, []string{"testdata"}); err != nil {
			t.Fatal(err)
		}
		if out.String() != c.want {
			t.Errorf("%s report changed:\n%s\nwant:\n%s", c.format, out.String(), c.want)
		}
	}
}

func TestRunRejectsArgumentsThatFitNoReport(t *testing.T) {
	for _, c := range []struct {
		name string
		o    options
		args []string
	}{
		{"no input", options{format: "md"}, nil},
		{"reasons without input", options{format: "md", reasons: true}, nil},
		{"compare with one set", options{format: "md", compare: true}, []string{"testdata"}},
		{"compare with three sets", options{format: "md", compare: true}, []string{"a", "b", "c"}},
		{"both reports at once", options{format: "md", reasons: true, compare: true}, []string{"a", "b"}},
	} {
		if err := run(io.Discard, c.o, c.args); !errors.Is(err, errUsage) {
			t.Errorf("%s: err = %v, want a usage error", c.name, err)
		}
	}
}

func TestNewReportsRejectUnknownFormatAndNewerSchema(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "old", "triage-findings.json")
	newer := filepath.Join(dir, "new", "triage-findings.json")
	writeFile(t, current, `{"schema_version": 1, "findings": []}`)
	writeFile(t, newer, `{"schema_version": 2, "findings": []}`)

	if err := run(io.Discard, options{format: "xml", reasons: true}, []string{current}); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("-reasons -format xml: err = %v", err)
	}
	if err := run(io.Discard, options{format: "xml", compare: true}, []string{current, current}); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("-compare -format xml: err = %v", err)
	}
	for _, o := range []options{{format: "md", reasons: true}, {format: "md", compare: true}} {
		args := []string{newer}
		if o.compare {
			args = []string{current, newer}
		}
		err := run(io.Discard, o, args)
		if err == nil || !strings.Contains(err.Error(), "schema_version 2") {
			t.Errorf("%+v: err = %v, want the newer schema refused", o, err)
		}
		if err != nil && strings.Contains(err.Error(), dir) {
			t.Errorf("error names the path: %v", err)
		}
	}
}

// artifactJSON renders a synthetic triage-findings.json.
func artifactJSON(t *testing.T, findings ...map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"schema_version": 1, "findings": findings})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// finding renders one triaged finding reported by the given rules. An empty
// stableID or vulnID leaves the field out, as older artifacts do.
func finding(stableID, vulnID, disposition, source string, rules ...string) map[string]any {
	var origins []map[string]string
	for _, rule := range rules {
		origins = append(origins, map[string]string{"rule_id": rule, "source": "synthetic", "file": "src/canary_module.py"})
	}
	f := map[string]any{"id": rules[0], "source": "synthetic", "file": "src/canary_module.py", "line": 7, "origins": origins}
	if stableID != "" {
		f["stable_id"] = stableID
	}
	if vulnID != "" {
		f["vuln_id"] = vulnID
	}
	return map[string]any{
		"finding":     f,
		"disposition": map[string]string{"disposition": disposition, "disposition_source": source, "rationale": "canary rationale"},
	}
}
