package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	tp = "True Positive"
	fp = "False Positive"
	nr = "Needs Manual Review"
)

// writeSets writes two sets of synthetic artifacts, one per project
// directory, and returns their roots.
func writeSets(t *testing.T, before, after map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for root, set := range map[string]map[string]string{"old": before, "new": after} {
		for project, content := range set {
			writeFile(t, filepath.Join(dir, root, project, "triage-findings.json"), content)
		}
	}
	return filepath.Join(dir, "old"), filepath.Join(dir, "new")
}

func TestCompareCountsVerdictFlips(t *testing.T) {
	oldRoot, newRoot := writeSets(t,
		map[string]string{
			"svc-a": artifactJSON(t,
				finding("stable-1", "CS-A-111111", tp, "llm", "R1"),
				finding("stable-2", "CS-A-222222", fp, "llm", "R2", "R2X"),
				finding("stable-3", "CS-A-333333", nr, "nr-fallback", "R1"),
				finding("stable-4", "CS-A-444444", tp, "cache", "R3"),
				// Shares its vuln_id with a new finding of another stable_id.
				finding("stable-5", "CS-X-555555", fp, "llm", "R4"),
			),
			// Written before stable_id existed.
			"svc-b": artifactJSON(t,
				finding("", "CS-B-1", tp, "llm", "R5"),
				finding("", "", nr, "llm", "R5"),
			),
			"svc-gone": artifactJSON(t, finding("stable-9", "CS-A-999999", tp, "llm", "R1")),
		},
		map[string]string{
			"svc-a": artifactJSON(t,
				finding("stable-1", "CS-A-111111", nr, "nr-fallback", "R1"),
				// R2X no longer reports it: the change still counts for R2X.
				finding("stable-2", "CS-A-222222", nr, "llm", "R2"),
				finding("stable-3", "CS-A-333333", tp, "llm", "R1"),
				finding("stable-5x", "CS-X-555555", fp, "llm", "R4"),
				finding("stable-6", "CS-A-666666", tp, "llm", "R1"),
			),
			"svc-b":   artifactJSON(t, finding("stable-b1", "CS-B-1", tp, "llm", "R5")),
			"svc-new": artifactJSON(t, finding("stable-7", "CS-A-777777", fp, "llm", "R1")),
		},
	)

	var tsv bytes.Buffer
	if err := run(&tsv, options{format: "tsv", compare: true}, []string{oldRoot, newRoot}); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"rule\tmatched\tflipped\tTP→FP\tTP→NR\tFP→TP\tFP→NR\tNR→TP\tNR→FP\tonly-old\tonly-new",
		"(all)\t4\t3\t0\t1\t0\t1\t1\t0\t2\t2",
		"R1\t2\t2\t0\t1\t0\t0\t1\t0\t0\t1",
		"R2\t1\t1\t0\t0\t0\t1\t0\t0\t0\t0",
		"R2X\t1\t1\t0\t0\t0\t1\t0\t0\t0\t0",
		"R4\t0\t0\t0\t0\t0\t0\t0\t0\t1\t1",
		"R3\t0\t0\t0\t0\t0\t0\t0\t0\t1\t0",
	}, "\n") + "\n"
	if tsv.String() != want {
		t.Errorf("tsv report:\n%s\nwant:\n%s", tsv.String(), want)
	}
	assertPrivate(t, tsv.String())

	var md bytes.Buffer
	if err := run(&md, options{format: "md", compare: true}, []string{oldRoot, newRoot}); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{
		"Artifacts: 2 compared, 1 only in old, 1 only in new (not compared)\n" +
			"Findings in compared artifacts: 7 old, 6 new; 4 matched, 2 only in old, 2 only in new\n" +
			"Findings with neither stable_id nor vuln_id (not matched): 1\n" +
			"Verdicts: TP 3 → 3, FP 2 → 1, NR 2 → 2\n",
		"## Verdicts of matched findings\n\n" +
			"| old | new | findings | disposition_source old → new |\n|---|---|---|---|\n" +
			"| TP | NR | 1 | llm → nr-fallback 1 |\n" +
			"| FP | NR | 1 | llm → llm 1 |\n" +
			"| NR | TP | 1 | nr-fallback → llm 1 |\n" +
			"| TP | TP | 1 | llm → llm 1 |\n",
		"## Per rule\n\n| rule | matched | flipped | TP→FP | TP→NR | FP→TP | FP→NR | NR→TP | NR→FP | only-old | only-new |\n",
		"| (all) | 4 | 3 | 0 | 1 | 0 | 1 | 1 | 0 | 2 | 2 |\n| R1 | 2 | 2 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 1 |\n",
		"Rules without a flipped, removed or added finding (not listed): 1\n",
	} {
		if !strings.Contains(md.String(), part) {
			t.Errorf("md report lacks %q:\n%s", part, md.String())
		}
	}
	assertPrivate(t, md.String())
}

func TestCompareMatchesTwoSingleArtifactsAnywhere(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "download-1", "run-a", "triage-findings.json")
	after := filepath.Join(dir, "download-2", "run-b", "triage-findings.json")
	writeFile(t, before, artifactJSON(t, finding("stable-1", "CS-A-111111", fp, "cache", "R1")))
	writeFile(t, after, artifactJSON(t, finding("stable-1", "CS-A-111111", nr, "llm", "R1")))

	for _, args := range [][]string{
		{filepath.Join(dir, "download-1"), filepath.Join(dir, "download-2")},
		{before, after},
	} {
		var tsv bytes.Buffer
		if err := run(&tsv, options{format: "tsv", compare: true}, args); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(tsv.String(), "(all)\t1\t1\t0\t0\t0\t1\t0\t0\t0\t0\n") {
			t.Errorf("single artifacts not compared:\n%s", tsv.String())
		}
	}
}

func TestCompareNeedsAnArtifactOnEachSide(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "new", "triage-findings.json"), artifactJSON(t))
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ before, want string }{
		{filepath.Join(dir, "empty"), "old set: no triage-findings.json found"},
		{filepath.Join(dir, "absent"), "no such file or directory"},
	} {
		err := run(&bytes.Buffer{}, options{format: "md", compare: true}, []string{c.before, filepath.Join(dir, "new")})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("old set %s: err = %v, want %q", filepath.Base(c.before), err, c.want)
		}
	}
}

func TestMatchFindingsPairsDuplicateIDsInOrder(t *testing.T) {
	parse := func(findings ...map[string]any) []triagedFinding {
		var a artifact
		if err := json.Unmarshal([]byte(artifactJSON(t, findings...)), &a); err != nil {
			t.Fatal(err)
		}
		return a.Findings
	}
	before := parse(finding("", "CS-1", tp, "llm", "R"), finding("", "CS-1", fp, "llm", "R"))
	after := parse(finding("", "CS-1", tp, "llm", "R"), finding("", "CS-1", fp, "llm", "R"), finding("", "CS-1", nr, "llm", "R"))
	pairs, onlyOld, onlyNew, unidentified := matchFindings(before, after)
	if len(pairs) != 2 || pairs[0] != [2]int{0, 0} || pairs[1] != [2]int{1, 1} || len(onlyOld) != 0 || len(onlyNew) != 1 || unidentified != 0 {
		t.Errorf("pairs %v, only old %v, only new %v, unidentified %d", pairs, onlyOld, onlyNew, unidentified)
	}
}
