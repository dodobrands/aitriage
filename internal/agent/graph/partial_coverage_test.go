package graph

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// A scanner that completed but analysed files only partly says so in the
// summary, naming the files where rules timed out: findings there can come and
// go between runs, and a reader must not take that for a fix or a regression.
func TestSummaryReportsPartlyAnalysedFiles(t *testing.T) {
	state := &AgentState{ScannerCoverage: "full"}
	state.ScannerExecutions = []external.ScannerExecution{
		{Scanner: "semgrep", Status: external.StatusCompleted, Findings: 19, PartialFiles: []external.PartialFile{
			{File: "site/app.py", Reason: external.PartialTimeout, Count: 3},
			{File: "deploy.sh", Reason: external.PartialParseError, Count: 1},
			{File: "site/app.py", Reason: external.PartialError, Count: 1},
		}},
		{Scanner: "bandit", Status: external.StatusCompleted, Findings: 4},
	}
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	want := "_`semgrep` analysed 2 file(s) only partly (1 with rule timeouts, 1 with parse errors, 1 with other scanner errors), " +
		"so findings in them may be missing. Rule timeouts depend on machine load, so findings in `site/app.py` can differ between runs. " +
		"The files are listed under `partial_files` in the scanner manifest._"
	if !strings.Contains(state.SummaryMarkdown, want) {
		t.Fatalf("summary does not report the partly analysed files:\n%s", state.SummaryMarkdown)
	}
	if strings.Contains(state.SummaryMarkdown, "`bandit` analysed") {
		t.Fatalf("a scanner without partial files got a note:\n%s", state.SummaryMarkdown)
	}
}

func TestPartialCoverageNotesNameAtMostFiveTimedOutFiles(t *testing.T) {
	var files []external.PartialFile
	for i := range 7 {
		files = append(files, external.PartialFile{File: fmt.Sprintf("big%d.py", i), Reason: external.PartialTimeout, Count: 3})
	}
	notes := partialCoverageNotes([]external.ScannerExecution{{Scanner: "semgrep", Status: external.StatusCompleted, PartialFiles: files}})
	if len(notes) != 1 {
		t.Fatalf("notes = %q", notes)
	}
	if !strings.Contains(notes[0], "findings in `big0.py`, `big1.py`, `big2.py`, `big3.py`, `big4.py` and 2 more file(s) can differ between runs") {
		t.Fatalf("note = %q", notes[0])
	}
	if strings.Contains(notes[0], "big5.py") {
		t.Fatalf("note names more than five files: %q", notes[0])
	}
}

func TestPartialCoverageNotesWithoutPartialFiles(t *testing.T) {
	if notes := partialCoverageNotes([]external.ScannerExecution{{Scanner: "semgrep", Status: external.StatusCompleted}}); notes != nil {
		t.Fatalf("notes = %q, want none", notes)
	}
}
