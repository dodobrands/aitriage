package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormaliseReasonKeepsOnlyTheTemplate(t *testing.T) {
	const rejected = "code_mitigation evidence rejected: "
	const kept = "false positive kept as Needs Manual Review: "
	for _, c := range []struct{ reason, want string }{
		{"out-of-range finding_index", "out-of-range finding_index"},
		{"unsupported disposition", "unsupported disposition"},
		{"duplicate disposition", "duplicate disposition"},
		{"finding_id does not match requested finding", "finding_id does not match requested finding"},
		{"fingerprint does not match requested finding", "fingerprint does not match requested finding"},
		{"false positive has no evidence", "false positive has no evidence"},
		{`false positive evidence basis "canary_basis" is not deterministically verifiable`,
			"false positive evidence basis {basis} is not deterministically verifiable"},
		{"test_only evidence does not reference a test finding", "test_only evidence does not reference a test finding"},
		{"test_only evidence file is missing", "test_only evidence file is missing"},
		{"test_only evidence file is invalid: evidence file does not match finding file",
			"test_only evidence file is invalid: evidence file does not match finding file"},
		{"code_mitigation evidence file is invalid: finding and evidence paths are required",
			"code_mitigation evidence file is invalid: finding and evidence paths are required"},
		{"test_only evidence file is invalid: evidence path: path escapes project root",
			"test_only evidence file is invalid: evidence path escapes project root"},
		{"code_mitigation evidence file is invalid: finding path: path is not a regular file",
			"code_mitigation evidence file is invalid: finding path is not a regular file"},
		{"test_only evidence file is invalid: evidence path: lstat /home/canary/src/canary_module.py: no such file or directory",
			"test_only evidence file is invalid: evidence path does not exist"},
		{`code_mitigation evidence file is invalid: finding path: CreateFile C:\canary\app.py: The system cannot find the file specified.`,
			"code_mitigation evidence file is invalid: finding path does not exist"},
		{"code_mitigation evidence file is invalid: evidence path: lstat /home/canary/loop: too many levels of symbolic links",
			"code_mitigation evidence file is invalid: evidence path cannot be resolved"},
		{"test_only evidence line does not match finding line", "test_only evidence line does not match finding line"},
		{"code_mitigation evidence is incomplete", "code_mitigation evidence is incomplete"},
		{rejected + "canary_settings.yaml is a configuration or data file, which contains no code that mitigates",
			rejected + "{file} is a configuration or data file, which contains no code that mitigates"},
		{rejected + "the finding has no line, so no mitigation can be tied to it",
			rejected + "the finding has no line, so no mitigation can be tied to it"},
		{rejected + "evidence.line must cite code other than the flagged line itself",
			rejected + "evidence.line must cite code other than the flagged line itself"},
		{rejected + "line 14 is after the flagged line 9; a mitigation must run before the flagged statement",
			rejected + "line N is after the flagged line N"},
		{rejected + "line 2 is more than 30 lines above the flagged line 77",
			rejected + "line N is more than N lines above the flagged line N"},
		{rejected + "canary.cob is not a recognised source language, so the cited text cannot be checked for comments and string literals",
			rejected + "{file} is not a recognised source language"},
		{"code_mitigation evidence is unreadable: open /srv/canary/app.py: permission denied", "code_mitigation evidence is unreadable"},
		{"code_mitigation evidence is unreadable: flagged line 120 is outside source file",
			"code_mitigation evidence is unreadable: flagged line N is outside source file"},
		{"code_mitigation observed text is absent from source", "code_mitigation observed text is absent from source"},
		{rejected + "observed text could not be located in the source line",
			rejected + "observed text could not be located in the source line"},
		{rejected + "observed text is not code only: part of it lies inside a comment",
			rejected + "observed text is not code only: part of it lies inside a comment"},
		{rejected + "observed text is not code only: part of it lies inside a comment or string literal",
			rejected + "observed text is not code only: part of it lies inside a comment or string literal"},
		{rejected + "observed text lies inside a string literal, not in code",
			rejected + "observed text lies inside a string literal, not in code"},
		{rejected + "observed text has no code tokens (prose is not a mitigation)",
			rejected + "observed text has no code tokens (prose is not a mitigation)"},
		{rejected + "observed text shares no identifier with the flagged statement on line 40; cite the code that checks or transforms the data it uses",
			rejected + "observed text shares no identifier with the flagged statement on line N"},
		{rejected + "line 31 is in a different function than the flagged line 52; a mitigation must run in the same function, before the flagged statement",
			rejected + "line N is in a different function than the flagged line N"},
		{rejected + "line 6 is neither a guard nor a re-assignment through a call; cite an if, elif or assert in the same function that checks canary_cmd (or an early exit under such a check), or a re-assignment through a call such as canary_cmd = f(canary_cmd)",
			rejected + "line N is neither a guard nor a re-assignment through a call"},
		{rejected + "line 7 is an assert that does not check canary_a, canary_b; cite an if",
			rejected + "line N is an assert that does not check {names}"},
		{rejected + "line 7 is an assertion that does not check canary_a; cite an if",
			rejected + "line N is an assertion that does not check {names}"},
		{rejected + "line 7 is a condition that does not check canary_a, canary_b; cite an if",
			rejected + "line N is a condition that does not check {names}"},
		{rejected + "line 7 is a check of canary_a that neither exits early (return, raise, throw, abort) nor encloses the flagged line 12; cite an if",
			rejected + "line N is a check of {names} that neither exits early nor encloses the flagged line N"},
		{rejected + "line 7 is an early exit under a condition that does not check canary_a; cite an if",
			rejected + "line N is an early exit under a condition that does not check {names}"},
		{rejected + "line 7 is an early exit that is not under a check of canary_a; cite an if",
			rejected + "line N is an early exit that is not under a check of {names}"},
		{rejected + "line 7 is an assignment to something other than canary_a; cite an if",
			rejected + "line N is an assignment to something other than {names}"},
		{rejected + "line 7 is an assignment of canary_a that does not pass canary_a through a call: the assignment that produces a value is not its mitigation, only canary_a = f(canary_a) is; cite an if",
			rejected + "line N is an assignment of {name} that does not pass it through a call"},
		// Long reasons are cut and end in an ellipsis.
		{rejected + "line 7 is an assignment of canary_a_name_that_runs_past_the_lim…",
			rejected + "line N is an assignment of {name} that does not pass it through a call"},
		{"  code_mitigation   evidence rejected:\n line 3 is neither a guard nor a re-assignment through a call ",
			rejected + "line N is neither a guard nor a re-assignment through a call"},
		// Downgrades wrap the validator's own reason.
		{kept + "a hardcoded secret is never dismissed automatically, whatever the evidence: a person must decide",
			kept + "a hardcoded secret is never dismissed automatically, whatever the evidence"},
		{kept + "code_mitigation evidence is not accepted for a CRITICAL finding: a person must decide",
			kept + "code_mitigation evidence is not accepted for a CRITICAL finding"},
		{kept + "code_mitigation evidence is not accepted for a hardcoded secret: a person must decide",
			kept + "code_mitigation evidence is not accepted for a hardcoded secret"},
		{kept + "code_mitigation evidence for a HIGH finding must be tied to the flagged statement's function, and AITriage has no parser for canary.rb: a person must decide",
			kept + "code_mitigation evidence for a HIGH finding must be tied to the flagged statement's function, and AITriage has no parser for {file}"},
		{kept + "code_mitigation evidence for a CANARY finding must be tied to the flagged statement's function, and AITriage has no parser for canary.rb: a person must decide",
			kept + "code_mitigation evidence for a {severity} finding must be tied to the flagged statement's function, and AITriage has no parser for {file}"},
		{`false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence requires high confidence, model reported "canary"`,
			"false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence requires high confidence"},
		// A reason no category knows keeps only known words.
		{"the model cited canary_fn at line 12", "the model {value} at line N"},
		{"the model cited a helper; cite canary_fn at line 12 instead", "the model {value} a {value}"},
		{`verdict named "canary x" for /home/canary/a.py twice`, "verdict {value} for {value}"},
		{kept + "canary_policy forbids it", kept + "{value} it"},
		{"", "(no reason)"},
	} {
		got := normaliseReason(c.reason)
		if got != c.want {
			t.Errorf("normaliseReason(%q)\n got %q\nwant %q", c.reason, got, c.want)
		}
		if strings.Contains(got, "canary") {
			t.Errorf("category %q leaks a value of the reason", got)
		}
	}
}

// reasonsArtifact is one triage run of four findings. Audit indices count
// the deduplicated findings of the run; fingerprints link them to findings.
const reasonsArtifact = `{"schema_version": 1,
 "findings": [
  {"finding": {"id": "RULE-A", "source": "aitriage", "vuln_id": "CS-INJ-a1a1a1", "stable_id": "stable-a", "file": "src/canary_module.py",
               "origins": [{"rule_id": "RULE-A", "source": "aitriage", "file": "src/canary_module.py"}]},
   "disposition": {"disposition": "Needs Manual Review", "disposition_source": "nr-fallback", "fingerprint": "fp-a"}},
  {"finding": {"id": "RULE-A", "source": "aitriage", "vuln_id": "CS-INJ-b2b2b2", "stable_id": "stable-b",
               "origins": [{"rule_id": "RULE-A", "source": "aitriage"}, {"rule_id": "EXT-1", "source": "semgrep"}]},
   "disposition": {"disposition": "False Positive", "disposition_source": "llm", "fingerprint": "fp-b"}},
  {"finding": {"id": "RULE-S", "source": "gitleaks", "vuln_id": "CS-SECRET-c3c3c3",
               "origins": [{"rule_id": "RULE-S", "source": "gitleaks"}]},
   "disposition": {"disposition": "Needs Manual Review", "disposition_source": "llm", "fingerprint": "fp-s"}},
  {"finding": {"id": "RULE-C", "source": "aitriage", "vuln_id": "CS-XSS-d4d4d4"},
   "disposition": {"disposition": "Needs Manual Review", "disposition_source": "nr-fallback"}}
 ],
 "classification_audit": [
  {"attempt": 0, "unique_finding_indices": [0, 1, 2, 3],
   "finding_ids": ["CS-INJ-a1a1a1", "CS-INJ-b2b2b2", "CS-SECRET-c3c3c3", "CS-XSS-d4d4d4"],
   "fingerprints": ["fp-a", "fp-b", "fp-s", "fp-d"],
   "raw_response": "[{\"finding_index\": 0, \"observed\": \"canary_token = 1\"}]",
   "accepted_finding_indices": [2],
   "rejected": [
    {"finding_index": 0, "reason": "code_mitigation evidence rejected: line 6 is neither a guard nor a re-assignment through a call; cite an if, elif or assert in the same function that checks canary_token (or an early exit under such a check), or a re-assignment through a call such as canary_token = f(canary_token)"},
    {"finding_index": 1, "reason": "code_mitigation evidence rejected: line 12 is a condition that does not check canary_key, canary_session; cite an if, elif or assert"},
    {"finding_index": 2, "reason": "out-of-range finding_index"},
    {"finding_index": 3, "reason": "test_only evidence file is invalid: evidence path: lstat /home/runner/work/canary-project/src/canary_module.py: no such file or directory"},
    {"finding_index": 3, "reason": "evidence cites canary_helper() in canary_util.rb at line 44"}
   ],
   "downgraded": [
    {"finding_index": 2, "reason": "false positive kept as Needs Manual Review: a hardcoded secret is never dismissed automatically, whatever the evidence: a person must decide"}
   ]},
  {"attempt": 1, "unique_finding_indices": [0], "finding_ids": ["CS-INJ-a1a1a1"], "fingerprints": ["fp-a"], "raw_response": "[]",
   "rejected": [{"finding_index": 0, "reason": "code_mitigation evidence rejected: line 9 is neither a guard nor a re-assignment through a call; cite canary_var"}]},
  {"attempt": 0, "unique_finding_indices": [3], "finding_ids": ["CS-XSS-d4d4d4"], "fingerprints": ["fp-d"], "raw_response": "", "parse_error": "reply is not JSON"}
 ]}`

func TestReasonsReport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "svc-canary", "triage-findings.json"), reasonsArtifact)

	var tsv bytes.Buffer
	if err := run(&tsv, options{format: "tsv", reasons: true}, []string{dir}); err != nil {
		t.Fatal(err)
	}
	const neither = "code_mitigation evidence rejected: line N is neither a guard nor a re-assignment through a call"
	const condition = "code_mitigation evidence rejected: line N is a condition that does not check {names}"
	const missing = "test_only evidence file is invalid: evidence path does not exist"
	const unknown = "evidence {value}() in {value} at line N"
	const secret = "false positive kept as Needs Manual Review: a hardcoded secret is never dismissed automatically, whatever the evidence"
	want := strings.Join([]string{
		"decision\trule\treason\tcount",
		"rejected\t(all)\t" + neither + "\t2",
		"rejected\t(all)\t" + condition + "\t1",
		"rejected\t(all)\t" + unknown + "\t1",
		"rejected\t(all)\tout-of-range finding_index\t1",
		"rejected\t(all)\t" + missing + "\t1",
		"downgraded\t(all)\t" + secret + "\t1",
		// The fingerprint names the finding; a retry counts again.
		"rejected\tRULE-A\t" + neither + "\t2",
		// An out-of-range index is the model's and names no finding.
		"rejected\t(unattributed)\tout-of-range finding_index\t1",
		// A merged finding counts for every rule that reported it.
		"rejected\tEXT-1\t" + condition + "\t1",
		"rejected\tRULE-A\t" + condition + "\t1",
		// No finding has the fingerprint: the finding id names it.
		"rejected\tRULE-C\t" + unknown + "\t1",
		"rejected\tRULE-C\t" + missing + "\t1",
		"downgraded\tRULE-S\t" + secret + "\t1",
	}, "\n") + "\n"
	if tsv.String() != want {
		t.Errorf("tsv report:\n%s\nwant:\n%s", tsv.String(), want)
	}
	assertPrivate(t, tsv.String())

	var md bytes.Buffer
	if err := run(&md, options{format: "md", reasons: true}, []string{dir}); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"Runs: 1\nClassification requests: 3 (1 without a parsed reply)\nValidator decisions: 6 rejected, 1 downgraded\n",
		"## Rejected verdicts\n\n| reason | count |\n|---|---|\n| " + neither + " | 2 |\n",
		"## Downgraded verdicts\n\n| reason | count |\n|---|---|\n| " + secret + " | 1 |\n",
		"## Per rule\n\n| rule | decision | reason | count |\n|---|---|---|---|\n| RULE-A | rejected | " + neither + " | 2 |\n",
		"| (unattributed) | rejected | out-of-range finding_index | 1 |\n",
	} {
		if !strings.Contains(md.String(), line) {
			t.Errorf("md report lacks %q:\n%s", line, md.String())
		}
	}
	assertPrivate(t, md.String())
}

func TestReasonsReportWithoutDecisions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "triage-findings.json"), `{"schema_version": 1, "findings": [], "classification_audit": []}`)
	var md bytes.Buffer
	if err := run(&md, options{format: "md", reasons: true}, []string{dir}); err != nil {
		t.Fatal(err)
	}
	want := "Runs: 1\nClassification requests: 0 (0 without a parsed reply)\nValidator decisions: 0 rejected, 0 downgraded\n" +
		"\n## Rejected verdicts\n\nNone.\n\n## Downgraded verdicts\n\nNone.\n\n## Per rule\n\nNone.\n"
	if md.String() != want {
		t.Errorf("md report:\n%s\nwant:\n%s", md.String(), want)
	}
}
