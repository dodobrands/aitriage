package healthcheck

import (
	"strings"
	"testing"
)

// A provider failure during triage must never turn into a passing gate: the
// triage_incomplete reason applies under every fail_on except never.
func TestEvaluatePolicyBlocksIncompleteTriageUnderEveryFailOnExceptNever(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{
		{Source: "core", Class: "EVAL", Severity: "LOW", File: "a.py", Line: 1, NeedsReview: true, Unclassified: true, TriageFailed: true},
	}})
	if res.Breakdown.TriageFailedFindings != 1 || res.Breakdown.UnclassifiedFindings != 1 {
		t.Fatalf("breakdown = %+v, want one triage-failed unclassified finding", res.Breakdown)
	}
	for _, failOn := range []string{FailOnCritical, FailOnAny, FailOnConfirmed} {
		verdict := EvaluatePolicy(res, Policy{Profile: PolicyBaseline, FailOn: failOn})
		if verdict.Passed {
			t.Fatalf("fail_on=%s passed an incomplete triage", failOn)
		}
		found := false
		for _, reason := range verdict.BlockingReasons {
			found = found || reason.Code == ReasonTriageIncomplete
		}
		if !found {
			t.Fatalf("fail_on=%s reasons = %+v, want %s", failOn, verdict.BlockingReasons, ReasonTriageIncomplete)
		}
	}
	if verdict := EvaluatePolicy(res, Policy{Profile: PolicyBaseline, FailOn: FailOnNever}); !verdict.Passed {
		t.Fatalf("fail_on=never must stay open: %+v", verdict)
	}
}

// Deduplication must not hide an incomplete triage behind a confirmed copy of
// the same issue.
func TestEvaluateCountsTriageFailuresBeforeDeduplication(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{
		{Source: "core", Class: "EVAL", Severity: "HIGH", File: "a.py", Line: 1},
		{Source: "core", Class: "EVAL", Severity: "HIGH", File: "a.py", Line: 1, NeedsReview: true, Unclassified: true, TriageFailed: true},
	}})
	if res.Breakdown.DedupedFindings != 1 || res.Breakdown.TriageFailedFindings != 1 {
		t.Fatalf("breakdown = %+v, want the triage failure counted despite deduplication", res.Breakdown)
	}
}

func TestConfirmedMinSeverityLimitsTheConfirmedGate(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{
		{Source: "core", Class: "A", Severity: "LOW", File: "a.py", Line: 1},
		{Source: "core", Class: "B", Severity: "MEDIUM", File: "a.py", Line: 2},
		{Source: "core", Class: "C", Severity: "HIGH", File: "a.py", Line: 3, NeedsReview: true},
	}})
	blocking := func(floor string) (bool, string) {
		verdict := EvaluatePolicy(res, Policy{Profile: PolicyBaseline, FailOn: FailOnConfirmed, ConfirmedMinSeverity: floor})
		message := ""
		for _, reason := range verdict.BlockingReasons {
			if reason.Code == "confirmed_findings" {
				message = reason.Message
			}
		}
		return !verdict.Passed, message
	}
	if blocked, msg := blocking(""); !blocked || !strings.Contains(msg, "2 confirmed finding(s) are not allowed") {
		t.Fatalf("default floor: blocked=%v message=%q, want every confirmed finding blocking", blocked, msg)
	}
	if blocked, msg := blocking("medium"); !blocked || !strings.Contains(msg, "1 confirmed finding(s) at or above MEDIUM") || !strings.Contains(msg, "1 confirmed below MEDIUM") {
		t.Fatalf("MEDIUM floor: blocked=%v message=%q", blocked, msg)
	}
	if blocked, _ := blocking("HIGH"); blocked {
		t.Fatal("HIGH floor: confirmed LOW/MEDIUM findings and an unreviewed HIGH must not block")
	}
	unknown := Evaluate(Input{Findings: []Finding{{Source: "trivy", Class: "CVE-1", Severity: "UNKNOWN", File: "go.mod", Line: 1}}})
	if verdict := EvaluatePolicy(unknown, Policy{Profile: PolicyBaseline, FailOn: FailOnConfirmed, ConfirmedMinSeverity: "CRITICAL"}); verdict.Passed {
		t.Fatal("a confirmed finding of unknown severity cannot be shown to be below the floor and must block")
	}
	critical := Evaluate(Input{Findings: []Finding{{Source: "core", Class: "A", Severity: "HIGH", File: "a.py", Line: 1}}})
	if verdict := EvaluatePolicy(critical, Policy{Profile: PolicyBaseline, FailOn: FailOnCritical, ConfirmedMinSeverity: "CRITICAL"}); verdict.Passed {
		t.Fatal("confirmed_min_severity must not relax any fail_on other than confirmed")
	}
}

func TestNormalizeConfirmedMinSeverity(t *testing.T) {
	for input, want := range map[string]string{"": SeverityLow, "low": SeverityLow, " High ": SeverityHigh, "CRITICAL": SeverityCritical, "hihg": SeverityLow} {
		if got := NormalizePolicy(Policy{ConfirmedMinSeverity: input}).ConfirmedMinSeverity; got != want {
			t.Errorf("NormalizePolicy(%q).ConfirmedMinSeverity = %q, want %q", input, got, want)
		}
	}
}

// The fail_on=any reason names the findings the model never classified, so a
// reader knows a re-run may resolve them.
func TestActiveFindingsReasonNamesUnclassifiedFindings(t *testing.T) {
	res := Evaluate(Input{Findings: []Finding{
		{Source: "core", Class: "A", Severity: "LOW", File: "a.py", Line: 1, NeedsReview: true, Unclassified: true},
		{Source: "core", Class: "B", Severity: "LOW", File: "a.py", Line: 2, NeedsReview: true},
	}})
	verdict := EvaluatePolicy(res, Policy{Profile: PolicyBaseline, FailOn: FailOnAny})
	if len(verdict.BlockingReasons) == 0 || !strings.Contains(verdict.BlockingReasons[0].Message, "1 of them were never classified by the model") {
		t.Fatalf("reasons = %+v, want the unclassified finding named", verdict.BlockingReasons)
	}
	if !strings.Contains(verdict.BlockingReasons[0].Message, "not been reviewed") {
		t.Fatalf("reason = %q, want the unreviewed wording kept", verdict.BlockingReasons[0].Message)
	}
}
