package healthcheck

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
)

// A gate written for a rule id must not relax when that rule's findings move
// to a new id: block_classes naming the earlier id still counts them.
func TestBlockedClassCountFollowsSplitRules(t *testing.T) {
	bd := Breakdown{CountByRule: map[string]int{"compose_default_credential": 2, "compose_hardcoded_secret": 1}}
	if got := blockedClassCount(bd, "compose_hardcoded_secret"); got != 3 {
		t.Fatalf("blockedClassCount(compose_hardcoded_secret) = %d, want 3 (the earlier id covers the findings split off it)", got)
	}
	if got := blockedClassCount(bd, "compose_default_credential"); got != 2 {
		t.Fatalf("blockedClassCount(compose_default_credential) = %d, want 2 (the new id covers only its own findings)", got)
	}

	res := ApplyPolicy(Result{Score: 100, Breakdown: Breakdown{CountByRule: map[string]int{"compose_default_credential": 1}}}, Policy{
		Profile:      PolicyBaseline,
		FailOn:       FailOnCritical,
		MaxCritical:  unlimitedThreshold,
		MaxHigh:      unlimitedThreshold,
		MaxMedium:    unlimitedThreshold,
		BlockClasses: []string{"compose_hardcoded_secret"},
	})
	blocked := false
	for _, reason := range res.Verdict.BlockingReasons {
		if reason.Code == "blocked_class" && reason.Class == "compose_hardcoded_secret" && reason.Count == 1 {
			blocked = true
		}
	}
	if res.Verdict.Passed || !blocked {
		t.Fatalf("verdict = %+v; block_classes [compose_hardcoded_secret] must still block a default Compose credential", res.Verdict)
	}
}

// The successor table must agree with the scanner that renamed the findings.
func TestRuleSuccessorsMatchScannerRenames(t *testing.T) {
	for previous, successors := range ruleSuccessors {
		for _, successor := range successors {
			if got := deployaudit.PreviousIssue(successor); got != previous {
				t.Fatalf("deployaudit.PreviousIssue(%q) = %q, want %q", successor, got, previous)
			}
		}
	}
}
