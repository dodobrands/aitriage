package suppression

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

func TestDescribeScopeNamesTheReachOfADismissal(t *testing.T) {
	cases := []struct {
		item baseline.Item
		want string
	}{
		{baseline.Item{RuleID: "SECRET-ASSIGN"}, "every core finding of SECRET-ASSIGN anywhere in the project"},
		{baseline.Item{Source: "gitleaks", RuleID: "generic-api-key", File: "app/settings.py"}, "every gitleaks finding of generic-api-key in app/settings.py"},
		{baseline.Item{RuleID: "NFR-API-001", Evidence: "no rate limit"}, "only core findings of NFR-API-001 that are reported without a file"},
		{baseline.Item{RuleID: "SECRET-ASSIGN", File: "a.py", Evidence: "x"}, "only the core finding of SECRET-ASSIGN in a.py that carries this evidence"},
	}
	for _, tc := range cases {
		if got := DescribeScope(tc.item); !strings.Contains(got, tc.want) {
			t.Errorf("DescribeScope(%+v) = %q, want it to contain %q", tc.item, got, tc.want)
		}
	}
}

// One call must not silently dismiss a rule across the whole project.
func TestValidateScopeNeedsAFileOrAnExplicitRuleWideRequest(t *testing.T) {
	if err := ValidateScope(baseline.Item{RuleID: "SECRET-ASSIGN"}, false); err == nil {
		t.Error("a dismissal without a file was accepted without rule_wide")
	}
	if err := ValidateScope(baseline.Item{RuleID: "SECRET-ASSIGN", File: "a.py"}, true); err == nil {
		t.Error("rule_wide together with a file was accepted")
	}
	if err := ValidateScope(baseline.Item{RuleID: "SECRET-ASSIGN"}, true); err != nil {
		t.Errorf("an explicit rule-wide dismissal was refused: %v", err)
	}
	if err := ValidateScope(baseline.Item{RuleID: "SECRET-ASSIGN", File: "a.py"}, false); err != nil {
		t.Errorf("a file-scoped dismissal was refused: %v", err)
	}
}
