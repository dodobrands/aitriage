package scanner

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

func TestSarifTagsCarryTheRuleCWE(t *testing.T) {
	if got := sarifTags(core.CheckResult{CWE: "CWE-89"}); len(got) != 2 || got[1] != "external/cwe/cwe-89" {
		t.Errorf("tags = %v", got)
	}
	if got := sarifTags(core.CheckResult{}); len(got) != 1 || got[0] != "security" {
		t.Errorf("tags without CWE = %v", got)
	}
}
