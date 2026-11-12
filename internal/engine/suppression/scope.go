package suppression

import (
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

// SourceName is the scanner a decision recorded without a source applies to:
// findings of the built-in engine.
func SourceName(source string) string {
	if strings.TrimSpace(source) == "" {
		return "core"
	}
	return source
}

// DescribeScope says which findings a dismissal of item covers. A decision
// without evidence covers every finding of the rule in its file; without a file
// as well, every finding of the rule anywhere in the project.
func DescribeScope(item baseline.Item) string {
	source := SourceName(item.Source)
	switch {
	case item.Evidence == "" && item.File == "":
		return fmt.Sprintf("covers every %s finding of %s anywhere in the project, including ones reported later", source, item.RuleID)
	case item.Evidence == "":
		return fmt.Sprintf("covers every %s finding of %s in %s, including ones reported later", source, item.RuleID, item.File)
	case item.File == "":
		return fmt.Sprintf("covers only %s findings of %s that are reported without a file and carry this evidence", source, item.RuleID)
	default:
		return fmt.Sprintf("covers only the %s finding of %s in %s that carries this evidence", source, item.RuleID, item.File)
	}
}

// ValidateScope rejects a dismissal whose reach the caller did not ask for. A
// decision without a file is rule-wide, so it must be requested explicitly
// (ruleWide); a rule-wide request must not name a file. Every write surface
// (MCP tool, Web API) applies the same rule so one call cannot silently dismiss
// a rule across the whole project.
func ValidateScope(item baseline.Item, ruleWide bool) error {
	switch {
	case item.File == "" && !ruleWide:
		return fmt.Errorf("file is required to dismiss a finding: pass the file it is in, and its evidence to dismiss only that finding. "+
			"Without a file this dismissal %s; set rule_wide to true if that is what you mean", DescribeScope(item))
	case item.File != "" && ruleWide:
		return fmt.Errorf("rule_wide records a dismissal that is not tied to a file, so it takes no file: drop file, or drop rule_wide to dismiss %s in %s only",
			item.RuleID, item.File)
	}
	return nil
}
