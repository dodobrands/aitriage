package graph

import (
	"strconv"
	"strings"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// ── Canonical classes in the triage graph ────────────────────────────────────
//
// The class table itself lives in healthcheck (ClassifyRule), so the core-only
// scan path and the triage graph agree on what "the same defect" means. The
// graph uses it three ways: to merge the reports of several detectors into one
// finding (mergeSemanticFindings), to give the merged finding one identity in
// the health check, and to pick the class code of its display id.

// findingClass returns the canonical class of a finding, from the class
// recorded at merge time or from its rule.
func findingClass(f EnrichedFinding) (healthcheck.FindingClass, bool) {
	if f.Class != "" {
		if class, ok := healthcheck.LookupClass(f.Class); ok {
			return class, true
		}
	}
	return healthcheck.ClassifyRule(healthcheck.RuleRef{
		Type:    f.Type,
		Source:  f.Source,
		RuleID:  f.ID,
		Package: f.Package,
	})
}

// semanticFindingClass returns the canonical class key of a finding, or ""
// when no class covers its rule.
func semanticFindingClass(f EnrichedFinding) string {
	if class, ok := findingClass(f); ok {
		return class.Key
	}
	return ""
}

// isHardcodedSecret reports whether a finding, or any detector merged into it,
// reports a hardcoded secret.
func isHardcodedSecret(f EnrichedFinding) bool {
	if semanticFindingClass(f) == healthcheck.ClassHardcodedSecret {
		return true
	}
	for _, origin := range f.Origins {
		class, ok := healthcheck.ClassifyRule(healthcheck.RuleRef{Type: origin.Type, Source: origin.Source, RuleID: origin.RuleID})
		if ok && class.Key == healthcheck.ClassHardcodedSecret {
			return true
		}
	}
	return false
}

// semanticFindingKey is the identity under which findings merge: one defect,
// whichever detectors reported it.
//   - Classified findings merge with the other findings of their class at the
//     same file and line, or at the same file for a file-scoped class.
//     Advisories (dependency CVEs) merge only with the same advisory for the
//     same package.
//   - A finding without a location is one rule's verdict about the project,
//     classified or not, and merges only with reports of the same rule: a
//     check reported once per detected stack is one finding. Two rules of one
//     class are two defects of two components (FAST-AUTH about a FastAPI
//     service, NEXT-AUTH about a Next.js frontend): they never merge, so a
//     decision about one never covers the other and each one counts.
//   - A located finding no class covers merges only with byte-identical
//     reports.
//   - Network probe results describe the scanning host, one per probed
//     service, and only merge when identical.
func semanticFindingKey(f EnrichedFinding) string {
	file := normalizePath(f.File)
	located := file != "" || f.Line != 0
	class, ok := findingClass(f)
	switch {
	case isEnvironmentFinding(f) || (!ok && located):
		return "exact|" + Fingerprint(f)
	case ok && class.Scope == healthcheck.ScopeRule:
		return "advisory|" + strings.ToLower(strings.TrimSpace(f.ID)) + "|" + strings.ToLower(strings.TrimSpace(f.Package)) +
			"|" + strings.TrimSpace(f.InstalledVersion) + "|" + file
	case !located:
		return projectRuleKey(f)
	case class.Scope == healthcheck.ScopeFile && file != "":
		return class.Key + "|" + file
	default:
		return class.Key + "|" + file + "|" + strconv.Itoa(f.Line)
	}
}

// projectRuleKey identifies a project-level finding by the rule that reported
// it: its type, scanner and rule id.
func projectRuleKey(f EnrichedFinding) string {
	return "rule|" + strings.ToLower(strings.TrimSpace(f.Type)) + "|" + strings.ToLower(strings.TrimSpace(f.Source)) +
		"|" + strings.ToLower(strings.TrimSpace(f.ID)) + "|project"
}

// classCode is the class part of a finding's display id.
func classCode(f EnrichedFinding) string {
	if class, ok := findingClass(f); ok && class.Code != "" {
		return class.Code
	}
	if isEnvironmentFinding(f) {
		return "NET"
	}
	return "MISC"
}

// isDependencyFinding reports whether a finding is a package advisory.
func isDependencyFinding(f EnrichedFinding) bool {
	return strings.TrimSpace(f.Package) != ""
}
