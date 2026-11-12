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

// semanticFindingKey is the identity under which findings merge: one defect,
// whichever detectors reported it.
//   - Classified findings merge with the other findings of their class at the
//     same file and line; at the same file for a file-scoped class; at the
//     project level when they have no location. Advisories (dependency CVEs)
//     merge only with the same advisory for the same package.
//   - A finding no class covers merges only with byte-identical reports, or,
//     when it has no location at all, with the same rule: a project-level
//     check reported once per detected stack is one finding.
//   - Network probe results describe the scanning host, one per probed
//     service, and only merge when identical.
func semanticFindingKey(f EnrichedFinding) string {
	file := normalizePath(f.File)
	located := file != "" || f.Line != 0
	class, ok := findingClass(f)
	switch {
	case isEnvironmentFinding(f) || (!ok && located):
		return "exact|" + Fingerprint(f)
	case !ok:
		return "rule|" + strings.ToLower(strings.TrimSpace(f.Type)) + "|" + strings.ToLower(strings.TrimSpace(f.ID)) + "|project"
	case class.Scope == healthcheck.ScopeRule:
		return "advisory|" + strings.ToLower(strings.TrimSpace(f.ID)) + "|" + strings.ToLower(strings.TrimSpace(f.Package)) +
			"|" + strings.TrimSpace(f.InstalledVersion) + "|" + file
	case !located:
		return class.Key + "|project"
	case class.Scope == healthcheck.ScopeFile && file != "":
		return class.Key + "|" + file
	default:
		return class.Key + "|" + file + "|" + strconv.Itoa(f.Line)
	}
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
