package config

import (
	"regexp"
	"strings"
)

// Trivy has spelled its Kubernetes (KSV) and Dockerfile (DS) checks three ways
// across releases: "KSV012" and "DS002" in older reports, "AVD-KSV-0012" as
// the id of the Aqua Vulnerability Database, and "KSV-0012" in current ones.
// The class table and every rule reference (ignore.rules, inline directives)
// recognise all three, or an upgrade of the scanner would silently change
// what a project suppresses.
//
// Only those spellings of those two families are normalised. Other ids look
// alike without naming the same check: tfsec's legacy code AWS001 is not
// Trivy's AWS-0001, and "DS26" or "KSV12" is no spelling Trivy ever used, but
// a word that may stand in the reason of an inline directive. They compare as
// written.

// trivyCheckSpelling matches the spellings of one KSV or DS check: three
// digits without a hyphen, or four after one, with or without "AVD-".
var trivyCheckSpelling = regexp.MustCompile(`^(?:(KSV|DS)([0-9]{3})|(?:AVD-)?(KSV|DS)-([0-9]{4}))$`)

// NormalizeTrivyCheckID maps the spellings Trivy releases have used for one
// Kubernetes or Dockerfile check ("KSV012", "KSV-0012", "AVD-KSV-0012", any
// case) to one form, "KSV-0012". Any other id, of another Trivy check family,
// an advisory (CVE-2024-1234, GHSA-…) or another scanner, comes back
// upper-cased and otherwise as written.
func NormalizeTrivyCheckID(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if check, ok := trivyCheck(id); ok {
		return check
	}
	return id
}

// trivyCheck returns the canonical form of an upper-cased KSV or DS check id
// in one of the spellings Trivy has used, or false.
func trivyCheck(id string) (string, bool) {
	m := trivyCheckSpelling.FindStringSubmatch(id)
	switch {
	case m == nil:
		return "", false
	case m[1] != "":
		return m[1] + "-0" + m[2], true
	default:
		return m[3] + "-" + m[4], true
	}
}

// sameRuleID reports whether a rule reference's id names the rule a finding
// was reported under. Ids compare whole and case-insensitively. For a finding
// that answers to trivy, a KSV or DS check also matches under any spelling
// Trivy has used for it; every other id still compares as written.
func sameRuleID(refID, ruleID string, sources []string) bool {
	ruleID = strings.TrimSpace(ruleID)
	if strings.EqualFold(refID, ruleID) {
		return true
	}
	if !answersTo(sources, "trivy") {
		return false
	}
	ref, ok := trivyCheck(strings.ToUpper(strings.TrimSpace(refID)))
	if !ok {
		return false
	}
	reported, ok := trivyCheck(strings.ToUpper(ruleID))
	return ok && ref == reported
}

// answersTo reports whether a finding reported under sources answers to the
// named source.
func answersTo(sources []string, source string) bool {
	for _, s := range sources {
		if strings.EqualFold(strings.TrimSpace(s), source) {
			return true
		}
	}
	return false
}
