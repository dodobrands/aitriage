package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Trivy has spelled one misconfiguration check several ways across releases:
// "KSV012" and "DS002" in older reports, "AVD-KSV-0012" as the id of the
// Aqua Vulnerability Database, and "KSV-0012" in current ones. The class table
// and every rule reference (ignore.rules, inline directives) must recognise
// all of them, or an upgrade of the scanner silently changes what a project
// suppresses.

// trivyCheckIDPattern matches a Trivy check id once an "AVD-" prefix is gone:
// letters, an optional hyphen and a number with any zero padding.
var trivyCheckIDPattern = regexp.MustCompile(`^([A-Z]+)-?0*([0-9]+)$`)

// NormalizeTrivyCheckID maps the spellings Trivy releases use for one check
// ("KSV012", "KSV-0012", "AVD-KSV-0012", any case) to one form, "KSV-0012".
// An id of another shape, such as an advisory (CVE-2024-1234, GHSA-…), comes
// back upper-cased and otherwise unchanged.
func NormalizeTrivyCheckID(id string) string {
	id = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id)), "AVD-")
	m := trivyCheckIDPattern.FindStringSubmatch(id)
	if m == nil {
		return id
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return id
	}
	return fmt.Sprintf("%s-%04d", m[1], n)
}

// sameRuleID reports whether a rule reference's id names the rule a finding
// was reported under. Ids compare whole and case-insensitively. For a finding
// that answers to trivy, a check also matches under any spelling Trivy has
// used for it; advisories (CVE, GHSA) and the ids of every other source still
// compare as written.
func sameRuleID(refID, ruleID string, sources []string) bool {
	ruleID = strings.TrimSpace(ruleID)
	if strings.EqualFold(refID, ruleID) {
		return true
	}
	if !answersTo(sources, "trivy") {
		return false
	}
	ref := NormalizeTrivyCheckID(refID)
	return trivyCheckIDPattern.MatchString(ref) && ref == NormalizeTrivyCheckID(ruleID)
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
