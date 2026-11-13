package config

import "testing"

func TestNormalizeTrivyCheckID(t *testing.T) {
	cases := map[string]string{
		"KSV012":              "KSV-0012",
		"KSV-0012":            "KSV-0012",
		"AVD-KSV-0012":        "KSV-0012",
		"avd-ksv-0012":        "KSV-0012",
		" ksv12 ":             "KSV-0012",
		"DS002":               "DS-0002",
		"AVD-AWS-0107":        "AWS-0107",
		"AWS-0107":            "AWS-0107",
		"CVE-2024-1234":       "CVE-2024-1234",
		"ghsa-abcd-efgh-ijkl": "GHSA-ABCD-EFGH-IJKL",
		"generic-api-key":     "GENERIC-API-KEY",
	}
	for id, want := range cases {
		if got := NormalizeTrivyCheckID(id); got != want {
			t.Errorf("NormalizeTrivyCheckID(%q) = %q; want %q", id, got, want)
		}
	}
}

// Trivy has reported one check as KSV012, AVD-KSV-0012 and KSV-0012 in
// different releases. A reference written for one spelling matched only that
// one, so a scanner upgrade silently brought back what a project had
// silenced.
func TestRuleRefMatchesEverySpellingOfATrivyCheck(t *testing.T) {
	spellings := []string{"KSV012", "KSV-0012", "AVD-KSV-0012", "ksv-12"}
	for _, entry := range spellings {
		for _, prefix := range []string{"", "trivy:", "Trivy:"} {
			ref := ParseRuleRef(prefix + entry)
			for _, id := range spellings {
				if !ref.Matches(id, "trivy") {
					t.Errorf("%q does not match Trivy's %q", prefix+entry, id)
				}
			}
		}
	}

	cases := []struct {
		entry   string
		ruleID  string
		sources []string
		want    bool
	}{
		// Different checks stay apart.
		{"KSV012", "KSV-0120", []string{"trivy"}, false},
		{"KSV012", "KCV-0012", []string{"trivy"}, false},
		{"DS002", "DS-0026", []string{"trivy"}, false},
		// Advisories compare as written: zero padding means a different id.
		{"trivy:CVE-2024-0042", "CVE-2024-0042", []string{"trivy"}, true},
		{"trivy:CVE-2024-0042", "CVE-2024-42", []string{"trivy"}, false},
		{"GHSA-abcd-efgh-ijkl", "GHSA-ABCD-EFGH-IJKL", []string{"trivy"}, true},
		// Other sources compare as written, even with check-shaped ids.
		{"B-0105", "B105", []string{"bandit"}, false},
		{"ENTR-018", "ENTR-18", CoreRuleSources, false},
		{"KSV012", "KSV-0012", []string{"semgrep"}, false},
		// A qualifier for another scanner still excludes Trivy findings.
		{"semgrep:KSV012", "KSV-0012", []string{"trivy"}, false},
	}
	for _, tc := range cases {
		if got := ParseRuleRef(tc.entry).Matches(tc.ruleID, tc.sources...); got != tc.want {
			t.Errorf("%q matches %q from %v = %t; want %t", tc.entry, tc.ruleID, tc.sources, got, tc.want)
		}
	}
}

func TestRuleMatcherReportsTheEntryWrittenForAnotherSpelling(t *testing.T) {
	m := NewRuleMatcher([]string{"trivy:DS002"})
	if entry, ok := m.Match("AVD-DS-0002", "trivy"); !ok || entry != "trivy:DS002" {
		t.Errorf("Match = %q, %t; want the configuration entry as written", entry, ok)
	}
}
