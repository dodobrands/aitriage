package config

import "testing"

func TestNormalizeTrivyCheckID(t *testing.T) {
	cases := map[string]string{
		// The spellings Trivy has used for its KSV and DS checks.
		"KSV012":       "KSV-0012",
		"KSV-0012":     "KSV-0012",
		"AVD-KSV-0012": "KSV-0012",
		"avd-ksv-0012": "KSV-0012",
		" ksv012 ":     "KSV-0012",
		"KSV110":       "KSV-0110",
		"DS002":        "DS-0002",
		"DS-0026":      "DS-0026",
		"AVD-DS-0002":  "DS-0002",
		// Anything else comes back as written, upper-cased.
		"KSV12":               "KSV12",
		"KSV0012":             "KSV0012",
		"KSV-012":             "KSV-012",
		"DS26":                "DS26",
		"AWS001":              "AWS001",
		"AWS-0001":            "AWS-0001",
		"AVD-AWS-0107":        "AVD-AWS-0107",
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

func TestIsTrivyCheckID(t *testing.T) {
	for id, want := range map[string]bool{
		"KSV012": true, "KSV-0012": true, "avd-ksv-0012": true, "DS002": true, " ds-0002 ": true,
		"KSV12": false, "AWS-0107": false, "AWS001": false,
		"CVE-2024-1234": false, "GHSA-abcd-efgh-ijkl": false, "generic-api-key": false, "NFR-ENV-001": false, "": false,
	} {
		if got := IsTrivyCheckID(id); got != want {
			t.Errorf("IsTrivyCheckID(%q) = %t; want %t", id, got, want)
		}
	}
}

// Trivy has reported one check as KSV012, AVD-KSV-0012 and KSV-0012 in
// different releases. A reference written for one spelling matched only that
// one, so a scanner upgrade silently brought back what a project had
// silenced.
func TestRuleRefMatchesEverySpellingOfATrivyCheck(t *testing.T) {
	families := [][]string{
		{"KSV012", "KSV-0012", "AVD-KSV-0012", "ksv012", "avd-ksv-0012"},
		{"DS002", "DS-0002", "AVD-DS-0002"},
	}
	for _, spellings := range families {
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
	}

	cases := []struct {
		entry   string
		ruleID  string
		sources []string
		want    bool
	}{
		// Different checks stay apart.
		{"KSV012", "KSV-0120", []string{"trivy"}, false},
		{"KSV012", "DS-0012", []string{"trivy"}, false},
		{"DS002", "DS-0026", []string{"trivy"}, false},
		// Only the spellings Trivy has used are read as one check: a short
		// form is a word, not an id.
		{"KSV12", "KSV-0012", []string{"trivy"}, false},
		{"KSV12", "KSV012", []string{"trivy"}, false},
		{"KSV0012", "KSV-0012", []string{"trivy"}, false},
		{"DS26", "DS-0026", []string{"trivy"}, false},
		{"trivy:DS26", "DS-0026", []string{"trivy"}, false},
		// Other Trivy families compare as written: tfsec's legacy AWS001 is
		// not Trivy's AWS-0001.
		{"AWS001", "AWS-0001", []string{"trivy"}, false},
		{"trivy:AWS001", "AWS-0001", []string{"trivy"}, false},
		{"AVD-AWS-0001", "AWS-0001", []string{"trivy"}, false},
		{"aws-0001", "AWS-0001", []string{"trivy"}, true},
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
