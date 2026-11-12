package healthcheck

import "testing"

func TestGetOWASP(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		expected string
	}{
		{
			name:     "Known rule: ENTROPY-SECRET",
			ruleID:   "ENTROPY-SECRET",
			expected: "A02:2021 – Cryptographic Failures",
		},
		{
			// The ENTR-FRAGILE heuristic never fired (it compared extensions
			// without the dot) and was removed; no producer emits this id.
			// The YAML rule ENTR-FRAGILE-LOGIC is a different rule.
			name:     "Removed heuristic: ENTR-FRAGILE",
			ruleID:   "ENTR-FRAGILE",
			expected: "",
		},
		{
			name:     "Known rule: ENTR-04",
			ruleID:   "ENTR-04",
			expected: "A04:2021 – Insecure Design",
		},
		{
			name:     "Known rule: ENTR-12",
			ruleID:   "ENTR-12",
			expected: "A04:2021 – Insecure Design",
		},
		{
			name:     "Known rule: missing_lockfile",
			ruleID:   "missing_lockfile",
			expected: "A06:2021 – Vulnerable and Outdated Components",
		},
		{
			name:     "Known rule: NFR-API-001",
			ruleID:   "NFR-API-001",
			expected: "A04:2021 – Insecure Design",
		},
		{
			name:     "Known rule: NFR-API-002",
			ruleID:   "NFR-API-002",
			expected: "A05:2021 – Security Misconfiguration",
		},
		{
			name:     "Known rule: NFR-API-003",
			ruleID:   "NFR-API-003",
			expected: "A01:2021 – Broken Access Control",
		},
		{
			name:     "Known rule: NFR-ENV-002",
			ruleID:   "NFR-ENV-002",
			expected: "A02:2021 – Cryptographic Failures",
		},
		{
			name:     "Unknown rule",
			ruleID:   "UNKNOWN_RULE_XYZ",
			expected: "",
		},
		{
			name:     "Empty rule",
			ruleID:   "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetOWASP(tc.ruleID)
			if result != tc.expected {
				t.Errorf("GetOWASP(%q) = %q; expected %q", tc.ruleID, result, tc.expected)
			}
		})
	}
}
