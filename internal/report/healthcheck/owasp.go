package healthcheck

// OWASPMap maps Rule ID → OWASP Top 10 2021 category
var OWASPMap = map[string]string{
	"ENTROPY-SECRET":   "A02:2021 – Cryptographic Failures",
	"ENTR-04":          "A04:2021 – Insecure Design",
	"ENTR-12":          "A04:2021 – Insecure Design",
	"missing_lockfile": "A06:2021 – Vulnerable and Outdated Components",
	"NFR-API-001":      "A04:2021 – Insecure Design",
	"NFR-API-002":      "A05:2021 – Security Misconfiguration",
	"NFR-API-003":      "A01:2021 – Broken Access Control",
	"NFR-ENV-002":      "A02:2021 – Cryptographic Failures",
}

// GetOWASP returns the OWASP category for a rule ID.
// Returns an empty string if no mapping exists.
func GetOWASP(ruleID string) string {
	return OWASPMap[ruleID]
}
