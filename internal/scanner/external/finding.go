package external

// UnifiedFinding — common structure for results from all scanners
type UnifiedFinding struct {
	Source             string `json:"source"` // "aitriage" | "semgrep" | "gitleaks" | "trivy" | "bandit" | "securecoder"
	RuleID             string `json:"rule_id"`
	Severity           string `json:"severity"` // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
	Message            string `json:"message"`
	File               string `json:"file"`
	Line               int    `json:"line"`
	Suggestion         string `json:"suggestion,omitempty"`
	OWASP              string `json:"owasp,omitempty"`
	CWE                string `json:"cwe,omitempty"`
	VulnerabilityClass string `json:"vulnerability_class,omitempty"`
	EndLine            int    `json:"end_line,omitempty"`
	StartColumn        int    `json:"start_column,omitempty"`
	EndColumn          int    `json:"end_column,omitempty"`

	// Dependency findings (Trivy vulnerabilities) name the affected package.
	// Without these fields fifty CVEs in one outdated library read as fifty
	// unrelated problems, and the upgrade that fixes them all is not visible.
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	// PrimaryURL is the scanner's reference page for the rule or advisory.
	PrimaryURL string `json:"primary_url,omitempty"`
}
