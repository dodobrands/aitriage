package healthcheck

import (
	"fmt"
	"strings"
)

const (
	PolicyBaseline = "baseline"
	PolicyStandard = "standard"
	PolicyStrict   = "strict"

	FailOnCritical = "critical"
	FailOnAny      = "any"
	FailOnNever    = "never"
	// FailOnConfirmed blocks only on findings someone actually confirmed.
	// Unreviewed findings are reported but do not fail the build. Teams choose
	// this when they triage on their own schedule and do not want an unreviewed
	// scanner hypothesis to stop a release.
	FailOnConfirmed = "confirmed"

	unlimitedThreshold = -1
)

// Policy defines the security requirements used to decide whether a repository
// may pass the security gate. Score remains informational; Verdict is the gate answer.
type Policy struct {
	Profile      string   `json:"profile"`
	FailOn       string   `json:"fail_on"`
	MinimumScore int      `json:"minimum_score"`
	MaxCritical  int      `json:"max_critical"`
	MaxHigh      int      `json:"max_high"`
	MaxMedium    int      `json:"max_medium"`
	BlockSources []string `json:"block_sources,omitempty"`
	BlockClasses []string `json:"block_classes,omitempty"`
}

// Verdict is the CI/CD-ready answer to "can this project pass its security policy?".
type Verdict struct {
	Passed          bool             `json:"passed"`
	Status          string           `json:"status"`
	Summary         string           `json:"summary"`
	BlockingReasons []BlockingReason `json:"blocking_reasons,omitempty"`
}

// BlockingReason explains one policy requirement that failed.
type BlockingReason struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Severity  string `json:"severity,omitempty"`
	Source    string `json:"source,omitempty"`
	Class     string `json:"class,omitempty"`
	Count     int    `json:"count,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
}

// DefaultPolicy preserves the existing deterministic scan gate semantics:
// active CRITICAL/HIGH findings block, score is reported but not a gate unless
// configured by CLI or YAML.
func DefaultPolicy() Policy {
	return PolicyForProfile(PolicyBaseline)
}

// PolicyForProfile returns a conservative built-in policy profile.
func PolicyForProfile(profile string) Policy {
	switch normalizeProfile(profile) {
	case PolicyStrict:
		return Policy{
			Profile:      PolicyStrict,
			FailOn:       FailOnAny,
			MinimumScore: 90,
			MaxCritical:  0,
			MaxHigh:      0,
			MaxMedium:    0,
		}
	case PolicyStandard:
		return Policy{
			Profile:      PolicyStandard,
			FailOn:       FailOnCritical,
			MinimumScore: 70,
			MaxCritical:  0,
			MaxHigh:      0,
			MaxMedium:    unlimitedThreshold,
		}
	default:
		return Policy{
			Profile:      PolicyBaseline,
			FailOn:       FailOnCritical,
			MinimumScore: 0,
			MaxCritical:  unlimitedThreshold,
			MaxHigh:      unlimitedThreshold,
			MaxMedium:    unlimitedThreshold,
		}
	}
}

// ApplyPolicy attaches policy and verdict to an already computed Health Check.
func ApplyPolicy(res Result, policy Policy) Result {
	policy = normalizePolicy(policy)
	res.Policy = policy
	res.Verdict = EvaluatePolicy(res, policy)
	return res
}

// EvaluatePolicy evaluates one policy against one Health Check result.
func EvaluatePolicy(res Result, policy Policy) Verdict {
	policy = normalizePolicy(policy)
	if policy.FailOn == FailOnNever {
		return Verdict{
			Passed:  true,
			Status:  "passed",
			Summary: "Security gate disabled by fail_on=never",
		}
	}

	var reasons []BlockingReason
	sevCounts := res.Breakdown.CountBySeverity

	if policy.FailOn == FailOnAny && res.Breakdown.ActiveFindings > 0 {
		reasons = append(reasons, BlockingReason{
			Code:      "active_findings",
			Message:   activeFindingsMessage(res.Breakdown),
			Count:     res.Breakdown.ActiveFindings,
			Threshold: 0,
		})
	}

	if policy.FailOn == FailOnConfirmed && res.Breakdown.ConfirmedFindings > 0 {
		reasons = append(reasons, BlockingReason{
			Code: "confirmed_findings",
			Message: fmt.Sprintf("%d confirmed finding(s) are not allowed by this policy (%d unreviewed finding(s) reported but not blocking)",
				res.Breakdown.ConfirmedFindings, res.Breakdown.NeedsReviewFindings),
			Count:     res.Breakdown.ConfirmedFindings,
			Threshold: 0,
		})
	}

	criticalHigh := sevCounts["CRITICAL"] + sevCounts["HIGH"]
	if policy.FailOn == FailOnCritical && criticalHigh > 0 {
		reasons = append(reasons, BlockingReason{
			Code:      "critical_or_high_findings",
			Message:   "Active CRITICAL/HIGH findings are not allowed by this policy",
			Severity:  "HIGH",
			Count:     criticalHigh,
			Threshold: 0,
		})
	}

	reasons = appendThresholdReason(reasons, "critical_threshold", "CRITICAL", sevCounts["CRITICAL"], policy.MaxCritical)
	reasons = appendThresholdReason(reasons, "high_threshold", "HIGH", sevCounts["HIGH"], policy.MaxHigh)
	reasons = appendThresholdReason(reasons, "medium_threshold", "MEDIUM", sevCounts["MEDIUM"], policy.MaxMedium)

	if policy.MinimumScore > 0 && res.Score < policy.MinimumScore {
		reasons = append(reasons, BlockingReason{
			Code:      "minimum_score",
			Message:   "Health Check score is below the required minimum",
			Count:     res.Score,
			Threshold: policy.MinimumScore,
		})
	}

	for _, source := range policy.BlockSources {
		key := normalizeKey(source)
		if key == "" {
			continue
		}
		if count := res.Breakdown.CountBySource[key]; count > 0 {
			reasons = append(reasons, BlockingReason{
				Code:      "blocked_source",
				Message:   fmt.Sprintf("Findings from source %q are blocked by policy", key),
				Source:    key,
				Count:     count,
				Threshold: 0,
			})
		}
	}

	for _, class := range policy.BlockClasses {
		key := normalizeKey(class)
		if key == "" {
			continue
		}
		if count := res.Breakdown.CountByClass[key]; count > 0 {
			reasons = append(reasons, BlockingReason{
				Code:      "blocked_class",
				Message:   fmt.Sprintf("Findings with class %q are blocked by policy", key),
				Class:     key,
				Count:     count,
				Threshold: 0,
			})
		}
	}

	if len(reasons) == 0 {
		return Verdict{
			Passed:  true,
			Status:  "passed",
			Summary: fmt.Sprintf("Security policy %q passed", policy.Profile),
		}
	}

	return Verdict{
		Passed:          false,
		Status:          "failed",
		Summary:         fmt.Sprintf("Security policy %q failed with %d blocking reason(s)", policy.Profile, len(reasons)),
		BlockingReasons: reasons,
	}
}

func appendThresholdReason(reasons []BlockingReason, code, severity string, count, threshold int) []BlockingReason {
	if threshold < 0 || count <= threshold {
		return reasons
	}
	return append(reasons, BlockingReason{
		Code:      code,
		Message:   fmt.Sprintf("Active %s findings exceed allowed threshold", severity),
		Severity:  severity,
		Count:     count,
		Threshold: threshold,
	})
}

// NormalizePolicy returns the canonical runtime representation for a policy.
func NormalizePolicy(policy Policy) Policy {
	return normalizePolicy(policy)
}

func normalizePolicy(policy Policy) Policy {
	if policy.Profile == "" {
		policy.Profile = PolicyBaseline
	}
	policy.Profile = normalizeProfile(policy.Profile)
	policy.FailOn = normalizeFailOn(policy.FailOn)
	if policy.MaxCritical == 0 && policy.MaxHigh == 0 && policy.MaxMedium == 0 && policy.Profile == PolicyBaseline {
		policy.MaxCritical = unlimitedThreshold
		policy.MaxHigh = unlimitedThreshold
		policy.MaxMedium = unlimitedThreshold
	}
	policy.BlockSources = normalizeList(policy.BlockSources)
	policy.BlockClasses = normalizeList(policy.BlockClasses)
	return policy
}

func normalizeProfile(profile string) string {
	switch normalizeKey(profile) {
	case PolicyStrict:
		return PolicyStrict
	case PolicyStandard:
		return PolicyStandard
	default:
		return PolicyBaseline
	}
}

func normalizeFailOn(failOn string) string {
	switch normalizeKey(failOn) {
	case FailOnAny:
		return FailOnAny
	case FailOnNever:
		return FailOnNever
	case FailOnConfirmed:
		return FailOnConfirmed
	default:
		return FailOnCritical
	}
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, item := range in {
		key := normalizeKey(item)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// activeFindingsMessage states why the gate blocked in terms a reader can act
// on. "Active findings are not allowed" next to "0 true positives" reads as a
// contradiction; naming the unreviewed count explains it.
func activeFindingsMessage(bd Breakdown) string {
	switch {
	case bd.ConfirmedFindings == 0 && bd.NeedsReviewFindings > 0:
		return fmt.Sprintf("%d finding(s) have not been reviewed yet. None are confirmed exploitable, but this policy requires every finding to be triaged (confirmed, or dismissed as a false positive / accepted risk) before the gate can pass",
			bd.NeedsReviewFindings)
	case bd.NeedsReviewFindings > 0:
		return fmt.Sprintf("%d confirmed and %d unreviewed finding(s) are open; this policy allows neither",
			bd.ConfirmedFindings, bd.NeedsReviewFindings)
	default:
		return fmt.Sprintf("%d confirmed finding(s) are open; this policy allows none", bd.ConfirmedFindings)
	}
}
