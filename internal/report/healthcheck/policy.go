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

	// ReasonTriageIncomplete is the blocking reason recorded when AI triage did
	// not finish. It applies under every fail_on except never: a gate that could
	// pass because the provider failed would turn an outage into an approval.
	ReasonTriageIncomplete = "triage_incomplete"
)

// Severity floors accepted by confirmed_min_severity, weakest first.
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Values of iac_findings: whether IaC misconfigurations (Trivy `config`
// results, which earlier releases silently dropped) gate.
const (
	// IaCFindingsReport triages and reports them, but keeps them out of the
	// score and the gate verdict. It is the default throughout v1, so that
	// findings an upgrade starts reporting do not break existing gates; a
	// default change is a breaking change (see the compatibility policy in
	// CONTRIBUTING.md).
	IaCFindingsReport = "report"
	// IaCFindingsBlock scores and gates them like any other finding.
	IaCFindingsBlock = "block"
)

// Values of quality_findings: whether findings about code quality,
// maintainability or hygiene with no direct security impact gate. They come
// from built-in rules with metadata.subcategory quality and from the checks
// of other scanners listed in qualityChecks.
const (
	// QualityFindingsReport triages and reports them, but keeps them out of
	// the score and the gate verdict. The default: a security score should
	// not move with the size of a file or a swallowed exception.
	QualityFindingsReport = "report"
	// QualityFindingsBlock scores and gates them like any other finding,
	// as every release before quality_findings did.
	QualityFindingsBlock = "block"
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
	// ConfirmedMinSeverity narrows fail_on=confirmed to confirmed findings at
	// or above this severity (LOW, the default, keeps every confirmed finding
	// blocking). It has no effect under any other fail_on.
	ConfirmedMinSeverity string `json:"confirmed_min_severity,omitempty"`
	// FPCriticalRequiresHighConfidence accepts a model's False Positive for a
	// CRITICAL finding only when the model reports high confidence; anything
	// less is kept as Needs Manual Review. It changes verdicts, not the gate.
	FPCriticalRequiresHighConfidence bool `json:"fp_critical_requires_high_confidence,omitempty"`
	// IaCFindings is IaCFindingsReport (the default) or IaCFindingsBlock. It
	// applies to findings every report of which is an IaC misconfiguration;
	// a finding another detector also reported gates as before. Assess marks
	// such findings Finding.ReportOnly.
	IaCFindings string `json:"iac_findings,omitempty"`
	// QualityFindings is QualityFindingsReport (the default) or
	// QualityFindingsBlock. It applies to findings every report of which is
	// a code-quality finding (see ReportOnlyKind); a finding a security rule
	// also reported gates as before.
	QualityFindings string `json:"quality_findings,omitempty"`
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

	if res.Breakdown.TriageFailedFindings > 0 {
		reasons = append(reasons, BlockingReason{
			Code: ReasonTriageIncomplete,
			Message: fmt.Sprintf("AI triage did not complete: %d finding(s) have no verdict because the LLM provider failed or returned no usable verdicts. The gate cannot pass on an incomplete triage; re-run once the provider works",
				res.Breakdown.TriageFailedFindings),
			Count:     res.Breakdown.TriageFailedFindings,
			Threshold: 0,
		})
	}

	if policy.FailOn == FailOnAny && res.Breakdown.ActiveFindings > 0 {
		reasons = append(reasons, BlockingReason{
			Code:      "active_findings",
			Message:   activeFindingsMessage(res.Breakdown),
			Count:     res.Breakdown.ActiveFindings,
			Threshold: 0,
		})
	}

	if policy.FailOn == FailOnConfirmed {
		if blocking := confirmedAtOrAbove(res.Breakdown, policy.ConfirmedMinSeverity); blocking > 0 {
			reasons = append(reasons, BlockingReason{
				Code:      "confirmed_findings",
				Message:   confirmedFindingsMessage(res.Breakdown, policy.ConfirmedMinSeverity, blocking),
				Severity:  confirmedSeverityLabel(policy.ConfirmedMinSeverity),
				Count:     blocking,
				Threshold: 0,
			})
		}
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
		if count := blockedClassCount(res.Breakdown, key); count > 0 {
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

// blockedClassCount counts the active findings a block_classes entry names. An
// entry may be a canonical class ("hardcoded_secret", or "hardcoded-secret" as
// the configuration examples spell it) or a rule id, which is what classes
// were before findings of several detectors were merged: a policy written
// then must keep blocking the findings it blocked.
func blockedClassCount(bd Breakdown, key string) int {
	count := bd.CountByClass[key]
	if c, ok := LookupClass(key); ok && bd.CountByClass[c.Key] > count {
		count = bd.CountByClass[c.Key]
	}
	if n := bd.CountByRule[key]; n > count {
		count = n
	}
	return count
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
	policy.ConfirmedMinSeverity = NormalizeConfirmedMinSeverity(policy.ConfirmedMinSeverity)
	policy.IaCFindings = NormalizeIaCFindings(policy.IaCFindings)
	policy.QualityFindings = NormalizeQualityFindings(policy.QualityFindings)
	return policy
}

// NormalizeIaCFindings returns the canonical iac_findings mode. Empty is the
// default, report. An unrecognised value becomes block: a typo must fall back
// to the strict reading, not the loose one.
func NormalizeIaCFindings(value string) string {
	if strings.TrimSpace(value) == "" {
		return IaCFindingsReport
	}
	if mode, ok := ParseIaCFindings(value); ok {
		return mode
	}
	return IaCFindingsBlock
}

// ParseIaCFindings reports whether value names a supported iac_findings mode.
func ParseIaCFindings(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case IaCFindingsReport:
		return IaCFindingsReport, true
	case IaCFindingsBlock:
		return IaCFindingsBlock, true
	default:
		return "", false
	}
}

// NormalizeQualityFindings returns the canonical quality_findings mode.
// Empty is the default, report. An unrecognised value becomes block: a typo
// must fall back to the strict reading, not the loose one.
func NormalizeQualityFindings(value string) string {
	if strings.TrimSpace(value) == "" {
		return QualityFindingsReport
	}
	if mode, ok := ParseQualityFindings(value); ok {
		return mode
	}
	return QualityFindingsBlock
}

// ParseQualityFindings reports whether value names a supported
// quality_findings mode.
func ParseQualityFindings(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case QualityFindingsReport:
		return QualityFindingsReport, true
	case QualityFindingsBlock:
		return QualityFindingsBlock, true
	default:
		return "", false
	}
}

// NormalizeConfirmedMinSeverity returns the canonical severity floor. Empty
// and unrecognised values become LOW: the floor can only ever relax the gate,
// so a typo must fall back to the strictest reading rather than the loosest.
func NormalizeConfirmedMinSeverity(value string) string {
	if severity, ok := ParseConfirmedMinSeverity(value); ok {
		return severity
	}
	return SeverityLow
}

// ParseConfirmedMinSeverity reports whether value names a supported floor.
func ParseConfirmedMinSeverity(value string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityCritical:
		return SeverityCritical, true
	default:
		return "", false
	}
}

// severityFloorRank orders severities for the floor; higher is more severe.
func severityFloorRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case "INFO":
		return 0
	default:
		// A severity nobody can rank cannot be shown to sit below the floor,
		// so it is treated as the most severe one.
		return 4
	}
}

// confirmedAtOrAbove counts the confirmed findings that block under the
// floor. LOW keeps the historical behaviour: every confirmed finding counts,
// whatever its severity label.
func confirmedAtOrAbove(bd Breakdown, floor string) int {
	floor = NormalizeConfirmedMinSeverity(floor)
	if floor == SeverityLow {
		return bd.ConfirmedFindings
	}
	minRank := severityFloorRank(floor)
	count := 0
	for severity, n := range bd.ConfirmedBySeverity {
		if severityFloorRank(severity) >= minRank {
			count += n
		}
	}
	return count
}

func confirmedSeverityLabel(floor string) string {
	if floor = NormalizeConfirmedMinSeverity(floor); floor == SeverityLow {
		return ""
	}
	return floor
}

func confirmedFindingsMessage(bd Breakdown, floor string, blocking int) string {
	reviewNote := unreviewedNote(bd)
	if floor = NormalizeConfirmedMinSeverity(floor); floor == SeverityLow {
		return fmt.Sprintf("%d confirmed finding(s) are not allowed by this policy (%s reported but not blocking)",
			blocking, reviewNote)
	}
	return fmt.Sprintf("%d confirmed finding(s) at or above %s are not allowed by this policy (%d confirmed below %s and %s reported but not blocking)",
		blocking, floor, bd.ConfirmedFindings-blocking, floor, reviewNote)
}

// unreviewedNote names the unreviewed findings and, separately, the ones the
// model never classified, so a reader can tell "unsure" from "never seen".
func unreviewedNote(bd Breakdown) string {
	if bd.UnclassifiedFindings > 0 {
		return fmt.Sprintf("%d unreviewed finding(s), %d of them never classified by the model,",
			bd.NeedsReviewFindings, bd.UnclassifiedFindings)
	}
	return fmt.Sprintf("%d unreviewed finding(s)", bd.NeedsReviewFindings)
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
		return fmt.Sprintf("%d finding(s) have not been reviewed yet%s. None are confirmed exploitable, but this policy requires every finding to be triaged (confirmed, or dismissed as a false positive / accepted risk) before the gate can pass",
			bd.NeedsReviewFindings, unclassifiedClause(bd))
	case bd.NeedsReviewFindings > 0:
		return fmt.Sprintf("%d confirmed and %d unreviewed finding(s) are open%s; this policy allows neither",
			bd.ConfirmedFindings, bd.NeedsReviewFindings, unclassifiedClause(bd))
	default:
		return fmt.Sprintf("%d confirmed finding(s) are open; this policy allows none", bd.ConfirmedFindings)
	}
}

// unclassifiedClause calls out unreviewed findings that have no model verdict
// at all: re-running triage may resolve them, reviewing them by hand will.
func unclassifiedClause(bd Breakdown) string {
	if bd.UnclassifiedFindings == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d of them were never classified by the model)", bd.UnclassifiedFindings)
}

// UnreviewedScoreNote explains a low score next to a gate that passed:
// unreviewed findings count in full toward the score, while the gate may not
// block on them at all. It returns "" unless the gate passed and unreviewed
// findings cause more than half of the penalty.
func UnreviewedScoreNote(res Result) string {
	bd := res.Breakdown
	if !res.Verdict.Passed || bd.NeedsReviewFindings == 0 || bd.Penalty == 0 || 2*bd.NeedsReviewPenalty <= bd.Penalty {
		return ""
	}
	share := fmt.Sprintf("%d of the %d penalty points", bd.NeedsReviewPenalty, bd.Penalty)
	if bd.NeedsReviewPenalty >= bd.Penalty {
		share = fmt.Sprintf("all %d penalty points", bd.Penalty)
	}
	return fmt.Sprintf("Score %d/100: %d finding(s) await review and count in full (%s), but %s.",
		res.Score, bd.NeedsReviewFindings, share, passingGateScope(res.Policy, res.Score))
}

// passingGateScope says what a gate that passed blocks on.
func passingGateScope(policy Policy, score int) string {
	policy = normalizePolicy(policy)
	var scope string
	switch policy.FailOn {
	case FailOnNever:
		return "`fail_on: never` never blocks"
	case FailOnConfirmed:
		scope = "`fail_on: confirmed` blocks only confirmed findings"
		if floor := NormalizeConfirmedMinSeverity(policy.ConfirmedMinSeverity); floor != SeverityLow {
			scope += " at or above " + floor
		}
	case FailOnCritical:
		scope = "`fail_on: critical` blocks only CRITICAL and HIGH findings"
	default:
		scope = fmt.Sprintf("`fail_on: %s` passed", policy.FailOn)
	}
	if policy.MinimumScore > 0 {
		scope += fmt.Sprintf(", and %d meets `minimum_score: %d`", score, policy.MinimumScore)
	}
	return scope
}
