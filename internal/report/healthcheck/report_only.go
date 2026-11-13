package healthcheck

import "strings"

// Kinds of findings a policy can report without scoring or gating them. They
// are the keys of Breakdown.ReportOnlyByKind.
const (
	// ReportOnlyIaC is an IaC misconfiguration reported by `trivy config`,
	// governed by iac_findings.
	ReportOnlyIaC = "iac"
	// ReportOnlyQuality is a finding about code quality, maintainability or
	// hygiene with no direct security impact, governed by quality_findings.
	ReportOnlyQuality = "quality"
)

// SubcategoryQuality is the metadata.subcategory of a rule that reports code
// quality, maintainability or hygiene with no direct security impact.
const SubcategoryQuality = "quality"

// kindMisconfiguration is the marker `trivy config` results carry
// (external.KindMisconfiguration).
const kindMisconfiguration = "misconfiguration"

// Origin is one scanner report behind a finding, described as far as the
// report-only rule needs it.
type Origin struct {
	// Type is the family of the check: "core", "external", "nfr", "deploy".
	Type string
	// Source is the scanner that reported it: "aitriage" or "core" for the
	// built-in engine, "trivy", "bandit", "nfr", ...
	Source string
	// RuleID is the rule, check or test id as the scanner reported it.
	RuleID string
	// Kind is the scanner's own marker of the report: "misconfiguration" for
	// an IaC misconfiguration. Never inferred from the rule id.
	Kind string
	// Subcategory is the metadata.subcategory of the rule that produced the
	// report, for a rule of the built-in catalog or of a rule pack.
	Subcategory string
}

// qualityChecks lists checks of other scanners that report code quality or
// hygiene with no direct security impact, by check family and upper-cased id.
// Rules of the built-in catalog declare it in metadata.subcategory instead.
//
// A swallowed exception (Bandit B110 and B112, FAST-LAZY-EXC) is not on it:
// `except Exception: pass` around a token check turns a failed check into a
// pass, so the finding is scored and gated whatever quality_findings says.
var qualityChecks = map[string]map[string]bool{
	// No .env.example documents the environment variables: documentation
	// hygiene. A .env file tracked by git (NFR-ENV-002) is not on this list.
	"nfr": {"NFR-ENV-001": true},
}

// OriginKind returns the report-only kind one scanner report belongs to:
// ReportOnlyIaC for a Trivy IaC misconfiguration, ReportOnlyQuality for a
// code-quality rule or check, and "" for any other report.
func OriginKind(o Origin) string {
	source := strings.ToLower(strings.TrimSpace(o.Source))
	if source == "trivy" && strings.EqualFold(strings.TrimSpace(o.Kind), kindMisconfiguration) {
		return ReportOnlyIaC
	}
	if strings.EqualFold(strings.TrimSpace(o.Subcategory), SubcategoryQuality) {
		return ReportOnlyQuality
	}
	family := source
	if strings.EqualFold(strings.TrimSpace(o.Type), "nfr") {
		// The triage graph labels NFR checks with source "aitriage".
		family = "nfr"
	}
	if qualityChecks[family][strings.ToUpper(strings.TrimSpace(o.RuleID))] {
		return ReportOnlyQuality
	}
	return ""
}

// ReportOnlyKind returns the kind under which policy reports f without
// scoring or gating it, or "" when f is scored and gated like any other
// finding. All of these must hold:
//
//   - Every scanner report behind f (its Origins) is of the same report-only
//     kind, and the policy reports that kind: a finding another detector
//     also reported, such as DOCKER-NO-USER merged with Trivy's DS-0002,
//     gates as it always did.
//   - A code-quality finding is LOW or INFO. A rule pack can label any rule
//     quality; a more severe finding is scored and gated whatever its label.
//   - No block_sources or block_classes entry names f: an explicit entry
//     always gates. The names are matched as the gate matches them.
func ReportOnlyKind(policy Policy, f Finding) string {
	return reportOnlyKind(normalizePolicy(policy), f)
}

// reportOnlyKind is ReportOnlyKind under a normalized policy.
func reportOnlyKind(policy Policy, f Finding) string {
	kind := originsKind(originsOf(f))
	switch kind {
	case ReportOnlyIaC:
		if policy.IaCFindings != IaCFindingsReport {
			return ""
		}
	case ReportOnlyQuality:
		if policy.QualityFindings != QualityFindingsReport || !qualitySeverity(f.Severity) {
			return ""
		}
	default:
		return ""
	}
	if namedByBlockLists(policy, f) {
		return ""
	}
	return kind
}

// originsKind returns the report-only kind every one of origins belongs to,
// or "" when they are of different kinds or there are none.
func originsKind(origins []Origin) string {
	if len(origins) == 0 {
		return ""
	}
	kind := OriginKind(origins[0])
	for _, origin := range origins[1:] {
		if OriginKind(origin) != kind {
			return ""
		}
	}
	return kind
}

// qualitySeverity reports whether a finding is mild enough to be reported
// as code quality: LOW or INFO. Any other severity, an unknown one included,
// is scored and gated.
func qualitySeverity(severity string) bool {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityLow, "INFO":
		return true
	default:
		return false
	}
}

// namedByBlockLists reports whether a block_sources or block_classes entry
// names f: its class, a rule behind it (an earlier id of a split rule
// included) or a scanner that reported it. f is counted the way Evaluate
// counts an active finding and matched by the gate's own namedBlockingReasons,
// so a finding the gate would block by name is never left out of it.
func namedByBlockLists(policy Policy, f Finding) bool {
	if len(policy.BlockSources) == 0 && len(policy.BlockClasses) == 0 {
		return false
	}
	var bd Breakdown
	bd.countNames(f)
	return len(namedBlockingReasons(bd, policy)) > 0
}

// Assess scores the findings under policy and attaches the verdict. It marks
// the findings policy reports without scoring or gating them (see
// ReportOnlyKind) before evaluating, so iac_findings and quality_findings
// mean the same in every command: the deterministic scan, the full scan and
// AI triage all score through it.
func Assess(in Input, policy Policy) Result {
	policy = normalizePolicy(policy)
	findings := make([]Finding, len(in.Findings))
	for i, f := range in.Findings {
		f.ReportOnlyKind = reportOnlyKind(policy, f)
		f.ReportOnly = f.ReportOnlyKind != ""
		findings[i] = f
	}
	in.Findings = findings
	return ApplyPolicy(Evaluate(in), policy)
}

// originsOf returns the reports behind a finding. A finding without Origins
// stands for one report: its Source and Class.
func originsOf(f Finding) []Origin {
	if len(f.Origins) > 0 {
		return f.Origins
	}
	return []Origin{{Source: f.Source, RuleID: f.Class}}
}
