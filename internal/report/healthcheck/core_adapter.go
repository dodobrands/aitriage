package healthcheck

import (
	"github.com/dodobrands/aitriage/internal/engine/core"
)

// FromCoreResults maps deterministic core SAST results into a Health Check Input.
//   - ABSENT checks become penalising Findings (respecting audit status).
//   - PRESENT checks become Positives (good-practice bonus).
//   - Manually triaged (ignored/checked) findings are flagged Ignored.
//   - Each finding's origin carries its rule's subcategory, so Assess can
//     tell a code-quality rule from a security rule.
func FromCoreResults(results []core.CheckResult) Input {
	in := Input{}
	for _, r := range results {
		switch r.Status {
		case core.Present:
			in.Positives = append(in.Positives, Positive{ID: r.ID})
		case core.Absent:
			ignored := r.AuditStatus == core.AuditStatusIgnored || r.AuditStatus == core.AuditStatusTriage
			in.Findings = append(in.Findings, Finding{
				Source:   "core",
				Class:    r.ID,
				Severity: r.Severity,
				File:     r.File,
				Line:     r.Line,
				Ignored:  ignored,
				// A deterministic scan produces hypotheses, not verdicts. Nobody
				// has confirmed these, so a report must not present them as
				// proven; only triage can move a finding out of this state.
				NeedsReview: !ignored,
				Origins:     []Origin{{Type: "core", Source: "core", RuleID: r.ID, Subcategory: r.Subcategory}},
			})
		}
	}
	return in
}

// Calculate preserves the legacy scorer signature for the core-only scan path.
// It now routes through the unified Health Check engine under the default
// policy.
func Calculate(results []core.CheckResult) (hasCriticalFailures bool, score int) {
	res := Assess(FromCoreResults(results), DefaultPolicy())
	return res.HasCriticalFailures, res.Score
}
