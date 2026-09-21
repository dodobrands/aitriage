// Package healthcheck implements the unified Security Health Check engine for a
// repository. It is the single source of truth for the repository's Information
// security posture score (0-100) and grade (A+..F).
//
// Unlike the legacy per-check scorer, the Health Check aggregates findings from
// ALL sources (core SAST, Semgrep, Trivy, Gitleaks, Bandit, NFR, Deploy, Network)
// and honours AI triage dispositions (False Positives never penalise the score).
//
// Design goals (see scoring_analysis.md):
//   - Multi-source aggregation, not core-only.
//   - False Positives / audit-ignored findings excluded from penalties.
//   - Positive scoring: good practices (PRESENT checks) grant a bonus.
//   - Deduplication: the same issue class at the same location counts once.
//   - Severity + source weighting: a real SQLi weighs more than a missing lockfile.
//   - Diminishing returns: one "terrible" component can no longer instantly zero
//     the whole repository; penalties saturate smoothly toward 100.
package healthcheck

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Finding is a source-agnostic, normalised issue used by the Health Check engine.
// Every concrete finding type (core.CheckResult, external.UnifiedFinding, NFR,
// Deploy, Network, ...) is mapped into this shape before scoring.
type Finding struct {
	Source   string // "core" | "semgrep" | "trivy" | "gitleaks" | "bandit" | "nfr" | "deploy" | "network" | ...
	Class    string // stable category key for dedup (rule ID / vuln class)
	Severity string // CRITICAL | HIGH | MEDIUM | LOW | INFO
	File     string
	Line     int
	Ignored  bool // true => excluded from penalties (audit-ignored OR AI False Positive)
	// NeedsReview marks a finding that no one has confirmed or dismissed yet.
	// It still counts as active — an unreviewed finding is unresolved work — but
	// the gate says so explicitly instead of implying the issue is proven.
	NeedsReview bool
}

// Positive represents a verified good security practice (e.g. a PRESENT core check).
// Positives grant a small, capped bonus to reward healthy repositories.
type Positive struct {
	ID string
}

// Input is the full set of signals fed into the Health Check.
type Input struct {
	Findings  []Finding
	Positives []Positive
}

// Breakdown explains how the final score was derived. It is serialised into the
// report so dashboards and CI can show the reasoning behind the number.
type Breakdown struct {
	BaseScore      int     `json:"base_score"`      // always 100
	Penalty        int     `json:"penalty"`         // points removed (post-saturation)
	Bonus          int     `json:"bonus"`           // points added for good practices
	RawWeight      float64 `json:"raw_weight"`      // total weighted penalty before saturation
	ActiveFindings int     `json:"active_findings"` // findings counted after dedup + ignore filter
	// ConfirmedFindings and NeedsReviewFindings partition ActiveFindings, so a
	// report can say "0 confirmed, 25 unreviewed" instead of leaving a reader to
	// wonder why a gate failed with nothing proven.
	ConfirmedFindings   int            `json:"confirmed_findings"`
	NeedsReviewFindings int            `json:"needs_review_findings"`
	IgnoredFindings     int            `json:"ignored_findings"`  // findings excluded (FP / audit-ignored)
	DedupedFindings     int            `json:"deduped_findings"`  // duplicates collapsed
	PenaltyBySource     map[string]int `json:"penalty_by_source"` // weighted penalty contribution per source
	CountBySeverity     map[string]int `json:"count_by_severity"` // active finding count per severity
	CountBySource       map[string]int `json:"count_by_source"`   // active finding count per source
	CountByClass        map[string]int `json:"count_by_class"`    // active finding count per class/rule
}

// Result is the outcome of a Health Check evaluation.
type Result struct {
	Score               int       `json:"score"`
	Grade               string    `json:"grade"`
	HasCriticalFailures bool      `json:"has_critical_failures"`
	Breakdown           Breakdown `json:"breakdown"`
	Policy              Policy    `json:"policy"`
	Verdict             Verdict   `json:"verdict"`
}

// severityWeight is the base penalty weight per severity bucket.
var severityWeight = map[string]float64{
	"CRITICAL": 18,
	"HIGH":     9,
	"MEDIUM":   3,
	"LOW":      1,
	"INFO":     0,
}

// defaultSeverityWeight is used when a finding's severity is unknown/empty.
const defaultSeverityWeight = 2

// sourceConfidence scales penalties by how directly a source maps to real,
// exploitable risk. Best-practice gaps (NFR) weigh less than concrete vulns.
var sourceConfidence = map[string]float64{
	"core":        1.0,
	"aitriage":    1.0,
	"securecoder": 1.0,
	"semgrep":     1.0,
	"bandit":      1.0,
	"gitleaks":    1.0,
	"trivy":       0.9,
	"deploy":      0.8,
	"network":     0.7,
	"nfr":         0.6,
}

const (
	// saturationScale controls how fast penalties approach the 100-point ceiling.
	// Higher => more linear; lower => saturates faster.
	saturationScale = 55.0
	// maxBonus caps the positive-practice bonus.
	maxBonus = 10
	// bonusPerPositive is the bonus granted per verified good practice.
	bonusPerPositive = 0.6
)

// confidenceFor returns the source confidence multiplier (defaults to 1.0).
func confidenceFor(source string) float64 {
	if c, ok := sourceConfidence[strings.ToLower(strings.TrimSpace(source))]; ok {
		return c
	}
	return 1.0
}

// weightFor returns the base severity weight (defaults to defaultSeverityWeight).
func weightFor(severity string) float64 {
	if w, ok := severityWeight[strings.ToUpper(strings.TrimSpace(severity))]; ok {
		return w
	}
	return defaultSeverityWeight
}

func effectiveWeight(f Finding) float64 {
	return weightFor(f.Severity) * confidenceFor(f.Source)
}

// dedupKey builds the deduplication key for a finding. Located findings dedup by
// class+file+line; location-less findings dedup by source+class so the same
// project-level rule firing twice (e.g. across two stacks) counts once.
func dedupKey(f Finding) string {
	class := strings.ToLower(strings.TrimSpace(f.Class))
	if f.File == "" && f.Line == 0 {
		return fmt.Sprintf("%s|%s", strings.ToLower(f.Source), class)
	}
	return fmt.Sprintf("%s|%s|%d", class, strings.ToLower(f.File), f.Line)
}

// Evaluate runs the full Health Check and returns the score, grade and breakdown.
func Evaluate(in Input) Result {
	bd := Breakdown{
		BaseScore:       100,
		PenaltyBySource: map[string]int{},
		CountBySeverity: map[string]int{},
		CountBySource:   map[string]int{},
		CountByClass:    map[string]int{},
	}

	// 1. Deduplicate findings. If one duplicate is ignored and another is still
	//    active, keep the active one so CI gates cannot be bypassed by input
	//    ordering. If both have the same ignore status, keep the stronger signal.
	seen := make(map[string]Finding, len(in.Findings))
	keys := make([]string, 0, len(in.Findings))
	for _, f := range in.Findings {
		key := dedupKey(f)
		prev, ok := seen[key]
		if ok {
			bd.DedupedFindings++
			switch {
			case prev.Ignored && !f.Ignored:
				seen[key] = f
			case prev.Ignored == f.Ignored && effectiveWeight(f) > effectiveWeight(prev):
				seen[key] = f
			}
			continue
		}
		seen[key] = f
		keys = append(keys, key)
	}
	deduped := make([]Finding, 0, len(seen))
	for _, key := range keys {
		deduped = append(deduped, seen[key])
	}

	// 2. Accumulate weighted penalties, skipping ignored (FP / audit-ignored).
	var rawWeight float64
	rawBySource := map[string]float64{}
	hasCritical := false
	for _, f := range deduped {
		if f.Ignored {
			bd.IgnoredFindings++
			continue
		}
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		bd.CountBySeverity[sev]++
		bd.ActiveFindings++
		if f.NeedsReview {
			bd.NeedsReviewFindings++
		} else {
			bd.ConfirmedFindings++
		}

		if sev == "CRITICAL" || sev == "HIGH" {
			hasCritical = true
		}

		w := effectiveWeight(f)
		rawWeight += w
		src := strings.ToLower(strings.TrimSpace(f.Source))
		if src == "" {
			src = "unknown"
		}
		class := strings.ToLower(strings.TrimSpace(f.Class))
		if class == "" {
			class = "unknown"
		}
		bd.CountBySource[src]++
		bd.CountByClass[class]++
		rawBySource[src] += w
	}

	// 3. Apply diminishing-returns saturation so heavy repos degrade smoothly
	//    instead of clamping instantly to zero.
	penalty := 100.0 * (1.0 - math.Exp(-rawWeight/saturationScale))

	// 4. Positive-practice bonus (capped). CI-safety: the bonus is suppressed
	//    whenever there is an active CRITICAL/HIGH finding, so good practices can
	//    never lift a repository over a fail-score gate while a real critical
	//    issue is open.
	bonus := math.Round(float64(len(in.Positives)) * bonusPerPositive)
	if bonus > maxBonus {
		bonus = maxBonus
	}
	if hasCritical {
		bonus = 0
	}

	score := int(math.Round(100.0 - penalty + bonus))
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	bd.RawWeight = math.Round(rawWeight*100) / 100
	bd.Penalty = int(math.Round(penalty))
	bd.Bonus = int(bonus)
	// Distribute the saturated penalty proportionally back to sources for display.
	if rawWeight > 0 {
		for src, w := range rawBySource {
			bd.PenaltyBySource[src] = int(math.Round(penalty * (w / rawWeight)))
		}
	}

	res := Result{
		Score:               score,
		Grade:               Grade(score),
		HasCriticalFailures: hasCritical,
		Breakdown:           bd,
	}
	return ApplyPolicy(res, DefaultPolicy())
}

// Grade maps a 0-100 score to a letter grade.
func Grade(score int) string {
	switch {
	case score >= 100:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 65:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// TopPenaltySources returns sources ordered by their penalty contribution,
// useful for "what hurt the score most" summaries.
func (r Result) TopPenaltySources() []string {
	type kv struct {
		src string
		pen int
	}
	pairs := make([]kv, 0, len(r.Breakdown.PenaltyBySource))
	for s, p := range r.Breakdown.PenaltyBySource {
		pairs = append(pairs, kv{s, p})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].pen > pairs[j].pen })
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.src)
	}
	return out
}
