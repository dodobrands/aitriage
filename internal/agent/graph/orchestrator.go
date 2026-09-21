package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agentcontext "github.com/dodobrands/aitriage/internal/agent/context"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// ErrNoLLMClient is returned when the pipeline is asked to run without a usable
// LLM client. Every stage of the graph issues Chat calls, so this is a caller
// contract violation rather than a recoverable runtime condition — it is
// reported as a plain error so callers surface it instead of panicking.
var ErrNoLLMClient = errors.New("no LLM client configured: the SecureCoder pipeline requires an LLM provider")

// Run Orchestrates the full SecureCoder-enhanced pipeline:
//
//	enrichFindings → buildThreatModel → runPoCVerification →
//	computeHealthCheck → generateReport → generateSummary → generateAIFixSpec
func Run(ctx context.Context, state *AgentState, llmClient llm.Client) error {
	if llmClient == nil {
		return ErrNoLLMClient
	}

	// Step 0: Gather repository context (reads files from disk, no LLM)
	fmt.Fprintf(os.Stderr, "📂 Gathering Repository Context...\n")
	reportRunwayProgress(state, 1, "preparing_context")
	gatherRepoContext(state)

	fmt.Fprintf(os.Stderr, "🤖 Context Enrichment...\n")
	enrichFindings(state)

	// SecureCoder Step 1: Threat Model (classifies each finding as TP/FP/NR)
	fmt.Fprintf(os.Stderr, "🏗️ Building Threat Model (SecureCoder)...\n")
	reportRunwayProgress(state, 1, "building_threat_model")
	if err := buildThreatModel(ctx, state, llmClient); err != nil {
		return fmt.Errorf("threat-model analysis failed: %w", err)
	}

	artifactCache := newArtifactBundleCache()
	artifactKey, artifactKeyMiss := buildArtifactCacheKey(state)
	artifactCacheHit := false
	if artifactCache.enabled {
		if artifactKeyMiss != "" {
			artifactCache.stats.MissReason = artifactKeyMiss
			fmt.Fprintf(os.Stderr, "   ℹ️ Artifact cache miss: %s\n", artifactKeyMiss)
		} else {
			artifactCache.stats.Key = artifactKey
			fmt.Fprintf(os.Stderr, "   ℹ️ Artifact cache key: %s (loaded_entries=%d)\n", artifactKey, artifactCache.stats.LoadedEntries)
			if artifactCache.Restore(state, artifactKey) {
				artifactCacheHit = true
				fmt.Fprintf(os.Stderr, "   ✅ Artifact cache exact hit: restored PoC/report/fixspec bundle\n")
			} else {
				fmt.Fprintf(os.Stderr, "   ℹ️ Artifact cache miss: %s\n", firstNonEmpty(artifactCache.stats.MissReason, "key_miss"))
			}
		}
	}

	if !artifactCacheHit {
		// SecureCoder Step 2: PoC Verification (proves exploitability of True Positives)
		fmt.Fprintf(os.Stderr, "🧪 PoC Verification (SecureCoder)...\n")
		reportRunwayProgress(state, 2, "verifying_poc")
		if err := runPoCVerification(ctx, state, llmClient); err != nil {
			return fmt.Errorf("PoC verification failed: %w", err)
		}
	}

	// Health Check: compute AFTER all triage is complete (Threat Model + PoC).
	// This ensures the CI gate verdict uses the final, authoritative dispositions.
	fmt.Fprintf(os.Stderr, "🩺 Computing Security Health Check (all sources, FP-aware)...\n")
	reportRunwayProgress(state, 3, "computing_health_check")
	computeHealthCheck(state)
	fmt.Fprintf(os.Stderr, "   ✅ Health Check: %d/100 (%s) — %d active (%d confirmed, %d unreviewed), %d ignored (FP), %d deduped\n",
		state.HealthCheck.Score, state.HealthCheck.Grade,
		state.HealthCheck.Breakdown.ActiveFindings,
		state.HealthCheck.Breakdown.ConfirmedFindings,
		state.HealthCheck.Breakdown.NeedsReviewFindings,
		state.HealthCheck.Breakdown.IgnoredFindings,
		state.HealthCheck.Breakdown.DedupedFindings)

	if !artifactCacheHit {
		fmt.Fprintf(os.Stderr, "🤖 Generating Security Report (CS-XXX-NNN format)...\n")
		reportRunwayProgress(state, 4, "generating_report")
		if err := generateReport(ctx, state, llmClient); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "🤖 Generating AI Fix Specification...\n")
		reportRunwayProgress(state, 5, "generating_fix_spec")
		if err := generateAIFixSpec(ctx, state, llmClient); err != nil {
			return err
		}

		// Canonical integrity: never publish or cache report/fixspec that drift
		// from the authoritative dispositions. On failure, they are rebuilt
		// deterministically (the gate already uses canonical state, so it is
		// unaffected).
		if enforceArtifactIntegrity(state) {
			artifactCache.stats.IntegrityFailed = true
			fmt.Fprintf(os.Stderr, "   ⚠️ Artifact integrity check failed: report/fixspec rebuilt deterministically; bundle NOT cached.\n")
		}

		if artifactCache.enabled && artifactKeyMiss == "" {
			uncached := countUncachedVerdicts(state)
			artifactCache.stats.UncachedVerdicts = uncached
			switch {
			case artifactCache.stats.IntegrityFailed:
				// Do not cache a run whose generated artifacts had to be
				// corrected; keep the cache honest and reusable only for clean
				// runs.
				artifactCache.stats.EligibilitySkipped = true
				artifactCache.stats.MissReason = "integrity_failed_not_eligible"
				fmt.Fprintf(os.Stderr, "   ⚠️ Artifact cache: integrity failure; bundle NOT stored (not eligible for exact reuse).\n")
			case uncached > 0:
				// Strict fallback mode: a run with uncached verdicts (NR-fallback
				// or sensitive-skip) can never produce an exact artifact hit — the
				// next run re-classifies those findings and the disposition hashes
				// change. Storing the bundle would only waste cache and mislead.
				// The verdict cache is untouched and still gives partial reuse.
				artifactCache.stats.EligibilitySkipped = true
				artifactCache.stats.MissReason = "fallback_present_not_eligible"
				fmt.Fprintf(os.Stderr, "   ⚠️ Artifact cache: %d unique verdicts are not backed by the verdict cache (NR-fallback or sensitive-skip); bundle NOT stored (not eligible for exact reuse). Verdict cache still saved.\n", uncached)
			default:
				artifactCache.Store(state, artifactKey)
				artifactCache.Save()
			}
			stats := artifactCache.Stats()
			fmt.Fprintf(os.Stderr, "   ℹ️ Artifact cache store: stores=%d saved=%t skipped_sensitive=%d uncached_verdicts=%d eligibility_skipped=%t\n",
				stats.Stores, stats.Saved, stats.SkippedSensitive, stats.UncachedVerdicts, stats.EligibilitySkipped)
		}
	}
	state.ArtifactCacheStats = artifactCache.Stats()

	// Generate the final summary only after every required AI stage has finished,
	// so its usage and findings cannot be partial or pre-triage.
	fmt.Fprintf(os.Stderr, "📋 Generating Actionable Summary (TP/NR only)...\n")
	reportRunwayProgress(state, 6, "generating_summary")
	if err := generateSummary(state); err != nil {
		return fmt.Errorf("failed to generate actionable handoff: %w", err)
	}

	// Print LLM usage summary
	u := state.TotalUsage
	if u.TotalTokens > 0 {
		fmt.Fprintf(os.Stderr, "\nLLM usage (provider reported): %s. Cost is not estimated because it depends on provider, model, caching, and billing tier.\n",
			formatLLMUsage(u))
	}

	reportRunwayProgress(state, 7, "completed")
	return nil
}

func reportRunwayProgress(state *AgentState, step int, progressMessage string) {
	if state != nil && state.RunwayProgress != nil {
		state.RunwayProgress(step, progressMessage)
	}
}

// gatherRepoContext reads the repository from disk and builds structured context.
func gatherRepoContext(state *AgentState) {
	state.RepoContext = agentcontext.BuildRepoContext(state.ProjectPath)

	keyCount := 0
	if state.RepoContext != nil {
		keyCount = len(state.RepoContext.KeyFiles)
	}
	fmt.Fprintf(os.Stderr, "   ✅ Tree built, %d key files read, stack: %s\n",
		keyCount, state.RepoContext.Stack)
}

func enrichFindings(state *AgentState) {
	var enriched []EnrichedFinding

	for _, f := range state.CoreFindings {
		enriched = append(enriched, EnrichedFinding{
			ID:       f.ID,
			Type:     "core",
			Source:   "aitriage",
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Message:  fmt.Sprintf("%s: %s", f.Name, f.Evidence),
			Snippet:  extractFullContext(state.ProjectPath, f.File, f.Line),
		})
	}
	for _, f := range state.ExternalFindings {
		enriched = append(enriched, EnrichedFinding{
			ID:       f.RuleID,
			Type:     "external",
			Source:   f.Source,
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Message:  fmt.Sprintf("[%s] %s", f.Source, f.Message),
			Snippet:  extractFullContext(state.ProjectPath, f.File, f.Line),
		})
	}
	// Add other findings without snippets or with basic info
	for _, f := range state.NFRFindings {
		enriched = append(enriched, EnrichedFinding{
			ID:       f.RuleID,
			Type:     "nfr",
			Source:   "aitriage",
			Severity: f.Severity,
			Message:  fmt.Sprintf("%s: %s", f.Name, f.Message),
		})
	}
	for _, f := range state.DeployFindings {
		enriched = append(enriched, EnrichedFinding{
			ID:       f.Issue,
			Type:     "deploy",
			Source:   "aitriage",
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Message:  fmt.Sprintf("%s. Advice: %s", f.Issue, f.Advice),
			Snippet:  extractFullContext(state.ProjectPath, f.File, f.Line),
		})
	}
	for _, f := range state.NetworkFindings {
		enriched = append(enriched, EnrichedFinding{
			ID:       fmt.Sprintf("port-%d", f.Port),
			Type:     "network",
			Source:   "aitriage",
			Severity: f.Severity,
			Message:  fmt.Sprintf("Port %d (%s): %s", f.Port, f.Service, f.Message),
		})
	}

	enriched = mergeSemanticFindings(enriched)
	sortEnrichedFindings(enriched)

	// Assign CS-XXX-NNN vulnerability IDs after canonical sorting so IDs remain
	// stable when scanner result order varies between otherwise identical runs.
	assignVulnIDs(enriched)

	state.EnrichedFindings = enriched

	// Map into batches of 5
	var targetFindings []EnrichedFinding
	if len(enriched) > 50 {
		for _, e := range enriched {
			if strings.ToUpper(e.Severity) == "HIGH" || strings.ToUpper(e.Severity) == "CRITICAL" {
				targetFindings = append(targetFindings, e)
			}
		}
	} else {
		targetFindings = enriched
	}

	chunkSize := 5
	for i := 0; i < len(targetFindings); i += chunkSize {
		end := i + chunkSize
		if end > len(targetFindings) {
			end = len(targetFindings)
		}
		state.Batches = append(state.Batches, targetFindings[i:end])
	}
}

// computeHealthCheck recomputes the authoritative Security Health Check across ALL
// scanner sources (core, external, NFR, deploy, network) and applies AI triage
// dispositions: findings classified as False Positive are excluded from the
// penalty. The result becomes the canonical SecurityScore/SecurityGrade.
func computeHealthCheck(state *AgentState) {
	// EnrichedFindings is the canonical, semantic-deduplicated inventory shown to
	// the model and written to artifacts. Score that same inventory so the health
	// gate cannot count Core/NFR/external aliases as separate vulnerabilities.
	ignored := make(map[int]bool)
	// Anything not classified as a confirmed True Positive is unreviewed work.
	// Tracking it separately lets the gate explain itself instead of reporting
	// "active findings" next to "0 true positives".
	unreviewed := make(map[int]bool)
	for _, d := range state.FindingDispositions {
		if d.FindingIndex < 0 || d.FindingIndex >= len(state.EnrichedFindings) {
			continue
		}
		switch d.Disposition {
		case "False Positive":
			ignored[d.FindingIndex] = true
		case "True Positive":
			// confirmed; neither ignored nor unreviewed
		default:
			unreviewed[d.FindingIndex] = true
		}
	}
	ignoredCore := make(map[string]bool)
	for _, finding := range state.CoreFindings {
		if finding.AuditStatus == core.AuditStatusIgnored || finding.AuditStatus == core.AuditStatusTriage {
			ignoredCore[hcKey(finding.ID, finding.File, finding.Line)] = true
		}
	}

	in := healthcheck.Input{}
	for _, r := range state.CoreFindings {
		if r.Status == core.Present {
			in.Positives = append(in.Positives, healthcheck.Positive{ID: r.ID})
		}
	}
	for i, f := range state.EnrichedFindings {
		// A listening port describes the machine AITriage ran on, not the code
		// under audit. Counting it would make a repository's score depend on
		// what happened to be running on a developer's laptop.
		if f.Type == "network" {
			continue
		}
		source := strings.TrimSpace(f.Source)
		if source == "" {
			source = f.Type
		}
		class := semanticFindingClass(f)
		if class == "" {
			class = f.ID
		}
		isIgnored := ignored[i]
		if !isIgnored && len(f.Origins) == 1 && f.Origins[0].Type == "core" {
			isIgnored = ignoredCore[hcKey(f.Origins[0].RuleID, f.File, f.Line)]
		}
		// With no dispositions at all (a scan that never ran AI triage), every
		// finding is by definition unreviewed.
		isUnreviewed := unreviewed[i] || len(state.FindingDispositions) == 0

		in.Findings = append(in.Findings, healthcheck.Finding{
			Source:      source,
			Class:       class,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Ignored:     isIgnored,
			NeedsReview: isUnreviewed,
		})
	}

	res := healthcheck.ApplyPolicy(healthcheck.Evaluate(in), state.Policy)
	state.HealthCheck = res
	state.SecurityScore = res.Score
	state.SecurityGrade = res.Grade
}

func mergeSemanticFindings(findings []EnrichedFinding) []EnrichedFinding {
	merged := make([]EnrichedFinding, 0, len(findings))
	positions := make(map[string]int)
	for _, finding := range findings {
		finding.Origins = mergeOrigins(finding.Origins, []FindingOrigin{originOf(finding)})
		key := semanticFindingKey(finding)
		if key == "" {
			merged = append(merged, finding)
			continue
		}
		if pos, ok := positions[key]; ok {
			current := merged[pos]
			origins := mergeOrigins(current.Origins, finding.Origins)
			if shouldPreferSemanticRepresentative(finding, current) {
				finding.Origins = origins
				merged[pos] = finding
			} else {
				current.Origins = origins
				if severitySortRank(finding.Severity) < severitySortRank(current.Severity) {
					current.Severity = finding.Severity
				}
				if current.File == "" && finding.File != "" {
					current.File, current.Line, current.Snippet = finding.File, finding.Line, finding.Snippet
				}
				merged[pos] = current
			}
			continue
		}
		positions[key] = len(merged)
		merged = append(merged, finding)
	}
	return merged
}

func semanticFindingClass(f EnrichedFinding) string {
	switch strings.ToUpper(strings.TrimSpace(f.ID)) {
	case "FAST-LAZY-EXC", "B110":
		return "exception_swallow"
	case "FAST-AUTH", "NFR-API-003":
		return "missing_authentication"
	case "FAST-RATELIMIT", "NFR-API-001":
		return "missing_rate_limiting"
	case "FAST-CORS", "NFR-API-002":
		return "missing_cors_policy"
	default:
		return ""
	}
}

func semanticFindingKey(f EnrichedFinding) string {
	class := semanticFindingClass(f)
	if class == "" {
		return "exact|" + Fingerprint(f)
	}
	if f.File != "" || f.Line != 0 {
		return class + "|" + normalizePath(f.File) + "|" + fmt.Sprint(f.Line)
	}
	return class + "|project"
}

func originOf(f EnrichedFinding) FindingOrigin {
	source := strings.TrimSpace(f.Source)
	if source == "" {
		source = f.Type
	}
	return FindingOrigin{Type: f.Type, Source: source, RuleID: f.ID}
}

func mergeOrigins(groups ...[]FindingOrigin) []FindingOrigin {
	seen := make(map[string]FindingOrigin)
	for _, group := range groups {
		for _, origin := range group {
			key := strings.ToLower(origin.Type + "\x00" + origin.Source + "\x00" + origin.RuleID)
			seen[key] = origin
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]FindingOrigin, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func shouldPreferSemanticRepresentative(candidate, current EnrichedFinding) bool {
	priority := func(f EnrichedFinding) int {
		switch strings.ToLower(f.Type) {
		case "core":
			return 3
		case "external":
			return 2
		case "nfr":
			return 1
		default:
			return 0
		}
	}
	if priority(candidate) != priority(current) {
		return priority(candidate) > priority(current)
	}
	if (candidate.File != "") != (current.File != "") {
		return candidate.File != ""
	}
	return strings.ToLower(candidate.ID) < strings.ToLower(current.ID)
}

// hcKey builds a location key used to match AI dispositions to findings.
func hcKey(id, file string, line int) string {
	return fmt.Sprintf("%s|%s|%d", strings.ToLower(id), strings.ToLower(file), line)
}

// countUncachedVerdicts returns how many unique verdicts a re-run cannot get
// from the verdict cache: NR-fallback dispositions (never cached — they must
// be re-triaged) plus verdicts skipped as sensitive. Each of them forces an
// LLM call on the next run, whose output text changes the artifact cache key.
func countUncachedVerdicts(state *AgentState) int {
	seen := make(map[string]bool)
	n := 0
	for _, d := range state.FindingDispositions {
		if d.DispositionSource != dispositionSourceNRFallback || seen[d.Fingerprint] {
			continue
		}
		seen[d.Fingerprint] = true
		n++
	}
	return n + state.VerdictCacheStats.SkippedSensitive
}

func sortEnrichedFindings(findings []EnrichedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ai, bj := findingTypeOrder(a.Type), findingTypeOrder(b.Type); ai != bj {
			return ai < bj
		}
		if as, bs := strings.ToLower(strings.TrimSpace(a.Source)), strings.ToLower(strings.TrimSpace(b.Source)); as != bs {
			return as < bs
		}
		if ai, bj := severitySortRank(a.Severity), severitySortRank(b.Severity); ai != bj {
			return ai < bj
		}
		if af, bf := normalizePath(a.File), normalizePath(b.File); af != bf {
			return af < bf
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if ai, bj := strings.ToLower(strings.TrimSpace(a.ID)), strings.ToLower(strings.TrimSpace(b.ID)); ai != bj {
			return ai < bj
		}
		if am, bm := strings.TrimSpace(a.Message), strings.TrimSpace(b.Message); am != bm {
			return am < bm
		}
		return Fingerprint(a) < Fingerprint(b)
	})
}

func findingTypeOrder(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "core":
		return 0
	case "external":
		return 1
	case "nfr":
		return 2
	case "deploy":
		return 3
	case "network":
		return 4
	default:
		return 9
	}
}

func severitySortRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 9
	}
}

// assignVulnIDs generates CS-XXX-NNN identifiers for each finding.
func assignVulnIDs(findings []EnrichedFinding) {
	counters := make(map[string]int)
	for i := range findings {
		code := classifyVulnCode(findings[i].Message)
		counters[code]++
		findings[i].VulnID = fmt.Sprintf("CS-%s-%03d", code, counters[code])
	}
}

// AssignVulnIDsPublic is the exported version of assignVulnIDs for use by the web pipeline.
func AssignVulnIDsPublic(findings []EnrichedFinding) {
	assignVulnIDs(findings)
}

// vulnClassKeys holds VulnClassCodes keys in a fixed order: longest first (the
// most specific class wins), then alphabetical. Map iteration order is random
// per run, which made CS-* IDs — and every cache key derived from them —
// nondeterministic for messages matching more than one class.
var vulnClassKeys = sortedVulnClassKeys()

func sortedVulnClassKeys() []string {
	keys := make([]string, 0, len(prompts.VulnClassCodes))
	for key := range prompts.VulnClassCodes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	return keys
}

// classifyVulnCode maps a finding message to a short vulnerability class code.
func classifyVulnCode(message string) string {
	lower := strings.ToLower(message)
	for _, key := range vulnClassKeys {
		if strings.Contains(lower, key) {
			return prompts.VulnClassCodes[key]
		}
	}
	return "MISC"
}

// ── Threat Model Step ────────────────────────────────────────────────────────

// GetBatchSize returns the batch size to use, falling back to 150 if not configured.
func GetBatchSize(state *AgentState) int {
	if state != nil && state.BatchSize > 0 {
		return state.BatchSize
	}
	return 150
}

// threatModelMaxRetries bounds how many extra LLM passes are made to classify
// findings the model omitted in earlier passes before they default to NR.
const threatModelMaxRetries = 2

// nrFallbackRationale is recorded for findings the LLM never classified, even
// after bounded retries. They default to Needs Manual Review (never False
// Positive) so they keep penalising the Health Check score.
const nrFallbackRationale = "LLM did not classify this finding after retries; defaulting to Needs Manual Review for safety."

// errThreatModelParse marks a malformed (unparseable) threat-model response.
// Transport errors are returned unwrapped so they always fail the pipeline,
// whereas a malformed retry response is tolerated and handled by the NR fallback.
var errThreatModelParse = errors.New("parse threat-model JSON")

// rawDisposition is the LLM's unvalidated classification for a single finding,
// indexed relative to the batch that was sent.
type rawDisposition struct {
	FindingIndex int
	FindingID    string
	Fingerprint  string
	Disposition  string
	Confidence   string
	Rationale    string
	Evidence     *DispositionEvidence
}

func buildThreatModel(ctx context.Context, state *AgentState, llmClient llm.Client) error {
	if len(state.EnrichedFindings) == 0 {
		fmt.Fprintf(os.Stderr, "   ℹ️ No findings — skipping threat model\n")
		state.ThreatModelSource = "skipped_empty"
		return nil
	}

	repoContextText := ""
	if state.RepoContext != nil {
		repoContextText = state.RepoContext.FormatForLLM(5000) // ~5K tokens for threat model
	}

	tm, dispositions, audit, cacheStats, err := ClassifyFindingsWithAudit(ctx, repoContextText, state.ProjectPath, state.Language, state.EnrichedFindings, trackTriageLLMStages(state, llmClient), &state.TotalUsage, GetBatchSize(state), withVerdictCachePolicy(state.Policy), withVerdictCacheLLMIdentity(state))
	state.VerdictCacheStats = cacheStats
	if err != nil {
		return err
	}

	state.ThreatModel = tm
	if tm == nil {
		state.ThreatModelSource = "cache_skipped"
	} else {
		state.ThreatModelSource = "llm"
	}
	state.FindingDispositions = dispositions
	state.ClassificationAudit = audit

	// Final invariant: every finding has exactly one valid disposition.
	if err := validateFindingDispositions(state.FindingDispositions, len(state.EnrichedFindings)); err != nil {
		return err
	}

	tp, fp, nr := countDispositions(state.FindingDispositions)
	fmt.Fprintf(os.Stderr, "   ✅ Threat model: %d True Positives, %d False Positives, %d Needs Review\n", tp, fp, nr)

	return nil
}

// threatModelLLMCall sends a single batch of findings to the LLM and returns the
// parsed threat model plus the raw (unvalidated) dispositions. Transport errors
// are wrapped plainly; malformed JSON is wrapped with errThreatModelParse.
func threatModelLLMCall(ctx context.Context, repoContextText, projectPath, language string, batch []EnrichedFinding, llmClient llm.Client, usage *llm.Usage) (*ThreatModel, []rawDisposition, error) {
	findingsJSON, _ := json.MarshalIndent(batch, "", "  ")
	userPrompt := fmt.Sprintf(prompts.ThreatModelUserPromptTemplate,
		repoContextText,
		projectPath,
		len(batch),
		string(findingsJSON),
	)

	messages := []llm.Message{
		{Role: "system", Content: prompts.ThreatModelSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(language)},
	}

	response, u, err := llmClient.Chat(ctx, messages)
	addUsage(usage, u)
	if err != nil {
		return nil, nil, fmt.Errorf("threat model LLM call failed: %w", err)
	}

	// Parse JSON from response (handle markdown code fences)
	jsonText := extractJSON(response)

	var rawResult struct {
		ComponentOverview   string       `json:"component_overview"`
		EntryPoints         []EntryPoint `json:"entry_points"`
		TrustBoundaries     TrustBounds  `json:"trust_boundaries"`
		SensitiveDataPaths  []DataPath   `json:"sensitive_data_paths"`
		PrivilegedActions   []PrivAction `json:"privileged_actions"`
		PriorityAreas       []string     `json:"priority_areas"`
		FindingDispositions []struct {
			FindingIndex int    `json:"finding_index"`
			Disposition  string `json:"disposition"`
			Rationale    string `json:"rationale"`
		} `json:"finding_dispositions"`
	}

	if err := json.Unmarshal([]byte(jsonText), &rawResult); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errThreatModelParse, err)
	}

	tm := &ThreatModel{
		ComponentOverview:  rawResult.ComponentOverview,
		EntryPoints:        rawResult.EntryPoints,
		TrustBoundaries:    rawResult.TrustBoundaries,
		SensitiveDataPaths: rawResult.SensitiveDataPaths,
		PrivilegedActions:  rawResult.PrivilegedActions,
		PriorityAreas:      rawResult.PriorityAreas,
	}

	disps := make([]rawDisposition, 0, len(rawResult.FindingDispositions))
	for _, d := range rawResult.FindingDispositions {
		disps = append(disps, rawDisposition{FindingIndex: d.FindingIndex, Disposition: d.Disposition, Rationale: d.Rationale})
	}
	return tm, disps, nil
}

func isSupportedDisposition(d string) bool {
	switch d {
	case "True Positive", "False Positive", "Needs Manual Review":
		return true
	default:
		return false
	}
}

func countDispositions(dispositions []FindingDisposition) (tp, fp, nr int) {
	for _, d := range dispositions {
		switch d.Disposition {
		case "True Positive":
			tp++
		case "False Positive":
			fp++
		default:
			nr++
		}
	}
	return tp, fp, nr
}

func validateFindingDispositions(dispositions []FindingDisposition, findingCount int) error {
	if findingCount == 0 {
		if len(dispositions) != 0 {
			return fmt.Errorf("threat-model response classified %d of 0 findings", len(dispositions))
		}
		return nil
	}
	if len(dispositions) != findingCount {
		return fmt.Errorf("threat-model response classified %d of %d findings", len(dispositions), findingCount)
	}

	seen := make(map[int]struct{}, findingCount)
	for _, disposition := range dispositions {
		if disposition.FindingIndex < 0 || disposition.FindingIndex >= findingCount {
			return fmt.Errorf("threat-model response has out-of-range finding_index %d", disposition.FindingIndex)
		}
		if _, duplicate := seen[disposition.FindingIndex]; duplicate {
			return fmt.Errorf("threat-model response classifies finding_index %d more than once", disposition.FindingIndex)
		}
		seen[disposition.FindingIndex] = struct{}{}

		switch disposition.Disposition {
		case "True Positive", "False Positive", "Needs Manual Review":
		default:
			return fmt.Errorf("threat-model response has unsupported disposition %q", disposition.Disposition)
		}
	}

	return nil
}

// runWorkers was removed in the pipeline simplification (June 2026).
// The Threat Model step (buildThreatModel) now serves as the single authoritative
// source of TP/FP/NR dispositions. The old Map-Reduce workers duplicated this
// classification with 10+ extra LLM calls and the output (raw markdown) was never
// parsed back into structured FindingDispositions.

// ── PoC Verification Step ────────────────────────────────────────────────────

func runPoCVerification(ctx context.Context, state *AgentState, llmClient llm.Client) error {
	// Collect True Positive findings for PoC
	var tpFindings []EnrichedFinding
	tpSet := make(map[string]bool)
	for _, d := range state.FindingDispositions {
		if d.Disposition == "True Positive" {
			tpSet[d.FindingID] = true
		}
	}

	for _, f := range state.EnrichedFindings {
		if tpSet[f.VulnID] {
			tpFindings = append(tpFindings, f)
		}
	}

	if len(tpFindings) == 0 {
		fmt.Fprintf(os.Stderr, "   ℹ️ No True Positives — skipping PoC verification\n")
		return nil
	}

	// Phase 5b: verify ALL true positives (deduped, batched, bounded concurrency,
	// budget-capped) instead of silently dropping everything past the 75th.
	pocResults, stats, err := verifyPoCs(ctx, state.Language, tpFindings, trackLLMStage(state, usageStagePoC, llmClient), &state.TotalUsage)
	state.PoCStats = stats
	if err != nil {
		return fmt.Errorf("PoC verification LLM call failed: %w", err)
	}

	state.PoCResults = pocResults

	verified := 0
	incomplete := 0
	for _, p := range pocResults {
		if p.ExploitBlocked != nil && !*p.ExploitBlocked {
			verified++
		} else {
			incomplete++
		}
	}
	fmt.Fprintf(os.Stderr, "   ✅ PoC: %d unique TPs → %d exploitable, %d blocked/unknown\n", len(pocResults), verified, incomplete)

	return nil
}

func generateReport(ctx context.Context, state *AgentState, llmClient llm.Client) error {
	// Generate lookup table for original findings (now with CS-XXX-NNN IDs)
	var lookupLines []string
	lookupLines = append(lookupLines, "| Vulnerability ID | Rule ID | Severity | File | Line |")
	lookupLines = append(lookupLines, "|---|---|---|---|---|")
	for _, f := range state.EnrichedFindings {
		file := f.File
		if file == "" {
			file = "N/A"
		}
		lookupLines = append(lookupLines, fmt.Sprintf("| %s | %s | %s | %s | %d |", f.VulnID, f.ID, f.Severity, file, f.Line))
	}
	lookupTable := strings.Join(lookupLines, "\n")

	// Build threat model summary block
	threatModelBlock := ""
	if state.ThreatModel != nil {
		threatModelBlock = fmt.Sprintf("\n## Threat Model Summary\n- **Component**: %s\n- **Priority Areas**: %s\n",
			state.ThreatModel.ComponentOverview,
			strings.Join(state.ThreatModel.PriorityAreas, ", "))

		if len(state.ThreatModel.EntryPoints) > 0 {
			threatModelBlock += "\n### Entry Points\n"
			for _, ep := range state.ThreatModel.EntryPoints {
				trusted := "untrusted"
				if ep.Trusted {
					trusted = "trusted"
				}
				threatModelBlock += fmt.Sprintf("- **%s** (%s, %s) — validation: %s\n", ep.Endpoint, ep.Type, trusted, ep.Validation)
			}
		}
	}

	// Build disposition summary block
	dispositionBlock := ""
	if len(state.FindingDispositions) > 0 {
		tp, fp, nr := 0, 0, 0
		for _, d := range state.FindingDispositions {
			switch d.Disposition {
			case "True Positive":
				tp++
			case "False Positive":
				fp++
			default:
				nr++
			}
		}
		dispositionBlock = fmt.Sprintf("\n## Finding Dispositions (Threat Model)\n- True Positives: %d\n- False Positives: %d\n- Needs Manual Review: %d\n", tp, fp, nr)

		// Audit trail: how each disposition was produced (scale transparency).
		srcCounts := map[string]int{}
		for _, d := range state.FindingDispositions {
			if d.DispositionSource != "" {
				srcCounts[d.DispositionSource]++
			}
		}
		if len(srcCounts) > 0 {
			dispositionBlock += fmt.Sprintf("- Disposition sources: %d LLM, %d cached, %d deterministic, %d NR-fallback\n",
				srcCounts[dispositionSourceLLM], srcCounts[dispositionSourceCache],
				srcCounts[dispositionSourceDeterministic], srcCounts[dispositionSourceNRFallback])
		}

		// Include False Positive rationales
		var fpLines []string
		for _, d := range state.FindingDispositions {
			if d.Disposition == "False Positive" {
				fpLines = append(fpLines, fmt.Sprintf("- **%s**: %s", d.FindingID, d.Rationale))
			}
		}
		if len(fpLines) > 0 {
			dispositionBlock += "\n### False Positive Rationales\n" + strings.Join(fpLines, "\n") + "\n"
		}
	}

	// Build PoC summary block
	pocBlock := ""
	if len(state.PoCResults) > 0 {
		pocBlock = "\n## PoC Verification Results\n"
		for _, poc := range state.PoCResults {
			pocBlock += fmt.Sprintf("\n### %s (%s)\n- **File**: %s\n- **Conclusion**: %s\n",
				poc.VulnerabilityType, poc.Severity, poc.AffectedFile, poc.Conclusion)
			if len(poc.ReasoningSteps) > 0 {
				pocBlock += "\n| Step | Description | Result |\n|---|---|---|\n"
				for _, step := range poc.ReasoningSteps {
					pocBlock += fmt.Sprintf("| %s | %s | %s |\n", step.Step, step.Description, step.Result)
				}
			}
		}
	}

	hc := state.HealthCheck
	healthBlock := fmt.Sprintf("- **Health Check**: %d/100 (%s) — the authoritative security posture score\n- **Security Gate Verdict**: %s under `%s` policy (`fail_on=%s`)\n- **Health Check Breakdown**: %d active findings, %d ignored (False Positives), %d deduplicated; penalty %d, bonus %d\n",
		hc.Score, hc.Grade,
		strings.ToUpper(hc.Verdict.Status), hc.Policy.Profile, hc.Policy.FailOn,
		hc.Breakdown.ActiveFindings, hc.Breakdown.IgnoredFindings, hc.Breakdown.DedupedFindings,
		hc.Breakdown.Penalty, hc.Breakdown.Bonus)
	if len(hc.Verdict.BlockingReasons) > 0 {
		var reasonLines []string
		for _, reason := range hc.Verdict.BlockingReasons {
			reasonLines = append(reasonLines, fmt.Sprintf("  - `%s`: %s", reason.Code, reason.Message))
		}
		healthBlock += "- **Security Gate Blocking Reasons**:\n" + strings.Join(reasonLines, "\n") + "\n"
	}

	metadataBlock := fmt.Sprintf("## AITriage + SecureCoder Engine Summary\n- **Date**: %s\n%s- **Total raw findings**: %d\n%s%s\n### Original Findings Reference Table (CRITICAL: Use these Vulnerability ID/File/Line mappings for your output):\n%s\n%s\n",
		time.Now().Format("January 2, 2006"), healthBlock, len(state.EnrichedFindings),
		threatModelBlock, dispositionBlock, lookupTable, pocBlock)

	userPrompt := fmt.Sprintf(prompts.ReportUserPromptTemplate, metadataBlock)

	messages := []llm.Message{
		{Role: "system", Content: prompts.ReportSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(state.Language)},
	}

	response, usage, err := trackLLMStage(state, usageStageReport, llmClient).Chat(ctx, messages)
	addUsage(&state.TotalUsage, usage)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// The LLM output is advisory narrative. Append the authoritative finding
	// inventory built deterministically from state so the report always carries
	// the canonical dispositions verbatim, regardless of any model drift in the
	// prose above.
	state.ReportMarkdown = strings.TrimRight(response, "\n") +
		"\n\n---\n\n" + buildCanonicalFindingsSection(state)
	return nil
}

// generateSummary builds a deterministic (no LLM), actionable Markdown summary
// for the GitHub Actions Step Summary. The output is split into three blocks:
//
//  1. Human Summary — compact health card for quick glance by humans
//  2. AI Remediation Prompt — copy-paste SecureCoder implementation brief
//  3. AI Agent Data — structured JSON in a collapsed &lt;details&gt; block
//
// False Positives are excluded from actionable sections but mentioned in stats.
func generateSummary(state *AgentState) error {
	handoff, err := BuildAgentHandoff(state, time.Now().UTC())
	if err != nil {
		return err
	}
	state.AgentHandoff = &handoff
	state.SummaryMarkdown = handoff.SummaryMarkdown
	fmt.Fprintf(os.Stderr, "   Summary: %d actionable, %d suppressed FP\n",
		len(handoff.AgentData.Findings), handoff.AgentData.Stats.FalsePositives)
	return nil
}

// ── Block 1: Human-Readable Summary ─────────────────────────────────────────

type actionableFinding struct {
	vulnID      string
	source      string
	severity    string
	file        string
	line        int
	message     string
	disposition string
}

func writeHumanSummary(sb *strings.Builder, state *AgentState, actionable []actionableFinding, tp, fp, nr int) {
	hc := state.HealthCheck

	sb.WriteString("## 🛡 Security Assessment\n\n")

	verdict := "✅ PASSED"
	if !hc.Verdict.Passed {
		verdict = "❌ FAILED"
	}
	_, _ = fmt.Fprintf(sb, "**Score**: %d/100 (%s) | **Gate**: %s | **Policy**: `%s` (`fail_on=%s`)\n\n",
		hc.Score, hc.Grade, verdict, hc.Policy.Profile, hc.Policy.FailOn)

	coverage := strings.ToUpper(strings.TrimSpace(state.ScannerCoverage))
	if coverage == "" {
		coverage = "PARTIAL"
	}
	_, _ = fmt.Fprintf(sb, "**Scanner coverage**: `%s`\n\n", coverage)
	if len(state.ScannerExecutions) > 0 {
		sb.WriteString("| Scanner | Status | Findings | Version |\n")
		sb.WriteString("|---|---|---:|---|\n")
		for _, scanner := range state.ScannerExecutions {
			_, _ = fmt.Fprintf(sb, "| `%s` | `%s` | %d | %s |\n",
				scanner.Scanner, scanner.Status, scanner.Findings, strings.ReplaceAll(scanner.Version, "|", "\\|"))
		}
		sb.WriteString("\n")
	}

	// ── Blocking Reasons ──────────────────────────────────────────────
	if len(hc.Verdict.BlockingReasons) > 0 {
		sb.WriteString("#### Blocking Reasons\n\n")
		for _, reason := range hc.Verdict.BlockingReasons {
			_, _ = fmt.Fprintf(sb, "- `%s`: %s", reason.Code, reason.Message)
			if reason.Count != 0 || reason.Threshold != 0 {
				_, _ = fmt.Fprintf(sb, " (count %d, threshold %d)", reason.Count, reason.Threshold)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// ── Severity Matrix ───────────────────────────────────────────────
	sevByDisp := map[string]map[string]int{
		"True Positive":       {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		"Needs Manual Review": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
	}
	for _, f := range actionable {
		sev := strings.ToUpper(f.severity)
		if _, ok := sevByDisp[f.disposition]; !ok {
			continue
		}
		if _, ok := sevByDisp[f.disposition][sev]; ok {
			sevByDisp[f.disposition][sev]++
		}
	}

	sb.WriteString("### Overview\n\n")
	sb.WriteString("| | Critical | High | Medium | Low |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	_, _ = fmt.Fprintf(sb, "| True Positives | %d | %d | %d | %d |\n",
		sevByDisp["True Positive"]["CRITICAL"], sevByDisp["True Positive"]["HIGH"],
		sevByDisp["True Positive"]["MEDIUM"], sevByDisp["True Positive"]["LOW"])
	_, _ = fmt.Fprintf(sb, "| Needs Review | %d | %d | %d | %d |\n\n",
		sevByDisp["Needs Manual Review"]["CRITICAL"], sevByDisp["Needs Manual Review"]["HIGH"],
		sevByDisp["Needs Manual Review"]["MEDIUM"], sevByDisp["Needs Manual Review"]["LOW"])

	_, _ = fmt.Fprintf(sb, "> **%d** findings analyzed · **%d** true positives · **%d** needs review · **%d** false positives suppressed\n\n",
		len(state.EnrichedFindings), tp, nr, fp)

	// ── Top Critical Issues (max 5, CRITICAL first then HIGH) ─────────
	if len(actionable) > 0 {
		sb.WriteString("### ⚠️ Top Critical Issues\n\n")

		type ranked struct {
			severity string
			vulnID   string
			file     string
			line     int
			message  string
		}
		var top []ranked
		// First pass: CRITICAL
		for _, f := range actionable {
			if strings.ToUpper(f.severity) == "CRITICAL" {
				top = append(top, ranked{severity: f.severity, vulnID: f.vulnID, file: f.file, line: f.line, message: f.message})
			}
		}
		// Second pass: HIGH
		for _, f := range actionable {
			if strings.ToUpper(f.severity) == "HIGH" {
				top = append(top, ranked{severity: f.severity, vulnID: f.vulnID, file: f.file, line: f.line, message: f.message})
			}
		}

		limit := 5
		if len(top) < limit {
			limit = len(top)
		}
		for i := 0; i < limit; i++ {
			file := top[i].file
			if file == "" {
				file = "N/A"
			}
			// Clean message for display: take first part before ":"
			displayMsg := top[i].message
			if idx := strings.Index(displayMsg, ":"); idx > 0 && idx < 60 {
				displayMsg = displayMsg[:idx]
			}
			displayMsg = strings.ReplaceAll(displayMsg, "\\|", "|")
			if top[i].line > 0 {
				_, _ = fmt.Fprintf(sb, "%d. **[%s]** %s — `%s:%d`\n", i+1, top[i].severity, displayMsg, file, top[i].line)
			} else {
				_, _ = fmt.Fprintf(sb, "%d. **[%s]** %s — `%s`\n", i+1, top[i].severity, displayMsg, file)
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("### Actionable Findings\n\nNo actionable security findings.\n\n")
	}

	// ── PoC Summary (compact) ─────────────────────────────────────────
	if len(state.PoCResults) > 0 {
		sb.WriteString("### PoC Verification\n\n")
		sb.WriteString("| Vulnerability | Severity | Conclusion |\n")
		sb.WriteString("|---|---|---|\n")
		for _, poc := range state.PoCResults {
			_, _ = fmt.Fprintf(sb, "| %s | %s | %s |\n",
				poc.VulnerabilityType, poc.Severity, poc.Conclusion)
		}
		sb.WriteString("\n")
	}
}

// ── Block 2: AI Agent Structured Data ───────────────────────────────────────

// ── Block 2: AI Remediation Prompt ──────────────────────────────────────────

func writeAIRemediationPrompt(sb *strings.Builder, state *AgentState, actionable []actionableFinding, generatedAt time.Time) {
	if len(actionable) == 0 {
		return
	}

	hc := state.HealthCheck

	sb.WriteString("\n### 📋 AI Remediation Prompt\n\n")
	sb.WriteString("> Copy this implementation brief into your AI IDE. It must audit and plan first, then implement verified fixes.\n\n")
	sb.WriteString("<details>\n")
	sb.WriteString("<summary>Click to expand prompt</summary>\n\n")
	sb.WriteString("```markdown\n")

	sb.WriteString("You are a SecureCoder security engineer working in this repository. Below is triage evidence from an AITriage security scan.\n")
	sb.WriteString("Your goal is a secure, verified remediation — not merely a checklist. Follow every phase in order.\n\n")

	sb.WriteString("## SCAN METADATA\n")
	_, _ = fmt.Fprintf(sb, "- Score: %d/100 (%s)\n", hc.Score, hc.Grade)
	_, _ = fmt.Fprintf(sb, "- Date: %s\n", generatedAt.Format("2006-01-02"))
	_, _ = fmt.Fprintf(sb, "- Gate: %s\n\n", strings.ToUpper(hc.Verdict.Status))

	sb.WriteString("## VULNERABILITIES FOUND\n\n")
	for i, f := range actionable {
		file := f.file
		if file == "" {
			file = "N/A"
		}
		title := strings.ReplaceAll(f.message, "\\|", "|")
		if f.line > 0 {
			_, _ = fmt.Fprintf(sb, "%d. [%s] %s | %s | %s:%d\n",
				i+1, strings.ToUpper(f.severity), f.vulnID, title, file, f.line)
		} else {
			_, _ = fmt.Fprintf(sb, "%d. [%s] %s | %s | %s\n",
				i+1, strings.ToUpper(f.severity), f.vulnID, title, file)
		}
		_, _ = fmt.Fprintf(sb, "   Status: %s\n", f.disposition)
	}

	sb.WriteString("\n## OPERATING CONTRACT\n\n")
	sb.WriteString("### Phase 0 — Audit before code\n")
	sb.WriteString("- Do not modify code until you have completed a scoped read-only audit of the affected files, dependencies, entry points, configuration, and side effects.\n")
	sb.WriteString("- Inspect available tools first. Use filesystem, search, git, browser, and MCP capabilities when available; never invent unavailable APIs, libraries, or tool results.\n")
	sb.WriteString("- For every non-trivial API, framework, dependency, or version change, verify the current official documentation before implementation. Record material sources and compatibility constraints in the plan.\n\n")

	sb.WriteString("### Phase 1 — Create the remediation plan\n")
	sb.WriteString("- Before editing, create a short lowercase-kebab-case `*.md` plan file in the repository root that names this remediation. Do not overwrite an existing plan.\n")
	sb.WriteString("- Group correlated findings by root cause and component; do not create duplicate fixes for the same defect. Prioritize CRITICAL, then HIGH, MEDIUM, LOW.\n")
	sb.WriteString("- For every remediation unit record affected files, the exact intended code/configuration change, security invariant, compatibility or migration risk, dependencies, verification, and acceptance criteria.\n")
	sb.WriteString("- Track each task and subtask with checkboxes. Do not begin implementation until this plan is complete.\n\n")

	sb.WriteString("### Phase 2 — Implement verified fixes\n")
	sb.WriteString("- Do not stop after the plan. Implement only findings marked `True Positive`, one remediation unit at a time, and update the plan after every completed unit.\n")
	sb.WriteString("- For `Needs Manual Review`, do not make speculative changes. Record the evidence, decision required, safe options, and the verification needed from a human owner.\n")
	sb.WriteString("- Preserve least privilege and secure-by-default behaviour: enforce authentication and authorization server-side, deny by default, validate inputs with allowlists, parameterize data access, encode untrusted output, keep secrets out of code and logs, use narrow CORS/CSP/cookie settings, and remove insecure debug/default behaviour.\n")
	sb.WriteString("- Use official advisories and documentation for dependency remediation. Preserve lockfiles and compatibility; never suppress a scanner, weaken a policy, disable a test, or hide a finding merely to obtain a green result.\n")
	sb.WriteString("- Keep changes minimal and scoped. Do not perform unrelated mass refactors. If a safe implementation depends on missing authority, a product decision, or uncertain facts, stop that unit and record the blocker.\n\n")

	sb.WriteString("### Phase 3 — Verify and report\n")
	sb.WriteString("- After every remediation unit, run the narrowest relevant test, linter, or security check. At the end, run the complete applicable verification suite.\n")
	sb.WriteString("- Confirm each fixed vulnerability is no longer reproducible and that authorization, negative-path, regression, and compatibility tests cover the intended security invariant.\n")
	sb.WriteString("- Finish only when every plan item is checked or explicitly marked blocked with an owner decision. Report changed files, finding IDs addressed, commands run, results, and any residual risk.\n")

	sb.WriteString("```\n\n")
	sb.WriteString("</details>\n")
}

func generateAIFixSpec(ctx context.Context, state *AgentState, llmClient llm.Client) error {
	// Extract repository name from project path (last path component)
	repoName := filepath.Base(state.ProjectPath)
	if repoName == "." || repoName == "/" {
		repoName = "unknown"
	}

	// Get stack and project tree from RepoContext
	stack := "Not detected"
	projectTree := ""
	if state.RepoContext != nil {
		if state.RepoContext.Stack != "" {
			stack = state.RepoContext.Stack
		}
		if state.RepoContext.ProjectTree != "" {
			projectTree = state.RepoContext.ProjectTree
			if len(projectTree) > 3000 {
				projectTree = projectTree[:3000] + "\n... (truncated)"
			}
		}
	}

	userPrompt := fmt.Sprintf(prompts.FixSpecUserPromptTemplate, repoName, stack, projectTree, state.ReportMarkdown)

	messages := []llm.Message{
		{Role: "system", Content: prompts.FixSpecSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(state.Language)},
	}

	response, usage, err := trackLLMStage(state, usageStageFixSpec, llmClient).Chat(ctx, messages)
	addUsage(&state.TotalUsage, usage)
	if err != nil {
		return fmt.Errorf("failed to generate fix spec: %w", err)
	}

	// Append the authoritative active-findings brief so the fix spec always
	// carries the canonical IDs; the model's prose above is advisory and is
	// checked against these by the integrity validator.
	state.AIFixSpec = strings.TrimRight(response, "\n") +
		"\n\n---\n\n" + canonicalActiveFindingsBrief(state)
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// addUsage accumulates LLM token usage from a single call into the total.
func addUsage(total *llm.Usage, u llm.Usage) {
	total.PromptTokens += u.PromptTokens
	total.CompletionTokens += u.CompletionTokens
	total.TotalTokens += u.TotalTokens
	total.CachedPromptTokens += u.CachedPromptTokens
	total.CacheCreationInputTokens += u.CacheCreationInputTokens
	total.CacheReadInputTokens += u.CacheReadInputTokens
	total.CacheTelemetryReported = total.CacheTelemetryReported || u.CacheTelemetryReported
}

// formatLLMUsage preserves the provider's total instead of inventing a price.
// Gemini thinking models can report tokens beyond prompt and visible completion.
func formatLLMUsage(u llm.Usage) string {
	parts := []string{
		fmt.Sprintf("%d total", u.TotalTokens),
		fmt.Sprintf("%d prompt", u.PromptTokens),
		fmt.Sprintf("%d completion", u.CompletionTokens),
	}
	if additional := u.TotalTokens - u.PromptTokens - u.CompletionTokens; additional > 0 {
		parts = append(parts, fmt.Sprintf("%d reasoning/other", additional))
	}
	if u.CacheTelemetryReported {
		cacheParts := []string{}
		if u.CachedPromptTokens > 0 {
			cacheParts = append(cacheParts, fmt.Sprintf("%d cached prompt", u.CachedPromptTokens))
		}
		if u.CacheCreationInputTokens > 0 {
			cacheParts = append(cacheParts, fmt.Sprintf("%d cache creation", u.CacheCreationInputTokens))
		}
		if u.CacheReadInputTokens > 0 {
			cacheParts = append(cacheParts, fmt.Sprintf("%d cache read", u.CacheReadInputTokens))
		}
		if len(cacheParts) == 0 {
			cacheParts = append(cacheParts, "0 cache tokens")
		}
		parts = append(parts, "cache telemetry: "+strings.Join(cacheParts, ", "))
	} else {
		parts = append(parts, "cache telemetry: provider_did_not_report")
	}
	return strings.Join(parts, " · ")
}

// extractFullContext extracts the full function body + imports for a finding.
// Uses tree-sitter AST when possible, falls back to ±30 lines.
func extractFullContext(projectPath, file string, line int) string {
	if file == "" || line <= 0 {
		return "Context not available."
	}
	cleanPath := strings.TrimPrefix(file, "/src/")
	fullPath := cleanPath
	if !filepath.IsAbs(cleanPath) {
		fullPath = filepath.Join(projectPath, cleanPath)
	}

	fc, err := agentcontext.ExtractFunction(fullPath, line)
	if err != nil {
		return "Context not available."
	}

	var sb strings.Builder
	if fc.Imports != "" {
		sb.WriteString("// Imports:\n")
		sb.WriteString(fc.Imports)
		sb.WriteString("\n\n")
	}
	_, _ = fmt.Fprintf(&sb, "// Function: %s (lines %d-%d)\n", fc.Name, fc.StartLine, fc.EndLine)
	sb.WriteString(fc.Body)
	return sb.String()
}

// extractJSON extracts a JSON block from an LLM response that may contain
// markdown code fences or other text around the JSON.
func extractJSON(text string) string {
	// Try ```json ... ``` first
	if idx := strings.Index(text, "```json"); idx >= 0 {
		rest := text[idx+7:]
		if endIdx := strings.Index(rest, "```"); endIdx >= 0 {
			return strings.TrimSpace(rest[:endIdx])
		}
	}
	// Try ``` ... ```
	if idx := strings.Index(text, "```"); idx >= 0 {
		rest := text[idx+3:]
		if endIdx := strings.Index(rest, "```"); endIdx >= 0 {
			return strings.TrimSpace(rest[:endIdx])
		}
	}
	// Try to find raw JSON (starts with { or [)
	for i, ch := range text {
		if ch == '{' || ch == '[' {
			return strings.TrimSpace(text[i:])
		}
	}
	return text
}
