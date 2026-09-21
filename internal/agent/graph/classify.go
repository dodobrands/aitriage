package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
)

// ClassifyFindings is the enterprise-scale entry point that builds a SecureCoder
// threat model and classifies EVERY finding as True Positive / False Positive /
// Needs Manual Review. It composes five layers on top of the batching safety net:
//
//	Layer 1  dedup identical findings by fingerprint (no silent drop)
//	Layer 2  reuse cached verdicts by fingerprint (cheap re-runs in CI)
//	Layer 3  severity/category gating: deterministic disposition for the rest
//	Layer 4  SecureCoder threat-model-once + structured per-finding classification
//	Layer 5  bounded concurrency + budget; anything left defaults to NR
//
// Invariants: every finding gets exactly one disposition; unclassified work
// defaults to Needs Manual Review (never False Positive); transport/provider
// failures fail the pipeline; the threat model is built ONCE and reused.
//
// The returned slice always has exactly len(findings) entries, ordered by index.
func ClassifyFindings(ctx context.Context, repoContextText, projectPath string, findings []EnrichedFinding, llmClient llm.Client, usage *llm.Usage, batchSize int) (*ThreatModel, []FindingDisposition, error) {
	tm, dispositions, _, _, err := ClassifyFindingsWithAudit(ctx, repoContextText, projectPath, "", findings, llmClient, usage, batchSize)
	return tm, dispositions, err
}

// ClassifyFindingsWithAudit behaves like ClassifyFindings and additionally
// returns the raw structured model responses plus their validated mapping. The
// audit is persisted in triage-findings.json by the CLI pipeline.
func ClassifyFindingsWithAudit(ctx context.Context, repoContextText, projectPath, language string, findings []EnrichedFinding, llmClient llm.Client, usage *llm.Usage, batchSize int, cacheOptions ...verdictCacheOption) (*ThreatModel, []FindingDisposition, []ClassificationAuditEntry, VerdictCacheStats, error) {
	if len(findings) == 0 {
		return nil, nil, nil, VerdictCacheStats{}, nil
	}

	// Layer 1: collapse byte-for-byte identical findings.
	unique, groups := dedupFindings(findings)

	cache := newVerdictCache(strings.TrimSpace(os.Getenv("AITRIAGE_MODEL")), cacheOptions...)
	gating := defaultGatingConfig()

	tm, uniqueDisps, audit, err := classifyUnique(ctx, repoContextText, projectPath, language, unique, llmClient, usage, cache, gating, batchSize)
	if err != nil {
		return nil, nil, audit, cache.Stats(), err
	}

	// Layer 1 (reverse): project the unique verdicts back onto every original.
	dispositions := projectDispositions(uniqueDisps, groups, findings)

	logTriageMetrics(findings, unique, uniqueDisps)
	return tm, dispositions, audit, cache.Stats(), nil
}

// classifyUnique classifies the deduplicated findings, returning one disposition
// per unique finding (indexed by unique position).
func classifyUnique(ctx context.Context, repoContextText, projectPath, language string, unique []EnrichedFinding, llmClient llm.Client, usage *llm.Usage, cache *verdictCache, gating gatingConfig, batchSize int) (*ThreatModel, []FindingDisposition, []ClassificationAuditEntry, error) {
	n := len(unique)
	result := make([]*FindingDisposition, n)

	// Layers 2 & 3: resolve as many findings as possible before any LLM call.
	// A full cache/gating hit should not pay for a threat-model request.
	var toLLM []int
	for i, f := range unique {
		fp := Fingerprint(f)
		if cached, ok := cache.Get(fp); ok {
			if cached.Disposition == "False Positive" {
				if err := validateFalsePositiveEvidence(projectPath, f, cached.Evidence); err != nil {
					cache.InvalidateFalsePositive()
				} else {
					cached.FindingIndex = i
					cached.DispositionSource = dispositionSourceCache
					cached.Fingerprint = fp
					result[i] = &cached
					continue
				}
			} else {
				cached.FindingIndex = i
				cached.DispositionSource = dispositionSourceCache
				cached.Fingerprint = fp
				result[i] = &cached
				continue
			}
		}
		if !gating.shouldTriageWithLLM(f) {
			d := deterministicDisposition(f)
			d.FindingIndex = i
			d.Fingerprint = fp
			result[i] = &d
			continue
		}
		toLLM = append(toLLM, i)
	}

	// Layer 5: enforce an optional hard budget on LLM-bound findings. Anything
	// over budget defaults to Needs Manual Review (safe, never auto-suppressed).
	if budget := llmBudget(); budget >= 0 && len(toLLM) > budget {
		for _, i := range toLLM[budget:] {
			fp := Fingerprint(unique[i])
			result[i] = &FindingDisposition{
				FindingIndex:      i,
				Disposition:       "Needs Manual Review",
				Rationale:         budgetRationale,
				Confidence:        "low",
				DispositionSource: dispositionSourceNRFallback,
				Fingerprint:       fp,
			}
		}
		toLLM = toLLM[:budget]
	}

	var (
		tm        *ThreatModel
		tmSummary = threatModelSummary(nil)
	)
	if len(toLLM) > 0 {
		// Layer 4a: build the SecureCoder threat model ONCE from a representative
		// sample of the findings that still require LLM classification. This call
		// is authoritative; a transport OR parse failure here is fatal (we must not
		// mask a broken provider before any classification).
		sample := make([]EnrichedFinding, 0, min(len(toLLM), batchSize))
		for _, i := range toLLM[:min(len(toLLM), batchSize)] {
			sample = append(sample, unique[i])
		}
		var err error
		tm, _, err = threatModelLLMCall(ctx, repoContextText, projectPath, language, sample, llmClient, usage)
		if err != nil {
			return nil, nil, nil, err
		}
		tmSummary = threatModelSummary(tm)
	}

	// Layer 4b + 5: classify the remaining findings against the threat model,
	// in bounded-concurrency batches with per-batch retry of omitted findings.
	classified, audit, err := classifyWithLLM(ctx, tmSummary, projectPath, language, unique, toLLM, llmClient, usage, batchSize)
	if err != nil {
		return nil, nil, audit, err
	}
	for gi, d := range classified {
		fp := Fingerprint(unique[gi])
		d.Fingerprint = fp
		d.DispositionSource = dispositionSourceLLM
		stored := d
		result[gi] = &stored
		cache.Set(fp, stored)
	}

	// NR fallback for any LLM-bound finding the model never classified.
	for _, i := range toLLM {
		if result[i] != nil {
			continue
		}
		fp := Fingerprint(unique[i])
		result[i] = &FindingDisposition{
			FindingIndex:      i,
			Disposition:       "Needs Manual Review",
			Rationale:         nrFallbackRationale,
			Confidence:        "low",
			DispositionSource: dispositionSourceNRFallback,
			Fingerprint:       fp,
		}
	}

	cache.Save()

	disps := make([]FindingDisposition, n)
	for i := range result {
		result[i].FindingIndex = i
		result[i].FindingID = unique[i].VulnID
		disps[i] = *result[i]
	}
	return tm, disps, audit, nil
}

// classifyWithLLM classifies the given unique-index targets in bounded-concurrency
// batches. It returns a map keyed by unique index. Transport/provider errors are
// fatal (returned); malformed responses are tolerated (left for the NR fallback).
func classifyWithLLM(ctx context.Context, tmSummary, projectPath, language string, unique []EnrichedFinding, targets []int, llmClient llm.Client, usage *llm.Usage, batchSize int) (map[int]FindingDisposition, []ClassificationAuditEntry, error) {
	out := make(map[int]FindingDisposition)
	if len(targets) == 0 {
		return out, nil, nil
	}

	var batches [][]int
	for off := 0; off < len(targets); off += batchSize {
		batches = append(batches, targets[off:min(off+batchSize, len(targets))])
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex // guards out
		usageMu  sync.Mutex // guards usage
		errMu    sync.Mutex // guards firstErr
		firstErr error
		wg       sync.WaitGroup
	)
	audit := &classificationAuditCollector{}
	sem := make(chan struct{}, triageConcurrency())

	addUsageSafe := func(u llm.Usage) {
		usageMu.Lock()
		addUsage(usage, u)
		usageMu.Unlock()
	}
	setErr := func(e error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = e
			cancel()
		}
		errMu.Unlock()
	}

	for _, batch := range batches {
		wg.Add(1)
		sem <- struct{}{}
		go func(batch []int) {
			defer wg.Done()
			defer func() { <-sem }()

			subset := make([]EnrichedFinding, len(batch))
			for li, gi := range batch {
				subset[li] = unique[gi]
			}
			local := classifyBatchWithRetry(ctx, tmSummary, projectPath, language, subset, batch, llmClient, addUsageSafe, setErr, audit)

			mu.Lock()
			for li, d := range local {
				out[batch[li]] = d
			}
			mu.Unlock()
		}(batch)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, audit.snapshot(), firstErr
	}
	return out, audit.snapshot(), nil
}

// classifyBatchWithRetry classifies a single batch, retrying omitted findings up
// to threatModelMaxRetries times. Returns a map keyed by LOCAL batch index.
func classifyBatchWithRetry(ctx context.Context, tmSummary, projectPath, language string, subset []EnrichedFinding, globalIndices []int, llmClient llm.Client, addUsageSafe func(llm.Usage), setErr func(error), audit *classificationAuditCollector) map[int]FindingDisposition {
	res := make(map[int]FindingDisposition)

	pass := func(attempt int, items []EnrichedFinding, localMap []int) {
		disps, rawResponse, u, err := classifyBatchLLM(ctx, tmSummary, language, items, llmClient)
		addUsageSafe(u)
		requestIndices := make([]int, len(localMap))
		for i, localIndex := range localMap {
			requestIndices[i] = globalIndices[localIndex]
		}
		entry := newClassificationAuditEntry(attempt, requestIndices, items, rawResponse)
		if err != nil {
			entry.ParseError = err.Error()
			audit.record(entry)
			// Malformed responses are tolerated (NR fallback covers them); only
			// transport/provider failures abort the whole pipeline.
			if !errors.Is(err, errThreatModelParse) {
				setErr(err)
			}
			return
		}
		for _, d := range disps {
			if d.FindingIndex < 0 || d.FindingIndex >= len(items) {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: d.FindingIndex, Reason: "out-of-range finding_index"})
				continue
			}
			if !isSupportedDisposition(d.Disposition) {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: requestIndices[d.FindingIndex], Reason: "unsupported disposition"})
				continue
			}
			gi := localMap[d.FindingIndex]
			if _, done := res[gi]; done {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: globalIndices[gi], Reason: "duplicate disposition"})
				continue
			}
			validated, reason := validateLLMDisposition(projectPath, items[d.FindingIndex], d)
			if reason != "" {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: globalIndices[gi], Reason: reason})
				continue
			}
			res[gi] = validated
			entry.AcceptedFindingIndices = append(entry.AcceptedFindingIndices, globalIndices[gi])
		}
		audit.record(entry)
	}

	full := make([]int, len(subset))
	for i := range full {
		full[i] = i
	}
	pass(0, subset, full)

	for attempt := 0; attempt < classifyMaxRetries(); attempt++ {
		var missing []int
		for i := range subset {
			if _, done := res[i]; !done {
				missing = append(missing, i)
			}
		}
		if len(missing) == 0 {
			break
		}
		items := make([]EnrichedFinding, len(missing))
		for j, li := range missing {
			items[j] = subset[li]
		}
		pass(attempt+1, items, missing)
	}
	return res
}

// classifyBatchLLM sends one batch to the LLM using the SecureCoder classification
// prompt (which references the prebuilt threat model and the MUST/MUST NOT
// ruleset) and returns the raw per-finding dispositions.
func classifyBatchLLM(ctx context.Context, tmSummary, language string, batch []EnrichedFinding, llmClient llm.Client) ([]rawDisposition, string, llm.Usage, error) {
	promptFindings := make([]classificationPromptFinding, len(batch))
	for i, finding := range batch {
		promptFindings[i] = classificationPromptFinding{
			FindingIndex: i,
			FindingID:    findingIdentity(finding),
			Fingerprint:  Fingerprint(finding),
			Finding:      finding,
		}
	}
	findingsJSON, _ := json.MarshalIndent(promptFindings, "", "  ")
	userPrompt := fmt.Sprintf(prompts.ClassificationUserPromptTemplate, tmSummary, len(batch), string(findingsJSON))

	messages := []llm.Message{
		{Role: "system", Content: prompts.ClassificationSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(language)},
	}

	response, u, err := llmClient.Chat(ctx, messages)
	if err != nil {
		return nil, "", u, fmt.Errorf("classification LLM call failed: %w", err)
	}

	jsonText := extractJSON(response)
	var raw struct {
		FindingDispositions []struct {
			FindingIndex int                  `json:"finding_index"`
			FindingID    string               `json:"finding_id"`
			Fingerprint  string               `json:"fingerprint"`
			Disposition  string               `json:"disposition"`
			Confidence   string               `json:"confidence"`
			Rationale    string               `json:"rationale"`
			Evidence     *DispositionEvidence `json:"evidence"`
		} `json:"finding_dispositions"`
	}
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
		return nil, response, u, fmt.Errorf("%w: %v", errThreatModelParse, err)
	}

	disps := make([]rawDisposition, 0, len(raw.FindingDispositions))
	for _, d := range raw.FindingDispositions {
		disps = append(disps, rawDisposition{
			FindingIndex: d.FindingIndex,
			FindingID:    d.FindingID,
			Fingerprint:  d.Fingerprint,
			Disposition:  d.Disposition,
			Confidence:   d.Confidence,
			Rationale:    d.Rationale,
			Evidence:     d.Evidence,
		})
	}
	return disps, response, u, nil
}

// threatModelSummary renders a compact text view of the threat model for use as
// classification context (keeps SecureCoder methodology without resending the
// full repository to every batch).
func threatModelSummary(tm *ThreatModel) string {
	if tm == nil {
		return "(no threat model available)"
	}
	var sb strings.Builder
	if tm.ComponentOverview != "" {
		sb.WriteString("Overview: " + tm.ComponentOverview + "\n")
	}
	if tm.TrustBoundaries.Authentication != "" || tm.TrustBoundaries.Authorization != "" {
		sb.WriteString(fmt.Sprintf("Trust boundaries: auth=%s; authz=%s; implicit=%s\n",
			tm.TrustBoundaries.Authentication, tm.TrustBoundaries.Authorization, tm.TrustBoundaries.ImplicitTrust))
	}
	if len(tm.EntryPoints) > 0 {
		sb.WriteString("Entry points:\n")
		for _, e := range tm.EntryPoints {
			sb.WriteString(fmt.Sprintf("  - %s (%s), trusted=%v, validation=%s\n", e.Endpoint, e.Type, e.Trusted, e.Validation))
		}
	}
	if len(tm.PriorityAreas) > 0 {
		sb.WriteString("Priority areas: " + strings.Join(tm.PriorityAreas, "; ") + "\n")
	}
	return strings.TrimSpace(sb.String())
}

func normalizeConfidence(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "high":
		return "high"
	case "medium", "med":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

// triageConcurrency returns the number of parallel classification workers.
func triageConcurrency() int {
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_CONCURRENCY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return 4
}

// classifyMaxRetries returns how many extra passes are made for findings the
// model omitted or returned malformed. Unclassified findings fall back to
// Needs Manual Review, which is safe but is NOT stored in the verdict cache —
// so flaky providers benefit from a higher retry count in CI.
func classifyMaxRetries() int {
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_CLASSIFY_RETRIES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return threatModelMaxRetries
}

// llmBudget returns the max number of unique findings to send to the LLM.
// A negative value (the default) means unlimited.
func llmBudget() int {
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_LLM_BUDGET")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return -1
}

const budgetRationale = "Exceeded the LLM triage budget; defaulting to Needs Manual Review for safety (never auto-suppressed)."

// logTriageMetrics prints a concise breakdown of how dispositions were produced.
func logTriageMetrics(findings, unique []EnrichedFinding, uniqueDisps []FindingDisposition) {
	bySource := map[string]int{}
	for _, d := range uniqueDisps {
		bySource[d.DispositionSource]++
	}
	fmt.Fprintf(os.Stderr, "   🔎 Triage scale: %d findings → %d unique (%d deduped) | sources: %d llm, %d cache, %d deterministic, %d nr-fallback\n",
		len(findings), len(unique), len(findings)-len(unique),
		bySource[dispositionSourceLLM], bySource[dispositionSourceCache],
		bySource[dispositionSourceDeterministic], bySource[dispositionSourceNRFallback])
}
