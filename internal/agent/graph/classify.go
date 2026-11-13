package graph

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
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
//	Layer 2  reuse cached verdicts by a line-free key (cheap re-runs in CI)
//	Layer 3  severity/category gating: deterministic disposition for the rest
//	Layer 4  SecureCoder threat-model-once + structured per-finding classification
//	Layer 5  bounded concurrency + budget; anything left defaults to NR
//
// Invariants: every finding gets exactly one disposition; unclassified work
// defaults to Needs Manual Review (never False Positive); the threat model is
// built ONCE and reused. A provider failure does not discard the work done:
// the dispositions are returned complete (findings the model never saw carry
// disposition_source "triage-failed") together with a *TriageIncompleteError.
// Missing output counts as such a failure, decided finding by finding: a
// finding no reply carried a verdict for after every retry (left out,
// malformed or empty replies, verdicts naming another finding) is
// "triage-failed" too, whatever happened to the other findings of its
// request. Only a finding whose own verdict came back and was rejected by
// validation is an ordinary "nr-fallback".
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
	res, err := classifyFindings(ctx, classifyRequest{
		repoContextText: repoContextText,
		projectPath:     projectPath,
		language:        language,
		findings:        findings,
		client:          llmClient,
		usage:           usage,
		batchSize:       batchSize,
		cacheOptions:    cacheOptions,
	})
	return res.ThreatModel, res.Dispositions, res.Audit, res.CacheStats, err
}

// classifyRequest is the complete input of one classification run.
type classifyRequest struct {
	repoContextText string
	projectPath     string
	language        string
	findings        []EnrichedFinding
	client          llm.Client
	usage           *llm.Usage
	batchSize       int
	cacheOptions    []verdictCacheOption
	policy          validationPolicy
}

// validationPolicy holds the policy switches that change which model verdicts
// are accepted.
type validationPolicy struct {
	// fpCriticalRequiresHighConfidence keeps a CRITICAL finding as Needs
	// Manual Review unless the model dismisses it with high confidence.
	fpCriticalRequiresHighConfidence bool
}

// classifyResult is the output of one classification run.
type classifyResult struct {
	ThreatModel *ThreatModel
	// ThreatModelSource is empty when no threat model was needed.
	ThreatModelSource string
	// ThreatModelIssue explains a missing threat model (failed_parse).
	ThreatModelIssue string
	Dispositions     []FindingDisposition
	Audit            []ClassificationAuditEntry
	CacheStats       VerdictCacheStats

	// declined holds the unique indices of the findings the model declined
	// to classify (stop_reason refusal) when a request carried only them.
	declined map[int]bool
}

// classifyFindings runs the layered classification. On success the error is
// nil; on a provider failure it is a *TriageIncompleteError and Dispositions
// is still complete; on an abort (cancellation, suspended run) it is that
// error and Dispositions is nil.
func classifyFindings(ctx context.Context, req classifyRequest) (classifyResult, error) {
	if len(req.findings) == 0 {
		return classifyResult{}, nil
	}
	if req.batchSize <= 0 {
		req.batchSize = defaultClassificationBatchSize
	}

	// Layer 1: collapse byte-for-byte identical findings.
	unique, groups := dedupFindings(req.findings)

	cache := newVerdictCache(strings.TrimSpace(os.Getenv("AITRIAGE_MODEL")), req.cacheOptions...)
	gating := defaultGatingConfig()

	res, uniqueDisps, err := classifyUnique(ctx, req, unique, cache, gating)
	res.CacheStats = cache.Stats()
	var incomplete *TriageIncompleteError
	if err != nil && !errors.As(err, &incomplete) {
		return res, err
	}

	// Layer 1 (reverse): project the unique verdicts back onto every original.
	res.Dispositions = projectDispositions(uniqueDisps, groups, req.findings)
	if incomplete != nil {
		for _, d := range res.Dispositions {
			if d.DispositionSource == dispositionSourceTriageFailed {
				incomplete.Unclassified++
			}
		}
		for u := range res.declined {
			incomplete.Declined += len(groups[u])
		}
	}

	logTriageMetrics(req.findings, unique, uniqueDisps)
	return res, err
}

// classifyUnique classifies the deduplicated findings, returning one disposition
// per unique finding (indexed by unique position).
func classifyUnique(ctx context.Context, req classifyRequest, unique []EnrichedFinding, cache *verdictCache, gating gatingConfig) (classifyResult, []FindingDisposition, error) {
	var res classifyResult
	n := len(unique)
	result := make([]*FindingDisposition, n)

	// Layers 2 & 3: resolve as many findings as possible before any LLM call.
	// A full cache/gating hit should not pay for a threat-model request.
	var toLLM []int
	for i, f := range unique {
		fp := Fingerprint(f)
		// Verdicts are cached without the line number, so a finding that only
		// moved within its file is not re-classified.
		if cached, cachedLine, ok := cache.lookup(verdictCacheKey(f)); ok {
			cached.Evidence = relocateEvidence(cached.Evidence, cachedLine, f)
			if evidence, usable := cachedVerdictUsable(req, f, cached); usable {
				cached.Evidence = evidence
				cached.FindingIndex = i
				cached.DispositionSource = dispositionSourceCache
				cached.Fingerprint = fp
				result[i] = &cached
				continue
			}
			cache.InvalidateFalsePositive()
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

	var failure *TriageIncompleteError
	tmSummary := threatModelSummary(nil)
	if len(toLLM) > 0 {
		// Layer 4a: build the SecureCoder threat model ONCE from a representative
		// sample of the findings that still require LLM classification.
		sample := make([]EnrichedFinding, 0, min(len(toLLM), req.batchSize))
		for _, i := range toLLM[:min(len(toLLM), req.batchSize)] {
			sample = append(sample, unique[i])
		}
		tm, source, issue, err := buildThreatModelWithRepair(ctx, req.repoContextText, req.projectPath, req.language, sample, req.client, req.usage, classifyMaxRetries())
		switch {
		case err == nil:
			res.ThreatModel, res.ThreatModelSource, res.ThreatModelIssue = tm, source, issue
			if tm != nil {
				tmSummary = threatModelSummary(tm)
			}
		case abortsRun(ctx, err):
			return res, nil, err
		default:
			// The provider itself failed: classifying against it would fail the
			// same way, so every LLM-bound finding is left triage-failed.
			res.ThreatModelSource = threatModelSourceFailed
			failure = newTriageIncomplete(usageStageThreatModel, err)
		}
	}

	// Layer 4b + 5: classify the remaining findings against the threat model,
	// in bounded-concurrency batches with adaptive retry of omitted findings.
	var (
		unanswered map[int]bool
		declined   map[int]llm.RefusalError
	)
	if failure == nil && len(toLLM) > 0 {
		classified, audit, outcome, err := classifyWithLLM(ctx, tmSummary, req, unique, toLLM)
		res.Audit = audit
		if err != nil {
			return res, nil, err
		}
		for gi, d := range classified {
			fp := Fingerprint(unique[gi])
			d.Fingerprint = fp
			d.DispositionSource = dispositionSourceLLM
			stored := d
			result[gi] = &stored
			cache.store(verdictCacheKey(unique[gi]), stored, unique[gi].Line)
		}
		switch {
		case outcome.transportErr != nil:
			failure = newTriageIncomplete(usageStageClassification, outcome.transportErr)
		case len(outcome.unanswered) > 0:
			// No reply carried a verdict for these findings, after every
			// retry: they were left out, the replies were unparseable, {} or
			// null, an error object or an empty list, or their verdicts named
			// another finding; or the model declined to classify them, sent
			// on their own. That is missing output, not a model judgement,
			// and it is judged per finding: whether a batch-mate got a verdict,
			// or came from the verdict cache, must not decide whether the gate
			// sees an incomplete triage. Treating these findings as ordinary
			// NR fallbacks would let a fail_on=confirmed gate pass.
			unanswered, declined = outcome.unanswered, outcome.declined
			failure = newTriageIncomplete(usageStageClassification, errors.New(noVerdictReason(len(unanswered), declined)))
			failure.Cause = TriageFailureCauseNoVerdict
			res.declined = make(map[int]bool, len(declined))
			for i := range declined {
				res.declined[i] = true
			}
		}
	}

	// Findings the model did not classify: triage-failed when the provider
	// failed for them, no reply carried their verdict or the model declined
	// them, NR fallback when the model returned their own verdict and
	// validation rejected it every time.
	everyMissingFailed := failure != nil && unanswered == nil
	for _, i := range toLLM {
		if result[i] != nil {
			continue
		}
		fp := Fingerprint(unique[i])
		if everyMissingFailed || unanswered[i] {
			rationale := triageFailedRationale(failure.Reason)
			if refusal, ok := declined[i]; ok {
				rationale = declinedRationale(refusal)
			}
			result[i] = &FindingDisposition{
				FindingIndex:      i,
				Disposition:       "Needs Manual Review",
				Rationale:         rationale,
				Confidence:        "low",
				DispositionSource: dispositionSourceTriageFailed,
				Fingerprint:       fp,
			}
			continue
		}
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
	if failure != nil {
		return res, disps, failure
	}
	return res, disps, nil
}

// cachedVerdictUsable re-checks a cached verdict against the current rules. A
// cached False Positive is only reused while its evidence still validates and
// it still satisfies the run's validation policy. It returns the evidence the
// reused verdict records: for a False Positive, as validated now, on the line
// its code is on today.
func cachedVerdictUsable(req classifyRequest, f EnrichedFinding, cached FindingDisposition) (*DispositionEvidence, bool) {
	if cached.Disposition != "False Positive" {
		return cached.Evidence, true
	}
	evidence, err := validateFalsePositiveEvidence(req.projectPath, f, cached.Evidence)
	if err != nil || violatesCriticalConfidencePolicy(req.policy, f, cached.Confidence) {
		return nil, false
	}
	return evidence, true
}

func triageFailedRationale(reason string) string {
	return "AI triage did not complete: " + reason + ". The model never classified this finding; it stays Needs Manual Review and the gate cannot pass until triage completes."
}

// declinedRationale is the rationale of a finding the model declined to
// classify in a request that carried only that finding.
func declinedRationale(refusal llm.RefusalError) string {
	return "AI triage did not complete: " + declinedText(refusal, "this finding", nil) +
		". The model never classified it; it stays Needs Manual Review and the gate cannot pass until triage completes. The same model is likely to decline it again: review it by hand, or triage it with another model."
}

// declinedText says that the model declined to classify what, with the
// policy categories it named: the refusal's own, or categories when it
// describes several refusals at once. For example "claude-sonnet-5-5
// declined to classify this finding (stop_reason refusal, category cyber)".
func declinedText(refusal llm.RefusalError, what string, categories []string) string {
	model := refusal.Model
	if model == "" {
		model = "the model"
	}
	if len(categories) == 0 {
		categories = []string{refusal.Category}
	}
	named := make([]string, len(categories))
	for i, category := range categories {
		named[i] = cmp.Or(category, "none")
	}
	label := "category"
	if len(named) > 1 {
		label = "categories"
	}
	return redactFailureText(fmt.Sprintf("%s declined to classify %s (stop_reason refusal, %s %s)", model, what, label, strings.Join(named, ", ")))
}

// noVerdictReason is the run's failure reason when unanswered findings have
// no verdict: the model declined to classify those in declined, and no reply
// carried a verdict for the rest.
func noVerdictReason(unanswered int, declined map[int]llm.RefusalError) string {
	attempts := classifyMaxRetries() + 1
	if len(declined) == 0 {
		return fmt.Sprintf("the provider returned no usable classification for %d finding(s) after %d attempt(s): no reply carried a verdict for them (left out, malformed or empty, or naming another finding)",
			unanswered, attempts)
	}
	// One client serves the run, so every refusal names the same model; the
	// categories can differ.
	var (
		first      = -1
		categories []string
	)
	for i, refusal := range declined {
		if first < 0 || i < first {
			first = i
		}
		if !slices.Contains(categories, refusal.Category) {
			categories = append(categories, refusal.Category)
		}
	}
	slices.Sort(categories)
	reason := declinedText(declined[first], fmt.Sprintf("%d finding(s)", len(declined)), categories) + ", each sent on its own"
	if rest := unanswered - len(declined); rest > 0 {
		reason += fmt.Sprintf("; no reply carried a verdict for %d other finding(s) after %d attempt(s) (left out, malformed or empty, or naming another finding)", rest, attempts)
	}
	return reason
}

// classifyOutcome reports how the LLM classification stage ended when it was
// not aborted.
type classifyOutcome struct {
	// transportErr is the first provider failure (auth, rate limit, timeout).
	transportErr error
	// unanswered holds the unique indices of unclassified findings no reply
	// carried a verdict of their own for, in any attempt. Only meaningful
	// when transportErr is nil.
	unanswered map[int]bool
	// declined holds the part of unanswered the model declined to classify
	// in a request that carried only that finding, with the refusal.
	declined map[int]llm.RefusalError
}

// classifyWithLLM classifies the given unique-index targets in bounded-concurrency
// batches. It returns a map keyed by unique index. An abort (cancellation or a
// suspended run) is returned as an error; a provider failure stops the stage
// and is reported in the outcome so the caller can mark what is left.
func classifyWithLLM(ctx context.Context, tmSummary string, req classifyRequest, unique []EnrichedFinding, targets []int) (map[int]FindingDisposition, []ClassificationAuditEntry, classifyOutcome, error) {
	out := make(map[int]FindingDisposition)
	if len(targets) == 0 {
		return out, nil, classifyOutcome{}, nil
	}

	var batches [][]int
	for off := 0; off < len(targets); off += req.batchSize {
		batches = append(batches, targets[off:min(off+req.batchSize, len(targets))])
	}

	batchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu           sync.Mutex // guards out, unanswered and declined
		usageMu      sync.Mutex // guards req.usage
		errMu        sync.Mutex // guards abortErr and transportErr
		abortErr     error
		transportErr error
		wg           sync.WaitGroup
	)
	unanswered := make(map[int]bool)
	declined := make(map[int]llm.RefusalError)
	audit := &classificationAuditCollector{}
	sem := make(chan struct{}, triageConcurrency())

	addUsageSafe := func(u llm.Usage) {
		usageMu.Lock()
		addUsage(req.usage, u)
		usageMu.Unlock()
	}
	// setErr records the first failure and stops the other batches. An abort
	// outranks a provider failure: a suspended run must be resumed, not
	// published as incomplete.
	setErr := func(e error) {
		errMu.Lock()
		defer errMu.Unlock()
		if abortsRun(ctx, e) {
			if abortErr == nil {
				abortErr = e
			}
			cancel()
			return
		}
		if transportErr == nil {
			transportErr = e
			cancel()
		}
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
			local := classifyBatchWithRetry(batchCtx, tmSummary, req, subset, batch, addUsageSafe, setErr, audit)

			mu.Lock()
			for li, d := range local.classified {
				out[batch[li]] = d
			}
			for li, gi := range batch {
				if _, ok := local.classified[li]; ok || local.rejected[li] {
					continue
				}
				unanswered[gi] = true
				if refusal, ok := local.declined[li]; ok {
					declined[gi] = refusal
				}
			}
			mu.Unlock()
		}(batch)
	}
	wg.Wait()

	if abortErr != nil {
		return nil, audit.snapshot(), classifyOutcome{}, abortErr
	}
	if err := ctx.Err(); err != nil {
		return nil, audit.snapshot(), classifyOutcome{}, err
	}
	outcome := classifyOutcome{transportErr: transportErr}
	if transportErr == nil && len(unanswered) > 0 {
		outcome.unanswered = unanswered
		outcome.declined = declined
	}
	return out, audit.snapshot(), outcome, nil
}

// passOutcome is the result of one classification request.
type passOutcome int

const (
	passParsed passOutcome = iota
	passUnparseable
	// passDeclined: the model declined the request (stop_reason refusal).
	passDeclined
	passFailed
)

// batchResult is what the requests of one batch got, keyed by LOCAL batch
// index.
type batchResult struct {
	// classified holds the accepted verdicts.
	classified map[int]FindingDisposition
	// rejected marks the findings whose own verdict came back at least once
	// (right index, echoed identity, a supported disposition) and was
	// rejected by validation.
	rejected map[int]bool
	// declined holds the findings the model declined to classify in a
	// request that carried only that finding, with the refusal.
	declined map[int]llm.RefusalError
}

// classifyBatchWithRetry classifies a single batch and retries what is still
// unclassified up to classifyMaxRetries times. A retry is split in halves when
// the previous reply was unparseable or omitted more than a quarter of its
// findings: weaker models drop items from long requests, and resending the
// same long request tends to fail the same way.
//
// A request the model declines (stop_reason refusal) classifies nothing, and
// one finding can be enough for that. It is split in halves at once, within
// the same attempt, until the declined finding is alone, so it costs its
// batch-mates neither their verdicts nor an attempt; a finding declined on
// its own is not sent again. One such finding among n adds at most
// 2·⌈log₂ n⌉ requests to the first one; a model that declines every request
// stops after 2n−1, each finding sent on its own once.
//
// Any finding left unclassified that is neither rejected nor declined never
// got a verdict of its own, whatever its batch-mates got.
func classifyBatchWithRetry(ctx context.Context, tmSummary string, req classifyRequest, subset []EnrichedFinding, globalIndices []int, addUsageSafe func(llm.Usage), setErr func(error), audit *classificationAuditCollector) batchResult {
	out := batchResult{
		classified: make(map[int]FindingDisposition),
		rejected:   make(map[int]bool),
		declined:   make(map[int]llm.RefusalError),
	}
	res, rejected := out.classified, out.rejected

	// pass sends one request. A declined request also returns the refusal.
	pass := func(attempt int, localMap []int) (passOutcome, error) {
		items := make([]EnrichedFinding, len(localMap))
		requestIndices := make([]int, len(localMap))
		for i, localIndex := range localMap {
			items[i] = subset[localIndex]
			requestIndices[i] = globalIndices[localIndex]
		}
		disps, rawResponse, u, err := classifyBatchLLM(ctx, tmSummary, req.language, items, req.client)
		addUsageSafe(u)
		entry := newClassificationAuditEntry(attempt, requestIndices, items, rawResponse)
		if err != nil {
			// A provider error can carry the gateway URL and credentials.
			entry.ParseError = failureReason(err)
			audit.record(entry)
			switch {
			case errors.Is(err, llm.ErrRefused):
				return passDeclined, err
			case errors.Is(err, errThreatModelParse):
				return passUnparseable, nil
			}
			setErr(err)
			return passFailed, err
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
			local := localMap[d.FindingIndex]
			if _, done := res[local]; done {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: globalIndices[local], Reason: "duplicate disposition"})
				continue
			}
			validated, reject, note := validateLLMDisposition(req.projectPath, items[d.FindingIndex], d, req.policy)
			if reject != "" {
				entry.Rejected = append(entry.Rejected, AuditRejection{FindingIndex: globalIndices[local], Reason: redactFailureText(reject)})
				if verdictNamesFinding(items[d.FindingIndex], d) {
					// The model judged this finding; the verdict just did
					// not pass validation.
					rejected[local] = true
				}
				continue
			}
			if note != "" {
				entry.Downgraded = append(entry.Downgraded, AuditRejection{FindingIndex: globalIndices[local], Reason: note})
			}
			res[local] = validated
			entry.AcceptedFindingIndices = append(entry.AcceptedFindingIndices, globalIndices[local])
		}
		audit.record(entry)
		return passParsed, nil
	}

	all := make([]int, len(subset))
	for i := range all {
		all[i] = i
	}
	chunks := [][]int{all}
	for attempt := 0; attempt <= classifyMaxRetries() && len(chunks) > 0; attempt++ {
		var next [][]int
		for len(chunks) > 0 {
			chunk := chunks[0]
			chunks = chunks[1:]
			if ctx.Err() != nil {
				// Another batch hit a provider failure, or the run was cancelled.
				return out
			}
			outcome, err := pass(attempt, chunk)
			switch outcome {
			case passFailed:
				return out
			case passDeclined:
				if len(chunk) == 1 {
					// Declined on its own: no smaller request can help, and
					// the same one would most likely be declined again.
					var refusal *llm.RefusalError
					if !errors.As(err, &refusal) {
						refusal = &llm.RefusalError{}
					}
					out.declined[chunk[0]] = *refusal
					continue
				}
				// Find the declined finding within this attempt: the halves
				// are sent next, before any other chunk.
				mid := len(chunk) / 2
				chunks = append([][]int{chunk[:mid], chunk[mid:]}, chunks...)
				continue
			}
			var missing []int
			for _, local := range chunk {
				if _, done := res[local]; !done {
					missing = append(missing, local)
				}
			}
			if len(missing) > 0 {
				next = append(next, retryChunks(missing, len(chunk), outcome == passUnparseable)...)
			}
		}
		chunks = next
	}
	return out
}

// verdictNamesFinding reports whether a reply item is a verdict about the
// finding it is indexed to: it echoes the finding's identity. A verdict that
// names another finding says nothing about this one.
func verdictNamesFinding(finding EnrichedFinding, raw rawDisposition) bool {
	return raw.FindingID == findingIdentity(finding)
}

// retryChunks plans the retry of the findings a request left unclassified.
func retryChunks(missing []int, requested int, unparseable bool) [][]int {
	if len(missing) > 1 && (unparseable || 4*len(missing) > requested) {
		mid := len(missing) / 2
		return [][]int{missing[:mid], missing[mid:]}
	}
	return [][]int{missing}
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
	if errors.Is(err, llm.ErrNoAnswer) {
		// The provider answered without an answer, such as a request the
		// model declined: a reply that classifies nothing, retried in smaller
		// requests like one that cannot be parsed, not a provider failure.
		return nil, "", u, fmt.Errorf("%w: %w", errThreatModelParse, err)
	}
	if err != nil {
		return nil, "", u, fmt.Errorf("classification LLM call failed: %w", err)
	}

	items, err := decodeClassificationReply(extractJSON(response))
	if err != nil {
		return nil, response, u, fmt.Errorf("%w: %v", errThreatModelParse, err)
	}

	disps := make([]rawDisposition, 0, len(items))
	for _, d := range items {
		disps = append(disps, rawDisposition(d))
	}
	return disps, response, u, nil
}

// classificationReplyItem is one entry of a classification reply: a
// rawDisposition as the model writes it. A fingerprint the model still
// echoes, as earlier prompts asked, is dropped by the decoder and never
// checked (see validateLLMDisposition).
type classificationReplyItem struct {
	FindingIndex int                  `json:"finding_index"`
	FindingID    string               `json:"finding_id"`
	Disposition  string               `json:"disposition"`
	Confidence   string               `json:"confidence"`
	Rationale    string               `json:"rationale"`
	Evidence     *DispositionEvidence `json:"evidence"`
}

// decodeClassificationReply decodes the first JSON value of a reply, which
// must be an object with a finding_dispositions list. {}, null, a bare list
// or an error object decode without error in a lenient decoder but classify
// nothing; they are parse errors here, so the audit records why the reply
// was unusable.
func decodeClassificationReply(jsonText string) ([]classificationReplyItem, error) {
	var envelope map[string]json.RawMessage
	if err := decodeFirstJSONValue(jsonText, &envelope); err != nil {
		return nil, err
	}
	list, ok := envelope["finding_dispositions"]
	if !ok {
		return nil, errors.New("reply has no finding_dispositions list")
	}
	var items []classificationReplyItem
	if err := json.Unmarshal(list, &items); err != nil {
		return nil, fmt.Errorf("finding_dispositions is not a list of dispositions: %w", err)
	}
	if items == nil {
		return nil, errors.New("finding_dispositions is null, not a list")
	}
	return items, nil
}

// threatModelSummary renders a compact text view of the threat model for use as
// classification context (keeps SecureCoder methodology without resending the
// full repository to every batch).
func threatModelSummary(tm *ThreatModel) string {
	const unavailable = "(no threat model available)"
	if tm == nil {
		return unavailable
	}
	var sb strings.Builder
	if tm.ComponentOverview != "" {
		sb.WriteString("Overview: " + tm.ComponentOverview + "\n")
	}
	if tm.TrustBoundaries.Authentication != "" || tm.TrustBoundaries.Authorization != "" {
		fmt.Fprintf(&sb, "Trust boundaries: auth=%s; authz=%s; implicit=%s\n",
			tm.TrustBoundaries.Authentication, tm.TrustBoundaries.Authorization, tm.TrustBoundaries.ImplicitTrust)
	}
	if len(tm.EntryPoints) > 0 {
		sb.WriteString("Entry points:\n")
		for _, e := range tm.EntryPoints {
			fmt.Fprintf(&sb, "  - %s (%s), trusted=%v, validation=%s\n", e.Endpoint, e.Type, e.Trusted, e.Validation)
		}
	}
	if len(tm.PriorityAreas) > 0 {
		sb.WriteString("Priority areas: " + strings.Join(tm.PriorityAreas, "; ") + "\n")
	}
	if summary := strings.TrimSpace(sb.String()); summary != "" {
		return summary
	}
	// A reply that parsed but carried nothing usable is no threat model.
	return unavailable
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
// model omitted or returned malformed, and how many repair requests a
// malformed threat model gets. Unclassified findings fall back to Needs Manual
// Review, which is safe but is NOT stored in the verdict cache — so flaky
// providers benefit from a higher retry count in CI.
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
	fmt.Fprintf(os.Stderr, "   🔎 Triage scale: %d findings → %d unique (%d deduped) | sources: %d llm, %d cache, %d deterministic, %d nr-fallback, %d triage-failed\n",
		len(findings), len(unique), len(findings)-len(unique),
		bySource[dispositionSourceLLM], bySource[dispositionSourceCache],
		bySource[dispositionSourceDeterministic], bySource[dispositionSourceNRFallback],
		bySource[dispositionSourceTriageFailed])
}
