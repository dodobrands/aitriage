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

// ── Phase 5b: PoC Verification scaling (SecureCoder step 5) ───────────────────
//
// PoC verification is also SecureCoder and previously capped True Positives at
// 75 with a SILENT drop. We apply the same scaling layers: dedup identical TPs
// by fingerprint, process ALL of them in bounded-concurrency batches, and for
// anything left over by the budget emit a "Needs Manual Review" PoC result
// instead of dropping it.

// pocBatchSize is smaller than the classification batch because PoC reasoning is
// far heavier per finding (full step-by-step exploit trace).
const pocBatchSize = 25

// errPoCParse marks a malformed PoC response, tolerated per batch (the finding
// simply gets no PoC trace) rather than failing the whole pipeline.
var errPoCParse = errors.New("parse PoC JSON")

type PoCStats struct {
	Refusals        int `json:"poc_refusals"`
	ParseFailures   int `json:"poc_parse_failures"`
	TransportErrors int `json:"poc_transport_errors"`
}

// verifyPoCs runs PoC verification over ALL true-positive findings (deduped),
// returning the collected results. Transport/provider errors are fatal.
func verifyPoCs(ctx context.Context, language string, tpFindings []EnrichedFinding, llmClient llm.Client, usage *llm.Usage) ([]PoCResult, PoCStats, error) {
	if len(tpFindings) == 0 {
		return nil, PoCStats{}, nil
	}

	// Dedup identical TPs so the same vulnerability is traced only once.
	unique, _ := dedupFindings(tpFindings)

	// Optional budget: anything beyond it becomes a Needs-Manual-Review result.
	var overflow []EnrichedFinding
	if budget := pocBudget(); budget >= 0 && len(unique) > budget {
		overflow = unique[budget:]
		unique = unique[:budget]
	}

	var batches [][]EnrichedFinding
	for off := 0; off < len(unique); off += pocBatchSize {
		batches = append(batches, unique[off:min(off+pocBatchSize, len(unique))])
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex
		usageMu  sync.Mutex
		errMu    sync.Mutex
		statsMu  sync.Mutex
		firstErr error
		results  []PoCResult
		stats    PoCStats
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, triageConcurrency())
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
		go func(batch []EnrichedFinding) {
			defer wg.Done()
			defer func() { <-sem }()

			res, u, batchStats, err := pocBatchLLM(ctx, language, batch, llmClient)
			usageMu.Lock()
			addUsage(usage, u)
			usageMu.Unlock()
			statsMu.Lock()
			stats.Refusals += batchStats.Refusals
			stats.ParseFailures += batchStats.ParseFailures
			stats.TransportErrors += batchStats.TransportErrors
			statsMu.Unlock()
			if err != nil {
				// Malformed PoC responses are tolerated; only transport errors abort.
				if !errors.Is(err, errPoCParse) {
					setErr(err)
				}
				return
			}
			mu.Lock()
			results = append(results, res...)
			mu.Unlock()
		}(batch)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, stats, firstErr
	}

	// Budget overflow: never silently dropped — surfaced as Needs Manual Review.
	for _, f := range overflow {
		results = append(results, PoCResult{
			VulnerabilityType: pocTypeOf(f),
			Severity:          f.Severity,
			AffectedFile:      f.File,
			Conclusion:        "Needs Manual Review",
		})
	}

	return results, stats, nil
}

// pocBatchLLM verifies a single batch of findings. Transport errors are wrapped
// plainly; malformed JSON is wrapped with errPoCParse.
func pocBatchLLM(ctx context.Context, language string, batch []EnrichedFinding, llmClient llm.Client) ([]PoCResult, llm.Usage, PoCStats, error) {
	findingsJSON, _ := json.MarshalIndent(batch, "", "  ")
	userPrompt := fmt.Sprintf(prompts.PoCUserPromptTemplate, len(batch), string(findingsJSON))

	messages := []llm.Message{
		{Role: "system", Content: prompts.PoCSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(language)},
	}

	response, u, err := llmClient.Chat(ctx, messages)
	if err != nil {
		return nil, u, PoCStats{TransportErrors: 1}, fmt.Errorf("PoC verification LLM call failed: %w", err)
	}
	if isPoCRefusal(response) {
		return pocRefusalResults(batch), u, PoCStats{Refusals: len(batch)}, nil
	}

	jsonText := extractJSON(response)
	var results []PoCResult
	if err := json.Unmarshal([]byte(jsonText), &results); err != nil {
		var single PoCResult
		if err2 := json.Unmarshal([]byte(jsonText), &single); err2 == nil {
			return []PoCResult{single}, u, PoCStats{}, nil
		}
		return nil, u, PoCStats{ParseFailures: 1}, fmt.Errorf("%w: %v", errPoCParse, err)
	}
	return results, u, PoCStats{}, nil
}

func isPoCRefusal(response string) bool {
	lower := strings.ToLower(response)
	refusalMarkers := []string{
		"i can't assist",
		"i cannot assist",
		"i can’t assist",
		"i cannot help",
		"i can't help",
		"i can’t help",
		"unable to assist",
		"not able to assist",
		"not able to provide",
		"can't provide",
		"cannot provide",
		"can’t provide",
		"safety policy",
	}
	for _, marker := range refusalMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func pocRefusalResults(batch []EnrichedFinding) []PoCResult {
	results := make([]PoCResult, 0, len(batch))
	for _, finding := range batch {
		results = append(results, PoCResult{
			VulnerabilityType: pocTypeOf(finding),
			Severity:          finding.Severity,
			AffectedFile:      finding.File,
			ReasoningSteps: []PoCStep{{
				Step:        json.Number("1"),
				Description: "Provider returned a safety refusal instead of a defensive PoC assessment.",
				Result:      "Needs Manual Review; no exploit payload was generated or persisted.",
			}},
			Conclusion:     "Needs Manual Review",
			ExploitBlocked: nil,
		})
	}
	return results
}

func pocTypeOf(f EnrichedFinding) string {
	if f.ID != "" {
		return f.ID
	}
	return strings.TrimSpace(f.Message)
}

// pocBudget caps how many unique TP findings get a (heavy) PoC trace.
// Negative (default) means unlimited.
func pocBudget() int {
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_POC_BUDGET")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return -1
}
