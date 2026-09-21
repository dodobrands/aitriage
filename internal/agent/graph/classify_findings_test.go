package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// fakeLLM is a content-aware mock. It distinguishes threat-model build requests
// from classification requests by inspecting the system prompt, so it is robust
// to the bounded-concurrency batching (which is pinned to 1 worker in tests).
type fakeLLM struct {
	t               *testing.T
	tmBody          string
	tmErr           error
	tmCalls         int
	classifyHandler func(call int, batch []EnrichedFinding) (string, error)
	classifyCalls   int
}

func (m *fakeLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	system := messages[0].Content
	user := messages[1].Content

	if strings.Contains(system, "Threat Model & Finding Classification") {
		m.tmCalls++
		if m.tmErr != nil {
			return "", llm.Usage{}, m.tmErr
		}
		body := m.tmBody
		if body == "" {
			body = `{"component_overview":"c","priority_areas":["p"]}`
		}
		return body, llm.Usage{}, nil
	}

	if strings.Contains(system, "Finding Classification") {
		call := m.classifyCalls
		m.classifyCalls++
		promptBatch := parsePromptBatchFromUser(user)
		batch := make([]EnrichedFinding, len(promptBatch))
		for i, item := range promptBatch {
			batch[i] = item.Finding
		}
		if m.classifyHandler == nil {
			return classifyAll(promptBatch, "True Positive"), llm.Usage{}, nil
		}
		body, err := m.classifyHandler(call, batch)
		return bindPromptIdentities(body, promptBatch), llm.Usage{}, err
	}

	m.t.Fatalf("unexpected LLM call with system prompt: %.80s", system)
	return "", llm.Usage{}, nil
}

// parsePromptBatchFromUser extracts the identity-bound findings JSON array
// embedded in a classification user prompt.
func parsePromptBatchFromUser(user string) []classificationPromptFinding {
	findingsMarker := strings.Index(user, "## Findings to classify")
	if findingsMarker < 0 {
		return nil
	}
	i := strings.Index(user[findingsMarker:], "[")
	if i < 0 {
		return nil
	}
	i += findingsMarker
	dec := json.NewDecoder(strings.NewReader(user[i:]))
	var fs []classificationPromptFinding
	_ = dec.Decode(&fs)
	return fs
}

// parseBatchFromUser remains available to the PoC test mock, whose prompt uses
// the older plain EnrichedFinding array.
func parseBatchFromUser(user string) []EnrichedFinding {
	i := strings.Index(user, "[")
	if i < 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(user[i:]))
	var findings []EnrichedFinding
	_ = dec.Decode(&findings)
	return findings
}

// classifyAll builds an identity-bound classification response covering every
// local prompt finding.
func classifyAll(batch []classificationPromptFinding, disposition string) string {
	var sb strings.Builder
	sb.WriteString(`{"finding_dispositions":[`)
	for i, finding := range batch {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{"finding_index":%d,"finding_id":%q,"fingerprint":%q,"disposition":%q,"confidence":"high","rationale":"r"}`, i, finding.FindingID, finding.Fingerprint, disposition))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func classifyAllByCount(count int, disposition string) string {
	var sb strings.Builder
	sb.WriteString(`{"finding_dispositions":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{"finding_index":%d,"disposition":%q,"confidence":"high","rationale":"r"}`, i, disposition))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

// bindPromptIdentities emulates the exact identity echo required from a real
// provider while preserving test handlers that focus only on index behavior.
func bindPromptIdentities(body string, batch []classificationPromptFinding) string {
	var raw struct {
		FindingDispositions []struct {
			FindingIndex int                  `json:"finding_index"`
			FindingID    string               `json:"finding_id"`
			Fingerprint  string               `json:"fingerprint"`
			Disposition  string               `json:"disposition"`
			Confidence   string               `json:"confidence"`
			Rationale    string               `json:"rationale"`
			Evidence     *DispositionEvidence `json:"evidence,omitempty"`
		} `json:"finding_dispositions"`
	}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return body
	}
	for i := range raw.FindingDispositions {
		d := &raw.FindingDispositions[i]
		if d.FindingIndex < 0 || d.FindingIndex >= len(batch) {
			continue
		}
		if d.FindingID == "" {
			d.FindingID = batch[d.FindingIndex].FindingID
		}
		if d.Fingerprint == "" {
			d.Fingerprint = batch[d.FindingIndex].Fingerprint
		}
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return string(out)
}

func classifyIndices(pairs map[int]string) string {
	var sb strings.Builder
	sb.WriteString(`{"finding_dispositions":[`)
	first := true
	for idx, disp := range pairs {
		if !first {
			sb.WriteString(",")
		}
		first = false
		sb.WriteString(fmt.Sprintf(`{"finding_index":%d,"disposition":%q,"confidence":"medium","rationale":"r"}`, idx, disp))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func makeFindings(n int) []EnrichedFinding {
	fs := make([]EnrichedFinding, n)
	for i := range fs {
		fs[i] = EnrichedFinding{
			ID:       fmt.Sprintf("R-%d", i),
			VulnID:   fmt.Sprintf("CS-MISC-%03d", i+1),
			Type:     "core",
			Severity: "HIGH",
			File:     fmt.Sprintf("file_%d.go", i),
			Line:     i + 1,
			Message:  "m",
		}
	}
	return fs
}

func pinConcurrency(t *testing.T) {
	t.Helper()
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
}

// Req: >150 findings must all be classified across batches, none dropped.
func TestClassifyFindingsClassifiesAllAcrossBatches(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(218)
	mock := &fakeLLM{t: t} // default handler classifies everything TP
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(disps) != 218 {
		t.Fatalf("want 218 dispositions, got %d", len(disps))
	}
	if mock.tmCalls != 1 {
		t.Fatalf("threat model must be built exactly once, got %d calls", mock.tmCalls)
	}
	tp, fp, nr := countDispositions(disps)
	if tp != 218 || fp != 0 || nr != 0 {
		t.Fatalf("want all 218 TP, got tp=%d fp=%d nr=%d", tp, fp, nr)
	}
	for i, d := range disps {
		if d.FindingIndex != i {
			t.Fatalf("disposition %d has wrong index %d", i, d.FindingIndex)
		}
		if d.DispositionSource != dispositionSourceLLM {
			t.Fatalf("disposition %d source = %q, want llm", i, d.DispositionSource)
		}
	}
}

// Req: omitted findings are retried; anything still missing defaults to NR
// (never FP), and the pipeline does not crash.
func TestClassifyFindingsPartialResponseFallsBackToNeedsReview(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(3)
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			switch call {
			case 0: // first pass over [0,1,2]: classify only local 0
				return classifyIndices(map[int]string{0: "True Positive"}), nil
			case 1: // retry over missing [1,2]: classify only local 0 -> global 1
				return classifyIndices(map[int]string{0: "True Positive"}), nil
			default: // retry over [2]: classify nothing
				return `{"finding_dispositions":[]}`, nil
			}
		},
	}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disps[0].Disposition != "True Positive" || disps[1].Disposition != "True Positive" {
		t.Fatalf("disps[0],[1] should be TP, got %q,%q", disps[0].Disposition, disps[1].Disposition)
	}
	if disps[2].Disposition != "Needs Manual Review" {
		t.Fatalf("disps[2] should be NR, got %q", disps[2].Disposition)
	}
	if disps[2].DispositionSource != dispositionSourceNRFallback {
		t.Fatalf("disps[2] source = %q, want nr-fallback", disps[2].DispositionSource)
	}
	if _, fp, _ := countDispositions(disps); fp != 0 {
		t.Fatalf("no finding may default to False Positive, got fp=%d", fp)
	}
}

// Req: unsupported disposition strings are rejected and default to NR, never FP.
func TestClassifyFindingsRejectsUnsupportedDisposition(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(1)
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			return classifyIndices(map[int]string{0: "Maybe"}), nil
		},
	}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disps[0].Disposition != "Needs Manual Review" {
		t.Fatalf("unsupported disposition should fall back to NR, got %q", disps[0].Disposition)
	}
}

// Req: a malformed classification response is tolerated (NR fallback), not fatal.
func TestClassifyFindingsToleratesMalformedClassification(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(2)
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			return "not json at all", nil
		},
	}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("malformed classification should be tolerated, got error: %v", err)
	}
	for i, d := range disps {
		if d.Disposition != "Needs Manual Review" {
			t.Fatalf("disps[%d] should be NR, got %q", i, d.Disposition)
		}
	}
}

// Req: a malformed THREAT MODEL response is fatal (don't mask a broken provider).
func TestClassifyFindingsThreatModelParseErrorFails(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(2)
	mock := &fakeLLM{t: t, tmBody: "garbage, not json"}
	var usage llm.Usage

	_, _, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err == nil {
		t.Fatal("expected error on malformed threat-model response")
	}
}

// Req: transport failure building the threat model must fail the pipeline.
func TestClassifyFindingsThreatModelTransportErrorFails(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(2)
	mock := &fakeLLM{t: t, tmErr: fmt.Errorf("network down")}
	var usage llm.Usage

	_, _, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err == nil {
		t.Fatal("expected error on threat-model transport failure")
	}
}

// Req: transport failure during classification must fail the pipeline (no masking).
func TestClassifyFindingsClassificationTransportErrorFails(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(2)
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			return "", fmt.Errorf("network down")
		},
	}
	var usage llm.Usage

	_, _, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err == nil {
		t.Fatal("expected error on classification transport failure")
	}
}

// Layer 1: identical findings are deduped and the verdict is projected to all.
func TestClassifyFindingsDedupProjectsVerdict(t *testing.T) {
	pinConcurrency(t)
	dup := EnrichedFinding{ID: "R-x", VulnID: "CS-MISC-001", Type: "core", Severity: "HIGH", File: "a.go", Line: 10, Message: "same"}
	other := EnrichedFinding{ID: "R-y", VulnID: "CS-MISC-002", Type: "core", Severity: "HIGH", File: "b.go", Line: 20, Message: "diff"}
	findings := []EnrichedFinding{dup, dup, other}

	var batchSizes []int
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			batchSizes = append(batchSizes, len(batch))
			return classifyAllByCount(len(batch), "True Positive"), nil
		},
	}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(disps) != 3 {
		t.Fatalf("want 3 projected dispositions, got %d", len(disps))
	}
	// Only 2 unique findings should have been classified by the LLM.
	if len(batchSizes) == 0 || batchSizes[0] != 2 {
		t.Fatalf("expected LLM to classify 2 unique findings, got batch sizes %v", batchSizes)
	}
	if disps[0].Fingerprint != disps[1].Fingerprint {
		t.Fatalf("identical findings must share a fingerprint")
	}
	if disps[0].Disposition != disps[1].Disposition {
		t.Fatalf("identical findings must share a disposition")
	}
}

// Layer 5: exceeding the LLM budget defaults the overflow to NR, never dropping.
func TestClassifyFindingsBudgetOverflowToNR(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_LLM_BUDGET", "1")
	findings := makeFindings(3)
	mock := &fakeLLM{t: t}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	llmCount, nrCount := 0, 0
	for _, d := range disps {
		switch d.DispositionSource {
		case dispositionSourceLLM:
			llmCount++
		case dispositionSourceNRFallback:
			nrCount++
		}
	}
	if llmCount != 1 || nrCount != 2 {
		t.Fatalf("budget=1 should yield 1 llm + 2 nr-fallback, got llm=%d nr=%d", llmCount, nrCount)
	}
	if _, fp, _ := countDispositions(disps); fp != 0 {
		t.Fatalf("budget overflow must never become FP, got fp=%d", fp)
	}
}

// Layer 3: gating sends only HIGH/CRITICAL to the LLM; the rest get a
// deterministic NR (never a silent FP).
func TestClassifyFindingsGatingDeterministicForLowSeverity(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_GATING", "on")
	findings := []EnrichedFinding{
		{ID: "R-1", VulnID: "CS-MISC-001", Type: "core", Severity: "HIGH", File: "a.go", Line: 1, Message: "m1"},
		{ID: "R-2", VulnID: "CS-MISC-002", Type: "core", Severity: "LOW", File: "b.go", Line: 2, Message: "m2"},
	}
	mock := &fakeLLM{t: t}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disps[0].DispositionSource != dispositionSourceLLM {
		t.Fatalf("HIGH finding should be triaged by LLM, source=%q", disps[0].DispositionSource)
	}
	if disps[1].DispositionSource != dispositionSourceDeterministic {
		t.Fatalf("LOW finding should be deterministic, source=%q", disps[1].DispositionSource)
	}
	if disps[1].Disposition == "False Positive" {
		t.Fatalf("gated-out finding must never be auto-FP")
	}
}

func TestClassifyFindingsFullCacheHitSkipsThreatModelAndClassification(t *testing.T) {
	pinConcurrency(t)
	dir := t.TempDir()
	t.Setenv("AITRIAGE_CACHE_DIR", dir)
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")

	findings := makeFindings(2)
	cache := newVerdictCache("")
	for _, finding := range findings {
		cache.Set(Fingerprint(finding), FindingDisposition{
			Disposition: "True Positive",
			Rationale:   "cached",
			Confidence:  "high",
		})
	}
	cache.Save()

	mock := &fakeLLM{t: t, tmErr: fmt.Errorf("threat model should not be called")}
	var usage llm.Usage

	tm, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm != nil {
		t.Fatalf("threat model = %+v, want nil on full cache hit", tm)
	}
	if mock.tmCalls != 0 || mock.classifyCalls != 0 {
		t.Fatalf("full cache hit should skip LLM calls, got tm=%d classify=%d", mock.tmCalls, mock.classifyCalls)
	}
	for i, d := range disps {
		if d.DispositionSource != dispositionSourceCache {
			t.Fatalf("disposition %d source = %q, want cache", i, d.DispositionSource)
		}
	}
}

func TestClassifyFindingsInvalidCachedFalsePositiveFallsBackToLLM(t *testing.T) {
	pinConcurrency(t)
	dir := t.TempDir()
	project := t.TempDir()
	t.Setenv("AITRIAGE_CACHE_DIR", dir)
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")

	findings := makeFindings(1)
	cache := newVerdictCache("")
	cache.Set(Fingerprint(findings[0]), FindingDisposition{
		Disposition: "False Positive",
		Rationale:   "cached fp",
		Confidence:  "high",
		Evidence: &DispositionEvidence{
			Basis:    "code_mitigation",
			File:     findings[0].File,
			Line:     findings[0].Line,
			Observed: "missing mitigation",
		},
	})
	cache.Save()

	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			if len(batch) != 1 {
				t.Fatalf("classification batch size = %d, want 1", len(batch))
			}
			return classifyAllByCount(len(batch), "True Positive"), nil
		},
	}
	var usage llm.Usage

	tm, disps, _, stats, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm == nil || mock.tmCalls != 1 || mock.classifyCalls != 1 {
		t.Fatalf("invalid cached FP should fall back to normal LLM path, tm=%+v tmCalls=%d classifyCalls=%d", tm, mock.tmCalls, mock.classifyCalls)
	}
	if disps[0].Disposition != "True Positive" || disps[0].DispositionSource != dispositionSourceLLM {
		t.Fatalf("disposition = %+v, want LLM true positive", disps[0])
	}
	if stats.Hits != 1 || stats.InvalidatedFalsePositives != 1 || stats.Stores != 1 {
		t.Fatalf("cache stats = %+v, want hit + invalidated stale FP + stored LLM verdict", stats)
	}
}

func TestClassifyFindingsPartialCacheHitBuildsThreatModelForUncachedFindings(t *testing.T) {
	pinConcurrency(t)
	dir := t.TempDir()
	t.Setenv("AITRIAGE_CACHE_DIR", dir)
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")

	findings := makeFindings(2)
	cache := newVerdictCache("")
	cache.Set(Fingerprint(findings[0]), FindingDisposition{
		Disposition: "True Positive",
		Rationale:   "cached",
		Confidence:  "high",
	})
	cache.Save()

	var batchSizes []int
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			batchSizes = append(batchSizes, len(batch))
			return classifyAllByCount(len(batch), "True Positive"), nil
		},
	}
	var usage llm.Usage

	tm, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm == nil {
		t.Fatal("partial cache hit should still build a threat model")
	}
	if mock.tmCalls != 1 || mock.classifyCalls != 1 {
		t.Fatalf("partial cache hit should call threat model and one classification batch, got tm=%d classify=%d", mock.tmCalls, mock.classifyCalls)
	}
	if len(batchSizes) != 1 || batchSizes[0] != 1 {
		t.Fatalf("classification batch sizes = %v, want one uncached finding", batchSizes)
	}
	if disps[0].DispositionSource != dispositionSourceCache {
		t.Fatalf("cached finding source = %q, want cache", disps[0].DispositionSource)
	}
	if disps[1].DispositionSource != dispositionSourceLLM {
		t.Fatalf("uncached finding source = %q, want llm", disps[1].DispositionSource)
	}
}
