package graph

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// pocLLM is a content-aware mock for the PoC verification step.
type pocLLM struct {
	t           *testing.T
	handler     func(call int, batch []EnrichedFinding) (string, error)
	calls       int
	seenBatches [][]EnrichedFinding
}

func (m *pocLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	if !strings.Contains(messages[0].Content, "PoC Verification") {
		m.t.Fatalf("unexpected non-PoC call")
	}
	batch := parseBatchFromUser(messages[1].Content)
	m.seenBatches = append(m.seenBatches, batch)
	call := m.calls
	m.calls++
	if m.handler == nil {
		return pocResultsJSON(len(batch)), llm.Usage{}, nil
	}
	body, err := m.handler(call, batch)
	return body, llm.Usage{}, err
}

func pocResultsJSON(n int) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"vulnerability_type":"x","severity":"HIGH","conclusion":"Exploitable"}`)
	}
	sb.WriteString("]")
	return sb.String()
}

func tpFindings(n int) []EnrichedFinding {
	fs := make([]EnrichedFinding, n)
	for i := range fs {
		fs[i] = EnrichedFinding{ID: fmt.Sprintf("R-%d", i), Severity: "HIGH", File: fmt.Sprintf("f%d.go", i), Line: i + 1, Message: "m"}
	}
	return fs
}

func TestVerifyPoCsDedup(t *testing.T) {
	pinConcurrency(t)
	dup := EnrichedFinding{ID: "r", Severity: "HIGH", File: "a.go", Line: 1, Message: "same"}
	other := EnrichedFinding{ID: "r2", Severity: "HIGH", File: "b.go", Line: 2, Message: "diff"}
	mock := &pocLLM{t: t}
	var usage llm.Usage

	_, _, err := verifyPoCs(context.Background(), "", []EnrichedFinding{dup, dup, other}, mock, &usage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only 2 unique TPs should reach the LLM (single batch).
	if len(mock.seenBatches) != 1 || len(mock.seenBatches[0]) != 2 {
		t.Fatalf("expected 1 batch of 2 unique findings, got %v", mock.seenBatches)
	}
}

func TestVerifyPoCsBudgetOverflowToNeedsReview(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_POC_BUDGET", "1")
	mock := &pocLLM{t: t}
	var usage llm.Usage

	results, _, err := verifyPoCs(context.Background(), "", tpFindings(3), mock, &usage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nr := 0
	for _, r := range results {
		if r.Conclusion == "Needs Manual Review" {
			nr++
		}
	}
	if nr != 2 {
		t.Fatalf("budget=1 over 3 TPs should yield 2 NR results, got %d (results=%d)", nr, len(results))
	}
}

func TestVerifyPoCsTransportErrorFatal(t *testing.T) {
	pinConcurrency(t)
	mock := &pocLLM{t: t, handler: func(call int, batch []EnrichedFinding) (string, error) {
		return "", fmt.Errorf("network down")
	}}
	var usage llm.Usage

	_, stats, err := verifyPoCs(context.Background(), "", tpFindings(2), mock, &usage)
	if err == nil {
		t.Fatal("expected error on PoC transport failure")
	}
	if stats.TransportErrors != 1 {
		t.Fatalf("transport errors = %d, want 1", stats.TransportErrors)
	}
}

func TestVerifyPoCsMalformedTolerated(t *testing.T) {
	pinConcurrency(t)
	mock := &pocLLM{t: t, handler: func(call int, batch []EnrichedFinding) (string, error) {
		return "not json", nil
	}}
	var usage llm.Usage

	results, stats, err := verifyPoCs(context.Background(), "", tpFindings(2), mock, &usage)
	if err != nil {
		t.Fatalf("malformed PoC response should be tolerated, got: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("malformed batch should yield no results, got %d", len(results))
	}
	if stats.ParseFailures != 1 {
		t.Fatalf("parse failures = %d, want 1", stats.ParseFailures)
	}
}

func TestVerifyPoCsSafetyRefusalToNeedsReview(t *testing.T) {
	pinConcurrency(t)
	mock := &pocLLM{t: t, handler: func(call int, batch []EnrichedFinding) (string, error) {
		return "I cannot assist with exploit payloads, but recommend defensive review.", nil
	}}
	var usage llm.Usage

	results, stats, err := verifyPoCs(context.Background(), "", tpFindings(2), mock, &usage)
	if err != nil {
		t.Fatalf("safety refusal should not fail PoC verification: %v", err)
	}
	if stats.Refusals != 2 {
		t.Fatalf("refusals = %d, want 2", stats.Refusals)
	}
	if len(results) != 2 {
		t.Fatalf("refusal should create one NR result per finding, got %d", len(results))
	}
	for _, result := range results {
		if result.Conclusion != "Needs Manual Review" {
			t.Fatalf("refusal conclusion = %q, want Needs Manual Review", result.Conclusion)
		}
	}
}
