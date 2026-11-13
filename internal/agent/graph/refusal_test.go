package graph

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// A request the model declines (stop_reason "refusal") is a failed request
// whose reply carries no answer. Each stage handles it the way it handles a
// reply it cannot use: never as an answer, and not as a provider outage.

func declined(category string) error {
	return fmt.Errorf("anthropic chat error: %w", &llm.RefusalError{Model: "claude-sonnet-5-5", Category: category})
}

// A declined classification batch is retried in smaller requests, like a
// reply that classifies nothing: the findings the model does classify get
// their verdicts, and the one it keeps declining is left without a verdict,
// which blocks the gate as missing output.
func TestRunRetriesADeclinedClassificationBatchInHalves(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.classify = func(_ int, batch []classificationPromptFinding) (string, error) {
		for _, item := range batch {
			if item.Finding.ID == "PY-EVAL" {
				return "", declined("cyber")
			}
		}
		return classifyAll(batch, "True Positive"), nil
	}
	state := degradedRunState(t, healthcheck.FailOnConfirmed)

	err := Run(context.Background(), state, stub)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("Run() error = %v, want a TriageIncompleteError", err)
	}
	if incomplete.Cause != TriageFailureCauseNoVerdict || incomplete.Unclassified != 1 {
		t.Fatalf("incomplete = %+v, want one finding without a verdict (no_verdict), not a provider failure", incomplete)
	}
	if !slices.Contains(stub.batchSizes, 1) {
		t.Fatalf("batch sizes = %v, want the declined batch retried in halves", stub.batchSizes)
	}
	for _, d := range state.FindingDispositions {
		want := dispositionSourceLLM
		if state.EnrichedFindings[d.FindingIndex].ID == "PY-EVAL" {
			want = dispositionSourceTriageFailed
		}
		if d.DispositionSource != want {
			t.Errorf("%s: disposition source %s, want %s", state.EnrichedFindings[d.FindingIndex].ID, d.DispositionSource, want)
		}
	}
	if !hasBlockingReason(state.HealthCheck.Verdict, healthcheck.ReasonTriageIncomplete) {
		t.Fatalf("verdict = %+v, want the gate blocked with triage_incomplete", state.HealthCheck.Verdict)
	}
	recorded := false
	for _, entry := range state.ClassificationAudit {
		if strings.Contains(entry.ParseError, "declined the request") && strings.Contains(entry.ParseError, "category cyber") {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("audit = %+v, want the refusal and its category recorded", state.ClassificationAudit)
	}
}

// A declined threat-model request is not repaired, which would send the
// declined content again: classification runs without a threat model, and
// the degraded stage names the refusal.
func TestRunClassifiesWithoutTheThreatModelTheModelDeclined(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.threatModel = func(int, []llm.Message) (string, error) { return "", declined("cyber") }
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want a completed run without a threat model", err)
	}
	if got := stub.count("threat_model"); got != 1 {
		t.Fatalf("threat-model calls = %d, want 1", got)
	}
	if state.ThreatModel != nil || state.ThreatModelSource != threatModelSourceFailedParse {
		t.Fatalf("threat model = %+v source = %q, want nil/failed_parse", state.ThreatModel, state.ThreatModelSource)
	}
	for _, d := range state.FindingDispositions {
		if d.DispositionSource != dispositionSourceLLM {
			t.Fatalf("disposition %+v, want classified by the model", d)
		}
	}
	if len(state.StageFailures) == 0 {
		t.Fatal("no stage failure recorded")
	}
	failure := state.StageFailures[0]
	if failure.Stage != usageStageThreatModel || failure.Status != stageStatusDegraded ||
		!strings.Contains(failure.Reason, "declined the request") || !strings.Contains(failure.Reason, "category cyber") {
		t.Fatalf("stage failure = %+v, want a degraded threat_model entry naming the refusal", failure)
	}
	if state.TriageStatus != TriageStatusComplete {
		t.Fatalf("triage status = %q, want complete", state.TriageStatus)
	}
}

// A declined PoC request ends like a refusal written as text: Needs Manual
// Review results counted as refusals, and verification goes on. A reply
// with no text is a malformed batch, tolerated.
func TestVerifyPoCsDeclinedRequestToNeedsReview(t *testing.T) {
	pinConcurrency(t)
	mock := &pocLLM{t: t, handler: func(int, []EnrichedFinding) (string, error) { return "", declined("cyber") }}
	var usage llm.Usage

	results, stats, err := verifyPoCs(context.Background(), "", tpFindings(2), mock, &usage)
	if err != nil {
		t.Fatalf("a declined PoC request must not fail verification: %v", err)
	}
	if stats.Refusals != 2 || stats.TransportErrors != 0 {
		t.Fatalf("stats = %+v, want 2 refusals and no transport error", stats)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want one Needs Manual Review result per finding", len(results))
	}
	for _, result := range results {
		if result.Conclusion != "Needs Manual Review" {
			t.Fatalf("conclusion = %q, want Needs Manual Review", result.Conclusion)
		}
	}

	empty := &pocLLM{t: t, handler: func(int, []EnrichedFinding) (string, error) {
		return "", fmt.Errorf("anthropic chat error: claude-sonnet-5-5 wrote no text (stop_reason max_tokens): %w", llm.ErrNoAnswer)
	}}
	results, stats, err = verifyPoCs(context.Background(), "", tpFindings(2), empty, &usage)
	if err != nil || len(results) != 0 || stats.ParseFailures != 1 || stats.TransportErrors != 0 {
		t.Fatalf("results %d, stats %+v, err %v; want a tolerated malformed batch", len(results), stats, err)
	}
}

// lastTurnChecker fails the test when a request does not end with a user
// turn: Claude models from Opus 4.6 on answer 400 to an assistant prefill.
type lastTurnChecker struct {
	t        *testing.T
	inner    llm.Client
	requests atomic.Int32
}

func (c *lastTurnChecker) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	c.requests.Add(1)
	if len(messages) == 0 || messages[len(messages)-1].Role != "user" {
		c.t.Errorf("a request ends with %+v, want a user turn", messages[len(messages)-1:])
	}
	return c.inner.Chat(ctx, messages)
}

// Every request of a run ends with a user turn, the threat-model repair
// request included: it is the only one that carries an earlier answer.
func TestRunRequestsEndWithAUserTurn(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.threatModel = func(call int, _ []llm.Message) (string, error) {
		if call == 0 {
			return `{"priority_areas":["a"}}`, nil
		}
		return `{"component_overview":"repaired"}`, nil
	}
	client := &lastTurnChecker{t: t, inner: stub}
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, client); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if stub.count("threat_model") != 2 {
		t.Fatalf("threat-model calls = %d, want the repair request too", stub.count("threat_model"))
	}
	for _, stage := range []string{"classification", "poc", "report", "fixspec"} {
		if stub.count(stage) == 0 {
			t.Fatalf("%s was never asked", stage)
		}
	}
	if client.requests.Load() == 0 {
		t.Fatal("no request was checked")
	}
}
