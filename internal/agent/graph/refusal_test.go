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

	// The run says why: the failure reason, the finding's rationale and the
	// summary name the refusal, and none of them suggests the retry tuning
	// that cannot help a declined finding.
	if state.TriageDeclined != 1 || incomplete.Declined != 1 {
		t.Fatalf("declined = %d (state %d), want 1", incomplete.Declined, state.TriageDeclined)
	}
	if !strings.Contains(state.TriageFailureReason, "claude-sonnet-5-5 declined to classify 1 finding(s) (stop_reason refusal, category cyber)") {
		t.Fatalf("failure reason = %q, want the refusal named", state.TriageFailureReason)
	}
	for _, d := range state.FindingDispositions {
		if state.EnrichedFindings[d.FindingIndex].ID == "PY-EVAL" && !strings.Contains(d.Rationale, "declined to classify this finding (stop_reason refusal, category cyber)") {
			t.Fatalf("rationale = %q, want the refusal named", d.Rationale)
		}
	}
	for _, want := range []string{"1 not triaged: the model declined to classify them", "the model declined to classify 1 of them and is likely to decline them again"} {
		if !strings.Contains(state.SummaryMarkdown, want) {
			t.Fatalf("summary lacks %q:\n%s", want, state.SummaryMarkdown)
		}
	}
	if strings.Contains(state.SummaryMarkdown, "AITRIAGE_CLASSIFY_RETRIES") {
		t.Fatalf("summary suggests retry tuning for a declined finding:\n%s", state.SummaryMarkdown)
	}
	if remedy := incomplete.Remedy(); !strings.Contains(remedy, "review them by hand") || strings.Contains(remedy, "provider is available") {
		t.Fatalf("remedy = %q, want a review by hand", remedy)
	}
}

// ceilLog2 returns ⌈log₂ n⌉ for n ≥ 1.
func ceilLog2(n int) int {
	depth := 0
	for size := 1; size < n; size *= 2 {
		depth++
	}
	return depth
}

// One finding the model always declines takes no other finding of its batch
// down with it. The declined request is split in halves within the same
// attempt until that finding is alone, so neither the attempts nor the
// batch-mates are spent on it, and the finding declined on its own is not
// sent again. With 40 findings in one batch that is at most
// 1 + 2·⌈log₂ 40⌉ = 13 requests, whatever the number of retries.
func TestClassifyIsolatesTheOneFindingTheModelDeclines(t *testing.T) {
	const n = 40
	bound := 1 + 2*ceilLog2(n)
	if bound != 13 {
		t.Fatalf("bound = %d, want 13", bound)
	}
	for _, retries := range []string{"", "0"} {
		for _, poison := range []int{0, 17, n - 1} {
			t.Run(fmt.Sprintf("retries=%q/declined=R-%d", retries, poison), func(t *testing.T) {
				hermeticRun(t)
				t.Setenv("AITRIAGE_CLASSIFY_RETRIES", retries)
				declinedID := fmt.Sprintf("R-%d", poison)
				alone := 0
				mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
					for _, f := range batch {
						if f.ID == declinedID {
							if len(batch) == 1 {
								alone++
							}
							return "", declined("cyber")
						}
					}
					return classifyAllByCount(len(batch), "True Positive"), nil
				}}
				var usage llm.Usage

				_, disps, err := ClassifyFindings(context.Background(), "", "p", makeFindings(n), mock, &usage, n)
				var incomplete *TriageIncompleteError
				if !errors.As(err, &incomplete) {
					t.Fatalf("err = %v, want an incomplete triage for the declined finding", err)
				}
				if incomplete.Cause != TriageFailureCauseNoVerdict || incomplete.Unclassified != 1 || incomplete.Declined != 1 {
					t.Fatalf("incomplete = %+v, want one declined finding without a verdict (no_verdict)", incomplete)
				}
				if !strings.Contains(incomplete.Reason, "declined to classify 1 finding(s) (stop_reason refusal, category cyber), each sent on its own") {
					t.Fatalf("reason = %q, want the refusal named", incomplete.Reason)
				}
				for i, d := range disps {
					if i == poison {
						if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceTriageFailed ||
							!strings.Contains(d.Rationale, "declined to classify this finding (stop_reason refusal, category cyber)") {
							t.Fatalf("declined finding: %+v, want Needs Manual Review, triage-failed, the refusal named", d)
						}
						continue
					}
					if d.Disposition != "True Positive" || d.DispositionSource != dispositionSourceLLM {
						t.Fatalf("finding %d: %+v, want the model's verdict", i, d)
					}
				}
				if alone != 1 {
					t.Fatalf("the declined finding was sent on its own %d times, want once", alone)
				}
				if mock.classifyCalls > bound {
					t.Fatalf("classification requests = %d, want at most %d", mock.classifyCalls, bound)
				}
			})
		}
	}
}

// A batch of one finding the model declines is not sent again in a later
// attempt: the same request would be declined the same way.
func TestClassifyDoesNotResendADeclinedFinding(t *testing.T) {
	hermeticRun(t)
	mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		if batch[0].ID == "R-1" {
			return "", declined("")
		}
		return classifyAllByCount(len(batch), "True Positive"), nil
	}}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", makeFindings(3), mock, &usage, 1)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) || incomplete.Declined != 1 || incomplete.Unclassified != 1 {
		t.Fatalf("err = %v, want one declined finding", err)
	}
	if mock.classifyCalls != 3 {
		t.Fatalf("classification requests = %d, want 3: one per finding, the declined one not sent again", mock.classifyCalls)
	}
	if !strings.Contains(disps[1].Rationale, "(stop_reason refusal, category none)") {
		t.Fatalf("rationale = %q, want the refusal without a category", disps[1].Rationale)
	}
}

// A finding the model declines and one it keeps leaving out are told apart:
// both stay without a verdict, the reason names each cause, and only the
// declined finding's rationale names the refusal.
func TestClassifyTellsADeclinedFindingFromAMissingOne(t *testing.T) {
	hermeticRun(t)
	mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		verdicts := map[int]string{}
		for i, f := range batch {
			switch f.ID {
			case "R-6":
				return "", declined("cyber")
			case "R-2":
				// Left out of every reply.
			default:
				verdicts[i] = "True Positive"
			}
		}
		return classifyIndices(verdicts), nil
	}}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", makeFindings(8), mock, &usage, 8)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) || incomplete.Unclassified != 2 || incomplete.Declined != 1 {
		t.Fatalf("err = %v (%+v), want two findings without a verdict, one declined", err, incomplete)
	}
	for _, want := range []string{"declined to classify 1 finding(s) (stop_reason refusal, category cyber)", "no reply carried a verdict for 1 other finding(s)"} {
		if !strings.Contains(incomplete.Reason, want) {
			t.Fatalf("reason = %q, want %q", incomplete.Reason, want)
		}
	}
	if !strings.Contains(disps[6].Rationale, "declined to classify this finding") {
		t.Fatalf("declined finding rationale = %q", disps[6].Rationale)
	}
	if strings.Contains(disps[2].Rationale, "declined to classify this finding") || disps[2].DispositionSource != dispositionSourceTriageFailed {
		t.Fatalf("missing finding = %+v, want triage-failed without the refusal", disps[2])
	}
	for _, i := range []int{0, 1, 3, 4, 5, 7} {
		if disps[i].DispositionSource != dispositionSourceLLM {
			t.Fatalf("finding %d: %+v, want the model's verdict", i, disps[i])
		}
	}
	if remedy := incomplete.Remedy(); !strings.Contains(remedy, "review them by hand") || !strings.Contains(remedy, "for the rest, re-run") {
		t.Fatalf("remedy = %q, want both remedies", remedy)
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
