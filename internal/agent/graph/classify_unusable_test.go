package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// Missing model output must never let the gate pass. A finding no reply ever
// carried a verdict of its own for is triage-failed, exactly like a provider
// failure, whatever shape the useless replies had. A finding whose own verdict
// came back and was rejected by validation is an ordinary fallback: the model
// judged it. Both are decided per finding.

// unusableReplies are parseable or near-parseable replies that carry no
// verdict for any finding of the request. Each takes the request's prompt
// findings.
var unusableReplies = map[string]func(batch []classificationPromptFinding) string{
	"empty object":     func([]classificationPromptFinding) string { return `{}` },
	"null":             func([]classificationPromptFinding) string { return `null` },
	"empty list":       func([]classificationPromptFinding) string { return `{"finding_dispositions":[]}` },
	"null list":        func([]classificationPromptFinding) string { return `{"finding_dispositions":null}` },
	"error object":     func([]classificationPromptFinding) string { return `{"error":"rate limited, try later"}` },
	"array":            func([]classificationPromptFinding) string { return `[]` },
	"unparseable text": func([]classificationPromptFinding) string { return "I cannot classify these findings." },
	"unsupported disposition": func(batch []classificationPromptFinding) string {
		return classifyAll(batch, "Probably fine")
	},
	"wrong identity": func(batch []classificationPromptFinding) string {
		var entries []string
		for i := range batch {
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"finding_id":"CS-OTHER-000","fingerprint":"wrong","disposition":"True Positive","confidence":"high","rationale":"r"}`, i))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`
	},
	"out-of-range indexes": func(batch []classificationPromptFinding) string {
		var entries []string
		for i := range batch {
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"True Positive","confidence":"high","rationale":"r"}`, len(batch)+i))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`
	},
}

func TestClassifyFindingsWithoutAnyAcceptedVerdictIsTriageFailure(t *testing.T) {
	for name, reply := range unusableReplies {
		t.Run(name, func(t *testing.T) {
			pinConcurrency(t)
			t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
			findings := makeFindings(3)
			calls := 0
			client := llmFunc(func(messages []llm.Message) (string, error) {
				if strings.Contains(messages[0].Content, "Threat Model & Finding Classification") {
					return `{"component_overview":"c"}`, nil
				}
				calls++
				return reply(parsePromptBatchFromUser(messages[1].Content)), nil
			})
			var usage llm.Usage

			_, disps, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", t.TempDir(), "", findings, client, &usage, 40)
			var incomplete *TriageIncompleteError
			if !errors.As(err, &incomplete) || incomplete.Stage != usageStageClassification {
				t.Fatalf("err = %v, want a classification-stage TriageIncompleteError", err)
			}
			if incomplete.Unclassified != 3 || !strings.Contains(incomplete.Reason, "no usable classification") {
				t.Fatalf("incomplete = %+v, want 3 unclassified findings and the reason", incomplete)
			}
			for i, d := range disps {
				if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceTriageFailed {
					t.Fatalf("disps[%d] = %+v, want triage-failed Needs Manual Review", i, d)
				}
			}
			if calls < classifyMaxRetries()+1 {
				t.Fatalf("classification calls = %d, want the request retried before giving up", calls)
			}
			if len(audit) != calls {
				t.Fatalf("audit has %d entries for %d replies, want every reply recorded", len(audit), calls)
			}
			for _, entry := range audit {
				if entry.ParseError == "" && len(entry.Rejected) == 0 && len(entry.AcceptedFindingIndices) == 0 && len(entry.FindingIDs) > 0 && name != "empty list" {
					t.Fatalf("audit entry %+v says nothing about why the reply was unusable", entry)
				}
			}
		})
	}
}

// The review reproduction: under fail_on=confirmed a provider whose every
// reply classifies nothing used to pass the gate with exit status 0. The run
// is now an incomplete triage and the gate blocks with triage_incomplete.
func TestRunWithUnusableClassificationRepliesBlocksConfirmedGate(t *testing.T) {
	for name, reply := range unusableReplies {
		t.Run(name, func(t *testing.T) {
			hermeticRun(t)
			stub := newStageLLM(t)
			stub.classify = func(_ int, batch []classificationPromptFinding) (string, error) { return reply(batch), nil }
			state := degradedRunState(t, healthcheck.FailOnConfirmed)

			err := Run(context.Background(), state, stub)
			if !errors.Is(err, ErrTriageIncomplete) {
				t.Fatalf("Run() error = %v, want ErrTriageIncomplete", err)
			}
			if state.TriageStatus != TriageStatusFailed || state.TriageFailureStage != usageStageClassification {
				t.Fatalf("triage status = %q stage = %q, want failed/classification", state.TriageStatus, state.TriageFailureStage)
			}
			verdict := state.HealthCheck.Verdict
			if verdict.Passed || !hasBlockingReason(verdict, healthcheck.ReasonTriageIncomplete) {
				t.Fatalf("verdict = %+v, want the gate blocked with triage_incomplete", verdict)
			}
			for _, d := range state.FindingDispositions {
				if d.DispositionSource != dispositionSourceTriageFailed {
					t.Fatalf("disposition %+v, want triage-failed", d)
				}
			}
			artifact, err := BuildTriageFindingsArtifact(state)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.TriageStatus != TriageStatusFailed || artifact.Classification.TriageFailed != 2 || artifact.Classification.NRFallback != 0 {
				t.Fatalf("artifact status = %q classification = %+v, want failed with 2 triage-failed findings", artifact.TriageStatus, artifact.Classification)
			}
		})
	}
}

// A verdict of its own that validation rejects every time is a model
// judgement that could not be accepted, not missing output: every finding is
// an ordinary fallback, Needs Manual Review, and the triage completes. Such
// findings stay unreviewed, so every gate but fail_on=confirmed still blocks
// on them, as it would on a model that answered Needs Manual Review.
func TestClassifyFindingsWithOnlyRejectedVerdictsAreOrdinaryFallbacks(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
	client := llmFunc(func(messages []llm.Message) (string, error) {
		if strings.Contains(messages[0].Content, "Threat Model & Finding Classification") {
			return `{"component_overview":"c"}`, nil
		}
		return classifyAll(parsePromptBatchFromUser(messages[1].Content), "False Positive"), nil
	})
	var usage llm.Usage
	_, disps, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", t.TempDir(), "", makeFindings(3), client, &usage, 40)
	if err != nil {
		t.Fatalf("err = %v, want a complete triage: the model judged every finding", err)
	}
	for i, d := range disps {
		if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceNRFallback {
			t.Fatalf("disps[%d] = %+v, want an nr-fallback Needs Manual Review", i, d)
		}
	}
	if !auditMentions(audit, "false positive has no evidence") {
		t.Fatalf("audit = %+v, want the rejections recorded", audit)
	}
}

// Findings are judged one by one: when a retry split leaves some findings in
// requests that never got a usable reply, those findings are triage-failed
// even though other findings of the same batch were classified.
func TestClassifyFindingsSplitRetryWithoutUsableReplyIsTriageFailure(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
	findings := makeFindings(4)
	mock := &fakeLLM{t: t, classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
		if call == 0 || batch[0].ID == "R-2" || batch[0].ID == "R-3" {
			return "not json", nil
		}
		return classifyAllByCount(len(batch), "True Positive"), nil
	}}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 40)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) || incomplete.Unclassified != 2 {
		t.Fatalf("err = %v, want a TriageIncompleteError for the 2 findings that never got a usable reply", err)
	}
	for i, want := range []string{dispositionSourceLLM, dispositionSourceLLM, dispositionSourceTriageFailed, dispositionSourceTriageFailed} {
		if disps[i].DispositionSource != want {
			t.Fatalf("disps[%d] source = %q, want %q (all: %+v)", i, disps[i].DispositionSource, want, disps)
		}
	}
}

// A partial answer is judged finding by finding: R-0 is classified, R-1's own
// verdict was rejected (an ordinary fallback), and R-2, which no reply ever
// carried a verdict for, is triage-failed although its batch-mates were
// answered. It used to be an ordinary fallback here and triage-failed when it
// was asked about alone, so the outcome depended on the batch and the cache.
func TestClassifyFindingsPartialAnswerIsJudgedPerFinding(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(3)
	mock := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		var entries []string
		for i, f := range batch {
			switch f.ID {
			case "R-0":
				entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"True Positive","confidence":"high","rationale":"r"}`, i))
			case "R-1":
				entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"False Positive","confidence":"high","rationale":"no evidence"}`, i))
			}
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, nil
	}}
	var usage llm.Usage

	_, disps, err := ClassifyFindings(context.Background(), "", "p", findings, mock, &usage, 40)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) || incomplete.Unclassified != 1 {
		t.Fatalf("err = %v, want an incomplete triage for the one finding no reply carried", err)
	}
	for i, want := range []string{dispositionSourceLLM, dispositionSourceNRFallback, dispositionSourceTriageFailed} {
		if disps[i].DispositionSource != want || (i > 0 && disps[i].Disposition != "Needs Manual Review") {
			t.Fatalf("disps[%d] = %+v, want source %q", i, disps[i], want)
		}
	}
}

// The outcome of a finding no reply carries a verdict for does not depend on
// whether its batch-mates were answered, or came from the verdict cache: the
// cold run (R1 and R2 in one request) and the warm run (R1 cached, R2 asked
// alone) both leave R2 triage-failed and the triage incomplete. A finding whose
// own verdict is rejected is an ordinary fallback in both runs.
func TestUnclassifiedOutcomeDoesNotDependOnTheVerdictCache(t *testing.T) {
	for name, r2Reply := range map[string]string{
		"left out of every reply": "",
		"rejected every time":     "False Positive",
	} {
		t.Run(name, func(t *testing.T) {
			hermeticRun(t)
			t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", t.TempDir())
			project := writeProjectFiles(t, map[string]string{"app.go": "package app\n"})
			run := func() (*AgentState, error) {
				state := fallbackRunState(project)
				state.Policy = healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed}
				llmClient := newFallbackRunLLM(t)
				// R1 confirms nothing, so under fail_on=confirmed only an
				// incomplete triage can block.
				llmClient.r1Disposition, llmClient.r2Disposition = "Needs Manual Review", r2Reply
				err := Run(context.Background(), state, llmClient)
				return state, err
			}
			cold, coldErr := run()
			warm, warmErr := run()
			if warm.VerdictCacheStats.Hits == 0 {
				t.Fatalf("warm run verdict cache = %+v, want R1 served from the cache", warm.VerdictCacheStats)
			}
			wantFailed := r2Reply == ""
			for label, state := range map[string]*AgentState{"cold": cold, "warm": warm} {
				if state.TriageFailed() != wantFailed {
					t.Fatalf("%s run: triage failed = %v, want %v", label, state.TriageFailed(), wantFailed)
				}
				if passed := state.HealthCheck.Verdict.Passed; passed == wantFailed {
					t.Fatalf("%s run: gate passed = %v under fail_on=confirmed", label, passed)
				}
			}
			if errors.Is(coldErr, ErrTriageIncomplete) != wantFailed || errors.Is(warmErr, ErrTriageIncomplete) != wantFailed {
				t.Fatalf("errors = %v / %v, want an incomplete triage = %v in both runs", coldErr, warmErr, wantFailed)
			}
		})
	}
}

// A classification reply must be a JSON object with a finding_dispositions
// list. Anything else is a parse error and is recorded as one.
func TestClassificationReplyMustCarryADispositionList(t *testing.T) {
	cases := map[string]bool{
		`{}`:                            true,
		`null`:                          true,
		`[]`:                            true,
		`"text"`:                        true,
		`{"error":"rate limited"}`:      true,
		`{"finding_dispositions":null}`: true,
		`{"finding_dispositions":{}}`:   true,
		`{"finding_dispositions":[]}`:   false,
		"```json\n{\"finding_dispositions\":[]}\n```": false,
		`{"finding_dispositions":[]} trailing prose`:  false,
	}
	for reply, wantParseError := range cases {
		client := llmFunc(func([]llm.Message) (string, error) { return reply, nil })
		_, raw, _, err := classifyBatchLLM(context.Background(), "", "", makeFindings(1), client)
		if got := errors.Is(err, errThreatModelParse); got != wantParseError {
			t.Errorf("reply %q: parse error = %v (%v), want %v", reply, got, err, wantParseError)
		}
		if raw != reply {
			t.Errorf("reply %q: raw response = %q, want it kept for the audit", reply, raw)
		}
	}
}

// llmFunc adapts a function to llm.Client.
type llmFunc func(messages []llm.Message) (string, error)

func (f llmFunc) Chat(_ context.Context, messages []llm.Message) (string, llm.Usage, error) {
	body, err := f(messages)
	return body, llm.Usage{}, err
}
