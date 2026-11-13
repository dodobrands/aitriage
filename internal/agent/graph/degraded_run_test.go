package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// stageLLM is a stage-aware stub provider for Run-level tests. Each stage
// answers from its handler; a nil handler gives a well-formed default answer.
type stageLLM struct {
	t           *testing.T
	threatModel func(call int, messages []llm.Message) (string, error)
	classify    func(call int, batch []classificationPromptFinding) (string, error)
	poc         func(call int) (string, error)
	report      func(call int) (string, error)
	fixspec     func(call int) (string, error)

	mu         sync.Mutex
	calls      map[string]int
	tmRequests [][]llm.Message
	classified []string // finding IDs every classification request carried
	batchSizes []int
}

func newStageLLM(t *testing.T) *stageLLM {
	return &stageLLM{t: t, calls: map[string]int{}}
}

func (m *stageLLM) count(stage string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[stage]
}

func (m *stageLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return "", llm.Usage{}, err
	}
	system := messages[0].Content
	usage := llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.Contains(system, "Current Task: Threat Model & Finding Classification"):
		call := m.calls["threat_model"]
		m.calls["threat_model"]++
		m.tmRequests = append(m.tmRequests, messages)
		if m.threatModel == nil {
			return `{"component_overview":"service","priority_areas":["input handling"]}`, usage, nil
		}
		body, err := m.threatModel(call, messages)
		return body, usage, err
	case strings.Contains(system, "Current Task: Finding Classification"):
		call := m.calls["classification"]
		m.calls["classification"]++
		batch := parsePromptBatchFromUser(messages[1].Content)
		m.batchSizes = append(m.batchSizes, len(batch))
		for _, item := range batch {
			m.classified = append(m.classified, item.Finding.ID)
		}
		if m.classify == nil {
			return classifyAll(batch, "True Positive"), usage, nil
		}
		body, err := m.classify(call, batch)
		return bindPromptIdentities(body, batch), usage, err
	case strings.Contains(system, "Current Task: PoC Verification"):
		call := m.calls["poc"]
		m.calls["poc"]++
		if m.poc == nil {
			return pocResultsJSON(len(parseBatchFromUser(messages[1].Content))), usage, nil
		}
		body, err := m.poc(call)
		return body, usage, err
	case strings.Contains(system, "Current Task: Compile Security Report"):
		call := m.calls["report"]
		m.calls["report"]++
		if m.report == nil {
			return "# Narrative report\n", usage, nil
		}
		body, err := m.report(call)
		return body, usage, err
	case strings.Contains(system, "Generate AI IDE Fix Plan"):
		call := m.calls["fixspec"]
		m.calls["fixspec"]++
		if m.fixspec == nil {
			return "# Narrative fix plan\n", usage, nil
		}
		body, err := m.fixspec(call)
		return body, usage, err
	}
	m.t.Fatalf("unexpected LLM request: %.80s", system)
	return "", llm.Usage{}, nil
}

// hermeticRun keeps Run-level tests away from any cache the developer's
// environment points at.
func hermeticRun(t *testing.T) {
	t.Helper()
	pinConcurrency(t)
	for _, name := range []string{"AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR", "AITRIAGE_GATING", "AITRIAGE_LLM_BUDGET", "AITRIAGE_POC_BUDGET", "AITRIAGE_CLASSIFY_RETRIES"} {
		t.Setenv(name, "")
	}
}

func degradedRunState(t *testing.T, failOn string) *AgentState {
	t.Helper()
	project := t.TempDir()
	source := "import os\nresult = eval(os.environ['EXPR'])\nTOKEN = 'placeholder-value'\n"
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return &AgentState{
		ProjectPath: project,
		CoreFindings: []core.CheckResult{
			{ID: "PY-EVAL", Name: "Code evaluation", Status: core.Absent, Evidence: "eval of environment input", Severity: "HIGH", File: "app.py", Line: 2},
			{ID: "PY-SECRET", Name: "Hardcoded secret", Status: core.Absent, Evidence: "token literal", Severity: "MEDIUM", File: "app.py", Line: 3},
		},
		Policy: healthcheck.Policy{FailOn: failOn},
	}
}

func hasBlockingReason(verdict healthcheck.Verdict, code string) bool {
	for _, reason := range verdict.BlockingReasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

// A1: one malformed threat-model reply is repaired; the run completes.
func TestRunRepairsMalformedThreatModelReply(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.threatModel = func(call int, _ []llm.Message) (string, error) {
		if call == 0 {
			return `{"priority_areas":["a"}}`, nil
		}
		return `{"component_overview":"repaired","entry_points":[{"endpoint":"/run","type":"http","trusted":"true","validation":"none"}]}`, nil
	}
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want a completed run", err)
	}
	if state.ThreatModelSource != threatModelSourceLLM || state.ThreatModel == nil || state.ThreatModel.ComponentOverview != "repaired" {
		t.Fatalf("threat model = %+v (%s), want the repaired model", state.ThreatModel, state.ThreatModelSource)
	}
	if !bool(state.ThreatModel.EntryPoints[0].Trusted) {
		t.Fatal(`"trusted":"true" must decode as true`)
	}
	if len(stub.tmRequests) != 2 {
		t.Fatalf("threat-model requests = %d, want 2 (attempt + repair)", len(stub.tmRequests))
	}
	repair := stub.tmRequests[1]
	if len(repair) != 4 || repair[2].Role != "assistant" || repair[2].Content != `{"priority_areas":["a"}}` || repair[3].Role != "user" || !strings.Contains(repair[3].Content, "ONLY that JSON object") {
		t.Fatalf("repair request = %+v, want the bad reply echoed and a repair instruction", repair)
	}
	if state.TriageStatus != TriageStatusComplete {
		t.Fatalf("triage status = %q, want complete", state.TriageStatus)
	}
}

// A1: a threat model that stays malformed is skipped, never fatal; findings
// are still classified by the model.
func TestRunContinuesWithoutThreatModelAfterRepeatedParseFailures(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.threatModel = func(int, []llm.Message) (string, error) {
		return "Here is the threat model: {component_overview: service", nil
	}
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want a completed run without a threat model", err)
	}
	if got := stub.count("threat_model"); got != threatModelMaxRetries+1 {
		t.Fatalf("threat-model calls = %d, want %d", got, threatModelMaxRetries+1)
	}
	if state.ThreatModel != nil || state.ThreatModelSource != threatModelSourceFailedParse {
		t.Fatalf("threat model = %+v source = %q, want nil/failed_parse", state.ThreatModel, state.ThreatModelSource)
	}
	for _, d := range state.FindingDispositions {
		if d.DispositionSource != dispositionSourceLLM {
			t.Fatalf("disposition %+v, want classified by the model", d)
		}
	}
	if len(state.StageFailures) == 0 || state.StageFailures[0].Stage != usageStageThreatModel || state.StageFailures[0].Status != stageStatusDegraded {
		t.Fatalf("stage failures = %+v, want a degraded threat_model entry", state.StageFailures)
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ThreatModelSource != threatModelSourceFailedParse || artifact.TriageStatus != TriageStatusComplete {
		t.Fatalf("artifact source/status = %q/%q, want failed_parse/complete", artifact.ThreatModelSource, artifact.TriageStatus)
	}
}

// A2: a provider failure during classification completes the run with every
// artifact, marks the unclassified findings, and fails the gate even under
// fail_on=confirmed, which would otherwise pass with nothing confirmed.
func TestRunClassificationProviderFailureProducesArtifactsAndBlocksGate(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.classify = func(int, []classificationPromptFinding) (string, error) {
		return "", fmt.Errorf("openai chat error: POST %q: 401 Unauthorized", "https://llm.example.internal/v1/chat/completions")
	}
	state := degradedRunState(t, healthcheck.FailOnConfirmed)

	err := Run(context.Background(), state, stub)
	var incomplete *TriageIncompleteError
	if !errors.As(err, &incomplete) || !errors.Is(err, ErrTriageIncomplete) {
		t.Fatalf("Run() error = %v, want a TriageIncompleteError", err)
	}
	if incomplete.Stage != usageStageClassification || incomplete.Unclassified != 2 {
		t.Fatalf("incomplete = %+v, want classification stage with 2 unclassified", incomplete)
	}
	if strings.Contains(incomplete.Reason, "llm.example.internal") || !strings.Contains(incomplete.Reason, "401 Unauthorized") {
		t.Fatalf("reason = %q, want the status kept and the URL removed", incomplete.Reason)
	}
	if state.TriageStatus != TriageStatusFailed || state.TriageFailureReason == "" {
		t.Fatalf("triage status = %q reason = %q, want failed with a reason", state.TriageStatus, state.TriageFailureReason)
	}
	for _, d := range state.FindingDispositions {
		if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceTriageFailed {
			t.Fatalf("disposition %+v, want triage-failed Needs Manual Review", d)
		}
	}
	verdict := state.HealthCheck.Verdict
	if verdict.Passed || !hasBlockingReason(verdict, healthcheck.ReasonTriageIncomplete) {
		t.Fatalf("verdict = %+v, want failed with triage_incomplete", verdict)
	}
	for _, stage := range []string{"poc", "report", "fixspec"} {
		if got := stub.count(stage); got != 0 {
			t.Fatalf("%s calls = %d, want 0 once the provider failed", stage, got)
		}
	}
	for name, doc := range map[string]string{"summary": state.SummaryMarkdown, "report": state.ReportMarkdown, "fixspec": state.AIFixSpec} {
		if !strings.Contains(doc, "AI triage did not complete: ") {
			t.Fatalf("%s has no triage-incomplete banner:\n%s", name, doc)
		}
	}
	if !strings.Contains(state.ReportMarkdown, "Needs Manual Review (unclassified)") || !strings.Contains(state.ReportMarkdown, "`"+healthcheck.ReasonTriageIncomplete+"`") {
		t.Fatalf("report lacks the unclassified status or the gate reason:\n%s", state.ReportMarkdown)
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatalf("artifact must be buildable for an incomplete triage: %v", err)
	}
	data, _ := json.Marshal(artifact)
	for _, want := range []string{`"triage_status":"failed"`, `"triage_failure_reason":"`, `"disposition_source":"triage-failed"`, `"triage_failed":2`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("artifact lacks %s: %s", want, data)
		}
	}
}

// A2: a threat-model provider failure ends triage before any classification
// call, with the same complete, gated outcome.
func TestRunThreatModelProviderFailureSkipsClassification(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.threatModel = func(int, []llm.Message) (string, error) {
		return "", errors.New("429 Too Many Requests: quota exceeded")
	}
	state := degradedRunState(t, healthcheck.FailOnCritical)

	err := Run(context.Background(), state, stub)
	if !errors.Is(err, ErrTriageIncomplete) {
		t.Fatalf("Run() error = %v, want ErrTriageIncomplete", err)
	}
	if stub.count("classification") != 0 {
		t.Fatalf("classification calls = %d, want 0", stub.count("classification"))
	}
	if state.ThreatModelSource != threatModelSourceFailed || state.TriageFailureStage != usageStageThreatModel {
		t.Fatalf("source = %q stage = %q, want failed/threat_model", state.ThreatModelSource, state.TriageFailureStage)
	}
	if !hasBlockingReason(state.HealthCheck.Verdict, healthcheck.ReasonTriageIncomplete) {
		t.Fatalf("verdict = %+v, want triage_incomplete", state.HealthCheck.Verdict)
	}
}

// A2: fail_on=never still means never, even for an incomplete triage; the
// caller reports the failure through its exit status instead.
func TestRunTriageFailureUnderFailOnNeverKeepsGateOpen(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.classify = func(int, []classificationPromptFinding) (string, error) { return "", errors.New("timeout") }
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, stub); !errors.Is(err, ErrTriageIncomplete) {
		t.Fatalf("Run() error = %v, want ErrTriageIncomplete", err)
	}
	if !state.HealthCheck.Verdict.Passed {
		t.Fatalf("fail_on=never verdict = %+v, want passed", state.HealthCheck.Verdict)
	}
}

// A2: PoC is advisory. A rate-limited PoC stage completes the run normally,
// and the dispositions and the gate are exactly those of a run whose PoC
// succeeded.
func TestRunPoCFailureIsNonFatalAndNeverChangesTheGate(t *testing.T) {
	hermeticRun(t)
	healthy := newStageLLM(t)
	healthyState := degradedRunState(t, healthcheck.FailOnConfirmed)
	if err := Run(context.Background(), healthyState, healthy); err != nil {
		t.Fatalf("healthy Run() error = %v", err)
	}

	failing := newStageLLM(t)
	failing.poc = func(int) (string, error) { return "", errors.New("429 RESOURCE_EXHAUSTED") }
	failingState := degradedRunState(t, healthcheck.FailOnConfirmed)
	failingState.ProjectPath = healthyState.ProjectPath
	if err := Run(context.Background(), failingState, failing); err != nil {
		t.Fatalf("Run() with a failing PoC stage error = %v, want nil", err)
	}

	if failingState.PoCStats.Status != pocStatusFailed || !strings.Contains(failingState.PoCStats.Reason, "429") {
		t.Fatalf("poc stats = %+v, want failed with the provider reason", failingState.PoCStats)
	}
	if failingState.TriageStatus != TriageStatusComplete {
		t.Fatalf("triage status = %q, want complete: PoC is not triage", failingState.TriageStatus)
	}
	if !reflect.DeepEqual(healthyState.FindingDispositions, failingState.FindingDispositions) {
		t.Fatalf("dispositions changed with PoC:\nhealthy=%+v\nfailing=%+v", healthyState.FindingDispositions, failingState.FindingDispositions)
	}
	if !reflect.DeepEqual(healthyState.HealthCheck.Verdict, failingState.HealthCheck.Verdict) {
		t.Fatalf("gate changed with PoC:\nhealthy=%+v\nfailing=%+v", healthyState.HealthCheck.Verdict, failingState.HealthCheck.Verdict)
	}
	// The provider already failed: the later stages render deterministically
	// instead of calling it again.
	if failing.count("report") != 0 || failing.count("fixspec") != 0 {
		t.Fatalf("report/fixspec calls = %d/%d, want 0 after the provider failed", failing.count("report"), failing.count("fixspec"))
	}
	if !strings.Contains(failingState.ReportMarkdown, "AI narrative unavailable") || !strings.Contains(failingState.ReportMarkdown, "Canonical Finding Inventory") {
		t.Fatalf("report = %q, want a deterministic report with a notice", failingState.ReportMarkdown)
	}
	if !strings.Contains(failingState.SummaryMarkdown, "Degraded run") {
		t.Fatalf("summary does not flag the degraded run:\n%s", failingState.SummaryMarkdown)
	}
}

// A2: a failing report call falls back to the canonical rendering.
func TestRunReportFailureFallsBackToDeterministicReport(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.report = func(int) (string, error) { return "", errors.New("503 Service Unavailable") }
	state := degradedRunState(t, healthcheck.FailOnNever)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if !strings.HasPrefix(state.ReportMarkdown, "# Security Report (deterministic)") || !strings.Contains(state.ReportMarkdown, "503 Service Unavailable") {
		t.Fatalf("report = %q, want the deterministic report naming the failure", state.ReportMarkdown)
	}
	if !strings.HasPrefix(state.AIFixSpec, "# AI Fix Specification (deterministic)") {
		t.Fatalf("fix spec = %q, want the deterministic rendering", state.AIFixSpec)
	}
	var stages []string
	for _, failure := range state.StageFailures {
		stages = append(stages, failure.Stage+"/"+failure.Status)
	}
	if want := []string{"report/failed", "fixspec/skipped"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("stage failures = %v, want %v", stages, want)
	}
}

type suspendError struct{}

func (suspendError) Error() string     { return "awaiting a host answer" }
func (suspendError) SuspendsRun() bool { return true }

// A2 must not swallow a deferred client's pause: the host-agent workflow
// resumes the run later and needs Run to unwind, at any stage.
func TestRunSuspensionUnwindsInsteadOfDegrading(t *testing.T) {
	for _, stage := range []string{"threat_model", "classification", "poc", "report", "fixspec"} {
		t.Run(stage, func(t *testing.T) {
			hermeticRun(t)
			stub := newStageLLM(t)
			suspend := func(int) (string, error) { return "", suspendError{} }
			switch stage {
			case "threat_model":
				stub.threatModel = func(int, []llm.Message) (string, error) { return "", suspendError{} }
			case "classification":
				stub.classify = func(int, []classificationPromptFinding) (string, error) { return "", suspendError{} }
			case "poc":
				stub.poc = suspend
			case "report":
				stub.report = suspend
			case "fixspec":
				stub.fixspec = suspend
			}
			state := degradedRunState(t, healthcheck.FailOnNever)

			err := Run(context.Background(), state, stub)
			var suspender RunSuspender
			if !errors.As(err, &suspender) {
				t.Fatalf("Run() error = %v, want the suspension to unwind Run", err)
			}
			if errors.Is(err, ErrTriageIncomplete) {
				t.Fatalf("a suspension must not be reported as an incomplete triage: %v", err)
			}
			if len(state.StageFailures) != 0 {
				t.Fatalf("stage failures = %+v, want none for a suspension", state.StageFailures)
			}
		})
	}
}

// A cancelled run aborts; it is not published as an incomplete triage.
func TestRunCancelledContextAborts(t *testing.T) {
	hermeticRun(t)
	ctx, cancel := context.WithCancel(context.Background())
	stub := newStageLLM(t)
	stub.classify = func(int, []classificationPromptFinding) (string, error) {
		cancel()
		return "", context.Canceled
	}
	state := degradedRunState(t, healthcheck.FailOnNever)

	err := Run(ctx, state, stub)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTriageIncomplete) {
		t.Fatalf("Run() error = %v, want context.Canceled, not an incomplete triage", err)
	}
}

// A3: a model whose verdict for a finding keeps failing validation leaves it
// visibly unclassified in the summary header, the report, the gate breakdown
// and the artifact. (A model that leaves the finding out of every reply makes
// it triage-failed instead: see TestUnclassifiedOutcomeDoesNotDependOnTheVerdictCache.)
func TestRunMakesUnclassifiedFindingsVisible(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.classify = func(_ int, batch []classificationPromptFinding) (string, error) {
		// A True Positive for PY-EVAL; a False Positive without evidence,
		// which validation rejects, for PY-SECRET.
		var entries []string
		for _, item := range batch {
			disposition := "True Positive"
			if item.Finding.ID == "PY-SECRET" {
				disposition = "False Positive"
			}
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"finding_id":%q,"disposition":%q,"confidence":"high","rationale":"r"}`,
				item.FindingIndex, item.FindingID, disposition))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, nil
	}
	state := degradedRunState(t, healthcheck.FailOnAny)

	if err := Run(context.Background(), state, stub); err != nil {
		t.Fatalf("Run() error = %v, want nil: a rejected verdict is not a provider failure", err)
	}
	bd := state.HealthCheck.Breakdown
	if bd.UnclassifiedFindings != 1 || bd.NeedsReviewFindings != 1 || bd.TriageFailedFindings != 0 {
		t.Fatalf("breakdown = %+v, want 1 unclassified needs-review finding", bd)
	}
	if !strings.Contains(state.SummaryMarkdown, "**Needs Review**: 1 (1 unclassified: the model's verdict did not pass validation") {
		t.Fatalf("summary header does not report the unclassified finding:\n%s", state.SummaryMarkdown)
	}
	if !strings.Contains(state.ReportMarkdown, "Needs Manual Review (unclassified) | nr-fallback") {
		t.Fatalf("report does not label the unclassified finding:\n%s", state.ReportMarkdown)
	}
	var activeMessage string
	for _, reason := range state.HealthCheck.Verdict.BlockingReasons {
		if reason.Code == "active_findings" {
			activeMessage = reason.Message
		}
	}
	if !strings.Contains(activeMessage, "1 of them were never classified by the model") {
		t.Fatalf("fail_on=any reason = %q, want it to name the unclassified finding", activeMessage)
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Classification.NRFallback != 1 || artifact.Classification.ModelBound != 2 || artifact.Classification.NRFallbackRate != 0.5 {
		t.Fatalf("classification stats = %+v, want 1 of 2 model-bound findings unclassified (rate 0.5)", artifact.Classification)
	}
}

// A3 root cause: retries are split in halves when the model drops more than a
// quarter of a request, and resent whole when it drops only a few items.
func TestClassifyRetriesInHalvesWhenTheModelDropsManyItems(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
	run := func(keep int) []int {
		var sizes []int
		mock := &fakeLLM{t: t, classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
			sizes = append(sizes, len(batch))
			if call == 0 {
				return classifyAllByCount(keep, "True Positive"), nil
			}
			return classifyAllByCount(len(batch), "True Positive"), nil
		}}
		var usage llm.Usage
		_, disps, err := ClassifyFindings(context.Background(), "", "p", makeFindings(8), mock, &usage, 8)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range disps {
			if d.DispositionSource != dispositionSourceLLM {
				t.Fatalf("disposition %+v, want every finding classified after the retry", d)
			}
		}
		return sizes
	}
	if got, want := run(2), []int{8, 3, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("6 of 8 dropped: request sizes = %v, want %v", got, want)
	}
	if got, want := run(7), []int{8, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("1 of 8 dropped: request sizes = %v, want %v", got, want)
	}
}

func TestDefaultClassificationBatchSizeIs40(t *testing.T) {
	if got := GetBatchSize(&AgentState{}); got != 40 {
		t.Fatalf("GetBatchSize default = %d, want 40", got)
	}
	if got := GetBatchSize(&AgentState{BatchSize: 12}); got != 12 {
		t.Fatalf("GetBatchSize configured = %d, want 12", got)
	}
}

func TestFailureReasonIsPublishable(t *testing.T) {
	err := fmt.Errorf("openai chat error: POST \"https://gateway.example.internal/v1/chat\": 401 Unauthorized\n{\"error\":\"invalid api_key: sk-abcdefghijklmnopqrstuvwx\"} token=abcdef123456")
	reason := failureReason(err)
	for _, leaked := range []string{"gateway.example.internal", "sk-abcdefghijklmnopqrstuvwx", "abcdef123456", "\n"} {
		if strings.Contains(reason, leaked) {
			t.Fatalf("reason %q leaks %q", reason, leaked)
		}
	}
	if !strings.Contains(reason, "401 Unauthorized") || !strings.Contains(reason, "token=[redacted]") {
		t.Fatalf("reason %q lost the useful part", reason)
	}
	long := failureReason(errors.New(strings.Repeat("x ", 400)))
	if len([]rune(long)) > maxFailureReasonRunes+1 {
		t.Fatalf("reason length = %d, want it capped", len([]rune(long)))
	}
}
