package graph

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ── Provider failures ────────────────────────────────────────────────────────
//
// A provider failure (401, 429, 5xx, timeout, malformed output) used to unwind
// Run and throw away everything already computed, including scan results and
// paid-for classifications, so CI got neither artifacts nor a verdict. Run now
// finishes the deterministic stages whatever the provider does: the threat
// model and optional stages degrade, unclassified findings are marked, the gate
// refuses to pass, and the caller receives a typed error at the very end.

// Triage status values recorded on AgentState and in triage-findings.json.
const (
	TriageStatusComplete = "complete"
	TriageStatusFailed   = "failed"
)

// Stage failure statuses, recorded in triage-findings.json.
const (
	// stageStatusFailed: the stage's LLM call failed and a deterministic
	// fallback was used instead.
	stageStatusFailed = "failed"
	// stageStatusSkipped: the stage did not call the provider because it had
	// already failed earlier in the run.
	stageStatusSkipped = "skipped"
	// stageStatusDegraded: the stage finished without part of its output.
	stageStatusDegraded = "degraded"
)

// StageFailure records an LLM stage that did not produce its normal output.
// The run still finished; the entry says what was used instead.
type StageFailure struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// ErrTriageIncomplete matches every *TriageIncompleteError via errors.Is.
var ErrTriageIncomplete = errors.New("AI triage did not complete")

// TriageIncompleteError reports that the LLM provider failed before every
// finding received a verdict. The dispositions, health check, gate, report and
// summary were still produced: findings the model never classified are Needs
// Manual Review with disposition_source "triage-failed", and the gate carries
// the triage_incomplete blocking reason. Callers that can publish a degraded
// result do so and exit with a distinct status; others treat it as a failure.
type TriageIncompleteError struct {
	// Stage is the usage stage that failed: "threat_model" or "classification".
	Stage string
	// Reason is a single-line, redacted description that is safe to publish.
	Reason string
	// Unclassified counts the findings left without a verdict.
	Unclassified int
	// Err is the underlying provider error.
	Err error
}

func (e *TriageIncompleteError) Error() string {
	return fmt.Sprintf("AI triage did not complete (%s stage): %s", e.Stage, e.Reason)
}

func (e *TriageIncompleteError) Unwrap() error { return e.Err }

// Is lets errors.Is(err, ErrTriageIncomplete) match any incomplete triage.
func (e *TriageIncompleteError) Is(target error) bool { return target == ErrTriageIncomplete }

func newTriageIncomplete(stage string, err error) *TriageIncompleteError {
	return &TriageIncompleteError{Stage: stage, Reason: failureReason(err), Err: err}
}

// RunSuspender is implemented by errors that pause a run rather than fail it.
// The deferred host-agent client returns one while it waits for the host to
// answer a request; such an error must unwind Run untouched so the run can be
// resumed later, instead of being absorbed by the provider-failure fallbacks.
type RunSuspender interface {
	SuspendsRun() bool
}

func isRunSuspension(err error) bool {
	var suspender RunSuspender
	return errors.As(err, &suspender) && suspender.SuspendsRun()
}

// abortsRun reports whether an LLM error must unwind Run instead of being
// handled by a stage fallback: the caller cancelled the run, or the client
// suspended it to wait for an answer.
func abortsRun(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	return ctx.Err() != nil || isRunSuspension(err)
}

// maxFailureReasonRunes keeps a provider error readable in a summary banner.
const maxFailureReasonRunes = 300

var (
	failureURLPattern = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	// Credential-shaped values. Provider errors rarely contain them, but the
	// reason is published in summaries, so anything that looks like a key or
	// token is removed first.
	failureSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:sk|pk|rk)-[A-Za-z0-9][A-Za-z0-9_-]{15,}`),
		regexp.MustCompile(`(?i)\b(?:ghp|gho|ghs|github_pat|xox[abprs])_?[-A-Za-z0-9_]{16,}`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`[A-Za-z0-9_-]{40,}`),
	}
	// failureKeyedSecretPattern keeps the field name, so a reader still sees
	// which credential the provider complained about.
	failureKeyedSecretPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|token|secret|password|authorization|bearer)(["'\s:=]+)[^\s"',;]{6,}`)
)

// failureReason renders a provider error as one short line that is safe to
// publish in a CI summary: whitespace collapsed, URLs (which may name private
// gateways) and credential-shaped values removed, length capped.
func failureReason(err error) string {
	if err == nil {
		return "unknown error"
	}
	text := strings.Join(strings.Fields(err.Error()), " ")
	text = failureURLPattern.ReplaceAllString(text, "<url>")
	text = failureKeyedSecretPattern.ReplaceAllString(text, "$1$2[redacted]")
	for _, pattern := range failureSecretPatterns {
		text = pattern.ReplaceAllString(text, "[redacted]")
	}
	if utf8.RuneCountInString(text) > maxFailureReasonRunes {
		runes := []rune(text)
		text = string(runes[:maxFailureReasonRunes]) + "…"
	}
	if text == "" {
		return "unknown error"
	}
	return text
}

// recordStageFailure appends a stage outcome to the run's audit trail.
func recordStageFailure(state *AgentState, stage, status, reason string) {
	state.StageFailures = append(state.StageFailures, StageFailure{Stage: stage, Status: status, Reason: reason})
}

// TriageFailed reports whether AI triage did not complete for this run.
func (s *AgentState) TriageFailed() bool {
	return s != nil && s.TriageStatus == TriageStatusFailed
}

// providerFailure explains why the remaining LLM stages must not call the
// provider: AI triage failed, or an earlier optional stage hit a provider
// failure. One failure already showed the provider is unusable for this run;
// calling it again in every later stage would only add retries and timeouts
// before the same deterministic fallback.
func providerFailure(state *AgentState) string {
	if state.TriageFailed() {
		return "AI triage did not complete: " + state.TriageFailureReason
	}
	for _, failure := range state.StageFailures {
		if failure.Status == stageStatusFailed {
			return fmt.Sprintf("the LLM provider failed in the %s stage: %s", failure.Stage, failure.Reason)
		}
	}
	return ""
}

// artifactStageFailed reports whether PoC, report or fix spec fell back to a
// deterministic rendering. Such a bundle must not be cached for exact reuse:
// the next healthy run should produce the real narrative.
func artifactStageFailed(state *AgentState) bool {
	for _, failure := range state.StageFailures {
		switch failure.Stage {
		case usageStagePoC, usageStageReport, usageStageFixSpec:
			return true
		}
	}
	return false
}
