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

// Why AI triage did not complete. The remedy differs: waiting for the
// provider, or retrying with more attempts and smaller requests.
const (
	// TriageFailureCauseProvider: the provider failed (authentication, rate
	// limit, timeout, transport).
	TriageFailureCauseProvider = "provider_failure"
	// TriageFailureCauseNoVerdict: the provider answered, but after every
	// retry no reply carried a verdict for some findings (left out,
	// malformed or empty replies, verdicts naming another finding), or the
	// model declined to classify a finding sent on its own.
	TriageFailureCauseNoVerdict = "no_verdict"
)

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
	// Declined counts the part of Unclassified the model declined to
	// classify (stop_reason refusal) in a request that carried only that
	// finding.
	Declined int
	// Cause is TriageFailureCauseProvider or TriageFailureCauseNoVerdict.
	Cause string
	// Err is the underlying provider error.
	Err error
}

func (e *TriageIncompleteError) Error() string {
	return fmt.Sprintf("AI triage did not complete (%s stage): %s", e.Stage, e.Reason)
}

// Remedy says what to do about the incomplete triage, as a sentence fragment
// ("re-run once the LLM provider is available"); setting names are in
// backticks.
func (e *TriageIncompleteError) Remedy() string {
	return triageRemedy(e.Cause, e.Declined, e.Unclassified)
}

// triageRemedy says what to do about an incomplete triage that left
// unclassified findings, declined of them by the model. After a provider
// failure a re-run helps once the provider is back; findings left out of
// every reply may get a verdict with more attempts or smaller requests; a
// finding the model declined on its own is likely to be declined again by
// the same model, so a person has to judge it.
func triageRemedy(cause string, declined, unclassified int) string {
	if cause != TriageFailureCauseNoVerdict {
		return "re-run once the LLM provider is available"
	}
	retry := "re-run, and if the model keeps leaving findings out, raise `AITRIAGE_CLASSIFY_RETRIES` or lower `AITRIAGE_BATCH_SIZE`"
	if declined <= 0 {
		return retry
	}
	refused := fmt.Sprintf("the model declined to classify %d of them and is likely to decline them again: review them by hand, or triage them with another model", declined)
	if declined >= unclassified {
		return refused
	}
	return refused + "; for the rest, " + retry
}

func (e *TriageIncompleteError) Unwrap() error { return e.Err }

// Is lets errors.Is(err, ErrTriageIncomplete) match any incomplete triage.
func (e *TriageIncompleteError) Is(target error) bool { return target == ErrTriageIncomplete }

func newTriageIncomplete(stage string, err error) *TriageIncompleteError {
	return &TriageIncompleteError{Stage: stage, Reason: failureReason(err), Cause: TriageFailureCauseProvider, Err: err}
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
		// Google API keys are AIza plus 35 characters; a provider echoes them
		// without a field name ("API key not valid: AIza...").
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`[A-Za-z0-9_-]{40,}`),
	}
	// failureKeyedSecretPattern keeps the field name, so a reader still sees
	// which credential the provider complained about. An authorization
	// scheme ("Authorization: Bearer <token>") is removed with the value
	// rather than taken for it.
	failureKeyedSecretPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|token|secret|password|authorization|bearer)(["'\s:=]+)(?:(?:bearer|basic|digest|token)\s+)?[^\s"',;]{6,}`)

	// Host names and addresses of the network around the run: a private
	// gateway, a proxy, an internal resolver. Go's network errors name them
	// outside any URL ("dial tcp: lookup llm.corp.internal on 10.0.0.2:53",
	// "dial tcp 10.20.30.40:8443", "proxyconnect tcp: dial tcp
	// proxy.corp.internal:3128", "x509: certificate is valid for
	// gw.corp.internal, not llm.corp.internal"). The surrounding words stay,
	// so the reader still sees what kind of failure it was.
	failureHostPatterns = []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
		// "lookup <host> on <resolver>", and "lookup <name.with.dots>"; a
		// bare "lookup failed" is prose.
		{regexp.MustCompile(`(?i)\b(lookup)\s+[^\s:,;"'\[\]]+\s+on\s+(?:\[[^\]\s]*\]|[^\s:,;"'\[\]]+)(?::\d+)?`), "$1 <host>"},
		{regexp.MustCompile(`(?i)\b(lookup)\s+(?:\[[^\]\s]*\]|[^\s:,;"'\[\]]*\.[^\s:,;"'\[\]]+)`), "$1 <host>"},
		{regexp.MustCompile(`(?i)\b(dial\s+(?:tcp|udp)[46]?)\s+(?:\[[^\]\s]*\]|[^\s:,;"'\[\]]+)(?::\d+)?`), "$1 <host>"},
		{regexp.MustCompile(`(?i)\b(certificate is valid for)\s+.+?,\s*not\s+[^\s,;"']+`), "$1 <host>, not <host>"},
		{regexp.MustCompile(`(?i)\b(but wanted to match|cannot validate certificate for)\s+[^\s,;"']+`), "$1 <host>"},
		// IP literals anywhere: IPv4 with an optional port, bracketed IPv6
		// (Go's host:port form), and full or compressed IPv6.
		{regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b`), "<ip>"},
		{regexp.MustCompile(`\[[0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*\](?::\d{1,5})?`), "<ip>"},
		{regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*\b)?`), "<ip>"},
	}
)

// failureReason renders a provider error as one short line that is safe to
// publish in a CI summary: whitespace collapsed, URLs (which may name private
// gateways), host names and addresses of the network, and credential-shaped
// values removed, length capped. Every error text written to an artifact goes
// through it.
func failureReason(err error) string {
	if err == nil {
		return "unknown error"
	}
	return redactFailureText(err.Error())
}

// redactFailureText is failureReason for text that is already a string, such
// as the rejection reasons recorded in the classification audit.
func redactFailureText(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	text = failureURLPattern.ReplaceAllString(text, "<url>")
	text = failureKeyedSecretPattern.ReplaceAllString(text, "$1$2[redacted]")
	for _, pattern := range failureSecretPatterns {
		text = pattern.ReplaceAllString(text, "[redacted]")
	}
	for _, host := range failureHostPatterns {
		text = host.pattern.ReplaceAllString(text, host.replacement)
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
