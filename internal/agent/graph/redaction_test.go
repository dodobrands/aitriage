package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// Provider errors can name a private gateway and echo credentials. Every
// artifact field that carries an error text gets the redaction that
// triage_failure_reason always had: the classification audit's parse_error,
// the PoC status, the stage failures, and the documents built from them.
func TestProviderErrorsAreRedactedInEveryArtifact(t *testing.T) {
	providerErr := func() error {
		return fmt.Errorf("openai chat error: POST %q: 401 Unauthorized api_key=sk-live-abcdefghijklmnopqrstuvwxyz Authorization: Bearer abcdef0123456789",
			"https://llm.example.internal/v1/chat/completions")
	}
	leaks := []string{"llm.example.internal", "sk-live-", "abcdefghijklmnopqrstuvwxyz", "abcdef0123456789"}

	for _, stage := range []string{"threat_model", "classification", "poc", "report", "fixspec"} {
		t.Run(stage, func(t *testing.T) {
			hermeticRun(t)
			stub := newStageLLM(t)
			fail := func(int) (string, error) { return "", providerErr() }
			switch stage {
			case "threat_model":
				stub.threatModel = func(int, []llm.Message) (string, error) { return "", providerErr() }
			case "classification":
				stub.classify = func(int, []classificationPromptFinding) (string, error) { return "", providerErr() }
			case "poc":
				stub.poc = fail
			case "report":
				stub.report = fail
			case "fixspec":
				stub.fixspec = fail
			}
			state := degradedRunState(t, healthcheck.FailOnNever)
			_ = Run(context.Background(), state, stub)

			artifact, err := BuildTriageFindingsArtifact(state)
			if err != nil {
				t.Fatal(err)
			}
			triage, _ := json.Marshal(artifact)
			handoff, _ := json.Marshal(state.AgentHandoff)
			documents := map[string]string{
				"triage-findings.json": string(triage),
				"handoff":              string(handoff),
				"summary.md":           state.SummaryMarkdown,
				"report.md":            state.ReportMarkdown,
				"fixspec.md":           state.AIFixSpec,
			}
			for name, doc := range documents {
				for _, leak := range leaks {
					if strings.Contains(doc, leak) {
						t.Errorf("%s leaks %q:\n%s", name, leak, doc)
					}
				}
			}
			if !strings.Contains(string(triage), "401 Unauthorized") {
				t.Fatalf("triage-findings.json lost the useful part of the error:\n%s", triage)
			}
		})
	}
}

// The classification audit keeps one entry per request; a failed request
// records the redacted error.
func TestClassificationAuditRecordsRedactedProviderError(t *testing.T) {
	hermeticRun(t)
	stub := newStageLLM(t)
	stub.classify = func(int, []classificationPromptFinding) (string, error) {
		return "", fmt.Errorf("openai chat error: POST %q: 401 Unauthorized api_key=sk-live-abcdefghijklmnopqrstuvwxyz", "https://llm.example.internal/v1/chat/completions")
	}
	state := degradedRunState(t, healthcheck.FailOnConfirmed)
	_ = Run(context.Background(), state, stub)

	if len(state.ClassificationAudit) == 0 {
		t.Fatal("classification audit is empty, want the failed request recorded")
	}
	for _, entry := range state.ClassificationAudit {
		if strings.Contains(entry.ParseError, "llm.example.internal") || strings.Contains(entry.ParseError, "sk-live-") {
			t.Fatalf("parse_error = %q, want it redacted", entry.ParseError)
		}
		if !strings.Contains(entry.ParseError, "401 Unauthorized") || !strings.Contains(entry.ParseError, "<url>") || !strings.Contains(entry.ParseError, "api_key=[redacted]") {
			t.Fatalf("parse_error = %q, want the redacted provider error", entry.ParseError)
		}
	}
}

// An Authorization header value is removed whole, not just its scheme.
func TestFailureReasonRedactsBearerCredentials(t *testing.T) {
	for _, text := range []string{
		"401: Authorization: Bearer abcdef0123456789",
		"401: authorization=Bearer abcdef0123456789",
		"401: Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l",
		"401: bearer abcdef0123456789",
	} {
		reason := failureReason(fmt.Errorf("%s", text))
		if strings.Contains(reason, "abcdef0123456789") || strings.Contains(reason, "YWxhZGRpbjpvcGVuc2VzYW1l") {
			t.Errorf("failureReason(%q) = %q, want the credential removed", text, reason)
		}
		if !strings.Contains(reason, "401") || !strings.Contains(reason, "[redacted]") {
			t.Errorf("failureReason(%q) = %q, want the status kept and the value marked redacted", text, reason)
		}
	}
}
