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

// Go's network and TLS errors name hosts and addresses outside any URL, and
// Gemini echoes the API key without a field name. The review's strings: every
// host, address and key is removed, and what kind of failure it was stays.
func TestFailureReasonRedactsHostsAddressesAndGoogleKeys(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{
			`openai chat error: Post "https://llm.corp.internal/v1/chat/completions": dial tcp: lookup llm.corp.internal on 10.0.0.2:53: no such host`,
			`openai chat error: Post "<url>": dial tcp: lookup <host>: no such host`,
		},
		{
			`openai chat error: Post "https://llm.corp.internal/v1/chat/completions": dial tcp 10.20.30.40:8443: connect: connection refused`,
			`openai chat error: Post "<url>": dial tcp <host>: connect: connection refused`,
		},
		{
			`tls: failed to verify certificate: x509: certificate is valid for gw.corp.internal, not llm.corp.internal`,
			`tls: failed to verify certificate: x509: certificate is valid for <host>, not <host>`,
		},
		{
			`x509: certificate is valid for a.corp.internal, b.corp.internal, *.corp.internal, not llm.corp.internal`,
			`x509: certificate is valid for <host>, not <host>`,
		},
		{
			`x509: certificate is not valid for any names, but wanted to match llm.corp.internal`,
			`x509: certificate is not valid for any names, but wanted to match <host>`,
		},
		{
			`gemini error: 400 API key not valid: AIzaSyA1234567890abcdefghijklmnopqrstu`,
			`gemini error: 400 API key not valid: [redacted]`,
		},
		{
			`proxyconnect tcp: dial tcp proxy.corp.internal:3128: i/o timeout`,
			`proxyconnect tcp: dial tcp <host>: i/o timeout`,
		},
		{
			`dial tcp [2001:db8::10]:443: connect: network is unreachable; resolver fe80::1 and 192.168.1.20 unreachable`,
			`dial tcp <host>: connect: network is unreachable; resolver <ip> and <ip> unreachable`,
		},
		{
			// Nothing secret: the request id and the provider's own words stay.
			`anthropic: 401 {"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}} request-id req_011CU1234567890abcdef`,
			`anthropic: 401 {"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}} request-id req_011CU1234567890abcdef`,
		},
		{
			// A failed lookup in prose is not a host.
			`dns lookup failed at 12:30:45`,
			`dns lookup failed at 12:30:45`,
		},
	}
	for _, tc := range cases {
		if got := failureReason(fmt.Errorf("%s", tc.text)); got != tc.want {
			t.Errorf("failureReason(%q)\n got: %s\nwant: %s", tc.text, got, tc.want)
		}
	}
	// A canonical key (AIza and 35 characters) inside a sentence.
	key := "AIza" + strings.Repeat("A1b2C3d4e5", 3) + "_-x9Z"
	if got := failureReason(fmt.Errorf("request rejected for key %s by policy", key)); strings.Contains(got, key) || !strings.Contains(got, "by policy") {
		t.Errorf("failureReason = %q, want the Google API key removed", got)
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
