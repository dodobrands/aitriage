package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

const literalSecret = "SuperSecret123"

func secretReports() (core.CheckResult, external.UnifiedFinding, external.UnifiedFinding) {
	return core.CheckResult{ID: "SECRET-ASSIGN", Name: "Hardcoded Secret", Status: core.Absent, Severity: "CRITICAL", File: "settings.py", Line: 1, Evidence: "DB_PASSWORD assignment"},
		external.UnifiedFinding{Source: "gitleaks", RuleID: "generic-api-key", Severity: "HIGH", File: "settings.py", Line: 1, Message: "Detected a Generic API Key: REDACTED"},
		external.UnifiedFinding{Source: "bandit", RuleID: "B105", Severity: "LOW", File: "settings.py", Line: 1, Message: "hardcoded_password_string: Possible hardcoded password: '" + literalSecret + "'"}
}

// The detectors of a hardcoded secret merge into one finding represented by
// Gitleaks whenever Gitleaks reported it, then by a built-in SECRET-* rule,
// then by anything else, whatever order the reports came in. The finding's
// source is then "gitleaks" for a CI gate written against Gitleaks, and its
// title is Gitleaks' redacted message, not Bandit's, which quotes the value.
func TestMergedSecretIsRepresentedByGitleaksThenBuiltIn(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{"settings.py": "DB_PASSWORD = \"" + literalSecret + "\"\n"})
	builtin, gitleaks, bandit := secretReports()
	cases := []struct {
		name       string
		core       []core.CheckResult
		external   []external.UnifiedFinding
		wantSource string
		wantRule   string
	}{
		{"gitleaks and bandit", nil, []external.UnifiedFinding{bandit, gitleaks}, "gitleaks", "generic-api-key"},
		{"gitleaks and bandit, reversed", nil, []external.UnifiedFinding{gitleaks, bandit}, "gitleaks", "generic-api-key"},
		{"gitleaks under a built-in rule", []core.CheckResult{builtin}, []external.UnifiedFinding{bandit, gitleaks}, "gitleaks", "generic-api-key"},
		{"built-in rule and bandit", []core.CheckResult{builtin}, []external.UnifiedFinding{bandit}, "aitriage", "SECRET-ASSIGN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &AgentState{ProjectPath: root, CoreFindings: tc.core, ExternalFindings: tc.external}
			enrichFindings(state)
			if len(state.EnrichedFindings) != 1 {
				t.Fatalf("findings = %+v, want one hardcoded secret", state.EnrichedFindings)
			}
			secret := state.EnrichedFindings[0]
			if secret.Class != healthcheck.ClassHardcodedSecret || secret.Source != tc.wantSource || secret.ID != tc.wantRule {
				t.Fatalf("representative = %s/%s (%s), want %s/%s", secret.Source, secret.ID, secret.Class, tc.wantSource, tc.wantRule)
			}
			if len(secret.Origins) != len(tc.core)+len(tc.external) {
				t.Fatalf("origins = %+v, want every detector", secret.Origins)
			}
			if strings.Contains(secret.Message, literalSecret) {
				t.Fatalf("message %q quotes the secret", secret.Message)
			}

			state.FindingDispositions = allDispositions(state, "True Positive")
			computeHealthCheck(state)
			if err := generateSummary(state); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(state.SummaryMarkdown, literalSecret) {
				t.Fatalf("summary quotes the secret:\n%s", state.SummaryMarkdown)
			}
			artifact, err := BuildTriageFindingsArtifact(state)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(artifact.Findings[0].Finding.Message)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), literalSecret) {
				t.Fatalf("triage-findings.json finding.message quotes the secret: %s", data)
			}
		})
	}
}

// Bandit's password checks quote the value they found; the triage graph masks
// it. Other Bandit messages are kept as reported.
func TestBanditPasswordMessagesAreMasked(t *testing.T) {
	_, _, bandit := secretReports()
	funcarg := external.UnifiedFinding{Source: "bandit", RuleID: "B106", Severity: "LOW", File: "db.py", Line: 3, Message: `hardcoded_password_funcarg: Possible hardcoded password: "hunter22"`}
	shell := external.UnifiedFinding{Source: "bandit", RuleID: "B602", Severity: "HIGH", File: "run.py", Line: 7, Message: "subprocess call with shell=True identified, security issue: 'ls'"}

	if got := scannerMessage(bandit); got != "hardcoded_password_string: Possible hardcoded password: '[redacted]'" {
		t.Errorf("B105 message = %q", got)
	}
	if got := scannerMessage(funcarg); got != `hardcoded_password_funcarg: Possible hardcoded password: "[redacted]"` {
		t.Errorf("B106 message = %q", got)
	}
	if got := scannerMessage(shell); got != shell.Message {
		t.Errorf("B602 message = %q, want it kept", got)
	}

	state := &AgentState{ProjectPath: t.TempDir(), ExternalFindings: []external.UnifiedFinding{bandit}}
	enrichFindings(state)
	if got := state.EnrichedFindings[0].Message; strings.Contains(got, literalSecret) || !strings.Contains(got, "[redacted]") {
		t.Fatalf("enriched message = %q, want the password masked", got)
	}
}
