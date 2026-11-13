package graph

import (
	"slices"
	"testing"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// A default credential in a Compose file is reported at MEDIUM. The class it
// shares with every hardcoded secret sets no severity of its own, so the
// MEDIUM survives the merge into canonical findings, also with a weaker
// detector on the same line, and the health check counts it at MEDIUM. It is
// still a hardcoded secret, which only a person dismisses.
func TestComposeDefaultCredentialKeepsItsSeverityEndToEnd(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{"docker-compose.yml": `services:
  ledger-db:
    image: postgres:16
    environment:
      POSTGRES_USER: ledger_app
      POSTGRES_PASSWORD: ledger_app
  ledger:
    image: ledger-service:dev
    environment:
      LEDGER_API_SECRET: 8f2Kq9vLx3TzR7mW4pYc
`})
	deploy, err := deployaudit.AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	weaker := external.UnifiedFinding{
		Source: "semgrep", RuleID: "generic.secrets.security.detected-generic-secret.detected-generic-secret",
		Severity: "LOW", File: "docker-compose.yml", Line: 6, Message: "Generic Secret detected",
	}
	state := &AgentState{ProjectPath: root, DeployFindings: deploy, ExternalFindings: []external.UnifiedFinding{weaker}}
	enrichFindings(state)

	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("findings = %+v; want the default credential and the secret", state.EnrichedFindings)
	}
	bySeverity := map[string]EnrichedFinding{}
	for _, f := range state.EnrichedFindings {
		bySeverity[f.Severity] = f
		if f.Class != healthcheck.ClassHardcodedSecret {
			t.Errorf("%s: class %q; want %q", f.ID, f.Class, healthcheck.ClassHardcodedSecret)
		}
		if !isHardcodedSecret(f) {
			t.Errorf("%s is no longer a hardcoded secret, so a model could dismiss it", f.ID)
		}
	}
	credential, secret := bySeverity["MEDIUM"], bySeverity["CRITICAL"]
	if secret.ID != deployaudit.IssueComposeHardcodedSecret || secret.Line != 10 {
		t.Errorf("CRITICAL finding = %s line %d; want the hardcoded secret on line 10", secret.ID, secret.Line)
	}
	var rules []string
	for _, origin := range credential.Origins {
		rules = append(rules, origin.RuleID)
	}
	if credential.Line != 6 || !slices.Contains(rules, deployaudit.IssueComposeDefaultCredential) || !slices.Contains(rules, weaker.RuleID) {
		t.Fatalf("MEDIUM finding = %+v; want the default credential on line 6 merged with the weaker report", credential)
	}

	state.FindingDispositions = allDispositions(state, "Needs Manual Review")
	computeHealthCheck(state)
	bd := state.HealthCheck.Breakdown
	if bd.CountBySeverity["MEDIUM"] != 1 || bd.CountBySeverity["CRITICAL"] != 1 || bd.CountByClass[healthcheck.ClassHardcodedSecret] != 2 {
		t.Errorf("breakdown by severity = %v, by class = %v; want the default credential at MEDIUM", bd.CountBySeverity, bd.CountByClass)
	}
}
