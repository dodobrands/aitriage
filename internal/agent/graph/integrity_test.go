package graph

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func integrityTestState() *AgentState {
	findings := []EnrichedFinding{
		{ID: "R1", VulnID: "CS-JWT-001", Type: "external", Severity: "HIGH", File: "req.txt", Line: 1, Message: "[trivy] PyJWT auth bypass CVE-2026-28684"},
		{ID: "R2", VulnID: "CS-XSS-001", Type: "core", Severity: "MEDIUM", File: "app.tsx", Line: 9, Message: "reflected XSS"},
	}
	return &AgentState{
		EnrichedFindings: findings,
		FindingDispositions: []FindingDisposition{
			{FindingIndex: 0, FindingID: "CS-JWT-001", Disposition: "True Positive", Rationale: "reachable", Fingerprint: Fingerprint(findings[0]), DispositionSource: dispositionSourceLLM},
			{FindingIndex: 1, FindingID: "CS-XSS-001", Disposition: "False Positive", Rationale: "escaped", Fingerprint: Fingerprint(findings[1]), DispositionSource: dispositionSourceLLM},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnNever},
	}
}

func TestValidateArtifactIntegrityCleanPasses(t *testing.T) {
	state := integrityTestState()
	state.ReportMarkdown = "Analysis of CS-JWT-001 and CVE-2026-28684.\n\n" + buildCanonicalFindingsSection(state)
	state.AIFixSpec = canonicalActiveFindingsBrief(state)

	if v := validateArtifactIntegrity(state); len(v) != 0 {
		t.Fatalf("clean artifacts should pass, got violations: %v", v)
	}
}

func TestValidateArtifactIntegrityFlagsHallucinatedCVE(t *testing.T) {
	state := integrityTestState()
	state.ReportMarkdown = "This is affected by CVE-2024-12345 in a dependency.\n" + buildCanonicalFindingsSection(state)
	state.AIFixSpec = canonicalActiveFindingsBrief(state)

	v := validateArtifactIntegrity(state)
	if len(v) == 0 || !strings.Contains(strings.Join(v, "\n"), "CVE-2024-12345") {
		t.Fatalf("expected hallucinated CVE violation, got: %v", v)
	}
}

func TestValidateArtifactIntegrityFlagsUnknownVulnID(t *testing.T) {
	state := integrityTestState()
	state.ReportMarkdown = buildCanonicalFindingsSection(state)
	state.AIFixSpec = "Fix CS-SQLI-999 first.\n" + canonicalActiveFindingsBrief(state)

	v := validateArtifactIntegrity(state)
	if len(v) == 0 || !strings.Contains(strings.Join(v, "\n"), "CS-SQLI-999") {
		t.Fatalf("expected unknown vuln ID violation, got: %v", v)
	}
}

func TestEnforceArtifactIntegrityRebuildsDeterministic(t *testing.T) {
	state := integrityTestState()
	state.ReportMarkdown = "Bogus narrative mentioning CVE-2024-12345.\n"
	state.AIFixSpec = "Bogus fix for CS-SQLI-999.\n"

	if !enforceArtifactIntegrity(state) {
		t.Fatal("expected integrity enforcement to trigger a fallback")
	}
	// After rebuild the artifacts must be canonical-safe (validation passes).
	if v := validateArtifactIntegrity(state); len(v) != 0 {
		t.Fatalf("deterministic rebuild should be canonical-safe, got: %v", v)
	}
	if !strings.Contains(state.ReportMarkdown, "Integrity notice") || !strings.Contains(state.ReportMarkdown, "CS-JWT-001") {
		t.Fatalf("rebuilt report missing notice/canonical content: %q", state.ReportMarkdown)
	}
	// The hallucinated identifiers must be gone.
	if strings.Contains(state.ReportMarkdown, "CVE-2024-12345") || strings.Contains(state.AIFixSpec, "CS-SQLI-999") {
		t.Fatal("rebuilt artifacts still contain hallucinated identifiers")
	}
}

// D4: the validator knows the CS-<CLASS>-<hex> display ids. A real id passes;
// an unknown one in either form, including the counter form of earlier
// releases a model may reproduce, is caught.
func TestValidateArtifactIntegrityUnderstandsStableDisplayIDs(t *testing.T) {
	state := &AgentState{
		CoreFindings: []core.CheckResult{
			{ID: "FAST-SQLI", Name: "SQL Injection Risk", Status: core.Absent, Severity: "CRITICAL", File: "db.py", Line: 10, Evidence: "raw query"},
		},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnNever},
	}
	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "True Positive")
	valid := state.EnrichedFindings[0].VulnID
	if !vulnIDPattern.MatchString(valid) {
		t.Fatalf("display id %q does not match the validator pattern", valid)
	}

	state.ReportMarkdown = "Fix " + valid + " first.\n\n" + buildCanonicalFindingsSection(state)
	state.AIFixSpec = canonicalActiveFindingsBrief(state)
	if v := validateArtifactIntegrity(state); len(v) != 0 {
		t.Fatalf("canonical display id flagged: %v", v)
	}

	for _, bogus := range []string{"CS-SQLI-ABC123", "CS-SQLI-001"} {
		state.AIFixSpec = "Also fix " + bogus + ".\n" + canonicalActiveFindingsBrief(state)
		v := validateArtifactIntegrity(state)
		if len(v) == 0 || !strings.Contains(strings.Join(v, "\n"), bogus) {
			t.Fatalf("unknown id %s not flagged: %v", bogus, v)
		}
	}
}

func TestCanonicalFindingsSectionMatchesState(t *testing.T) {
	state := integrityTestState()
	section := buildCanonicalFindingsSection(state)
	for _, want := range []string{"CS-JWT-001", "CS-XSS-001", "True Positive", "False Positive"} {
		if !strings.Contains(section, want) {
			t.Fatalf("canonical section missing %q:\n%s", want, section)
		}
	}
	// FP finding must not leak into the active-findings brief.
	brief := canonicalActiveFindingsBrief(state)
	if strings.Contains(brief, "CS-XSS-001") {
		t.Fatalf("active brief must exclude False Positive finding:\n%s", brief)
	}
	if !strings.Contains(brief, "CS-JWT-001") {
		t.Fatalf("active brief must include the True Positive finding:\n%s", brief)
	}
}
