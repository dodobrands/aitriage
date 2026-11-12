package graph

import (
	"reflect"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

func TestEnrichFindingsCanonicalizesOrderBeforeVulnIDs(t *testing.T) {
	findings := []core.CheckResult{
		{ID: "FAST-RATELIMIT", Name: "Missing Rate Limiting", Evidence: "Required pattern not found", Severity: "HIGH"},
		{ID: "ENTR-INSECURE-RANDOM", Name: "Insecure Randomness", Evidence: "Math.random", Severity: "HIGH", File: "frontend/src/Confetti.tsx", Line: 21},
		{ID: "FAST-CORS-WILDCARD", Name: "CORS Allow All Origins", Evidence: "allow_origins=['*']", Severity: "HIGH", File: "backend/main.py", Line: 24},
		{ID: "FAST-LOGGING", Name: "Missing Security Logging", Evidence: "Required pattern not found", Severity: "MEDIUM"},
	}

	stateA := &AgentState{CoreFindings: findings}
	stateB := &AgentState{CoreFindings: []core.CheckResult{findings[1], findings[3], findings[2], findings[0]}}
	enrichFindings(stateA)
	enrichFindings(stateB)

	gotA := enrichedOrderSignature(stateA.EnrichedFindings)
	gotB := enrichedOrderSignature(stateB.EnrichedFindings)
	if !reflect.DeepEqual(gotA, gotB) {
		t.Fatalf("canonical enriched order differs:\nA=%v\nB=%v", gotA, gotB)
	}
}

func TestEnrichFindingsMergesSemanticAliasesAndKeepsOrigins(t *testing.T) {
	state := &AgentState{
		CoreFindings: []core.CheckResult{
			{ID: "FAST-LAZY-EXC", Name: "Lazy Exception Handling", Evidence: "except pass", Severity: "HIGH", File: "app.py", Line: 10},
			{ID: "FAST-AUTH", Name: "Missing Authentication", Evidence: "required pattern", Severity: "HIGH"},
			{ID: "FAST-RATELIMIT", Name: "Missing Rate Limiting", Evidence: "required pattern", Severity: "HIGH"},
		},
		ExternalFindings: []external.UnifiedFinding{
			{RuleID: "B110", Source: "bandit", Severity: "LOW", File: "app.py", Line: 10, Message: "try_except_pass"},
		},
		NFRFindings: []nfr.NFRFinding{
			{RuleID: "NFR-API-003", Name: "Authentication Middleware Missing", Severity: "HIGH", Message: "No authentication middleware detected"},
			{RuleID: "NFR-API-001", Name: "Rate Limiting Missing", Severity: "HIGH", Message: "No rate limiting detected"},
		},
	}

	enrichFindings(state)
	// The two reports of the swallowed exception on app.py:10 are one finding;
	// the four project-level checks are four rules, each its own finding: a
	// class never merges reports that carry no location.
	if len(state.EnrichedFindings) != 5 {
		t.Fatalf("semantic findings = %d, want 5 (one located merge, four project-level rules): %+v", len(state.EnrichedFindings), state.EnrichedFindings)
	}
	byRule := map[string]EnrichedFinding{}
	for _, finding := range state.EnrichedFindings {
		byRule[finding.ID] = finding
	}
	if swallow := byRule["FAST-LAZY-EXC"]; swallow.Class != "exception_swallow" || len(swallow.Origins) != 2 {
		t.Fatalf("exception_swallow = %+v, want both scanners merged", swallow)
	}
	for _, rule := range []string{"FAST-AUTH", "NFR-API-003", "FAST-RATELIMIT", "NFR-API-001"} {
		finding, ok := byRule[rule]
		if !ok || len(finding.Origins) != 1 || finding.Origins[0].RuleID != rule {
			t.Fatalf("%s = %+v, want a finding of its own", rule, finding)
		}
	}

	computeHealthCheck(state)
	if state.HealthCheck.Breakdown.ActiveFindings != 5 {
		t.Fatalf("health active findings = %d, want 5", state.HealthCheck.Breakdown.ActiveFindings)
	}
}

func enrichedOrderSignature(findings []EnrichedFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.VulnID+"|"+f.ID+"|"+Fingerprint(f))
	}
	return out
}

func TestCountUncachedVerdicts(t *testing.T) {
	state := &AgentState{
		FindingDispositions: []FindingDisposition{
			{Fingerprint: "fp-a", DispositionSource: dispositionSourceNRFallback},
			{Fingerprint: "fp-a", DispositionSource: dispositionSourceNRFallback}, // duplicate projection
			{Fingerprint: "fp-b", DispositionSource: dispositionSourceNRFallback},
			{Fingerprint: "fp-c", DispositionSource: dispositionSourceLLM},
			{Fingerprint: "fp-d", DispositionSource: dispositionSourceCache},
		},
	}
	state.VerdictCacheStats.SkippedSensitive = 1

	if got := countUncachedVerdicts(state); got != 3 {
		t.Fatalf("countUncachedVerdicts = %d, want 2 unique NR-fallback + 1 sensitive-skipped", got)
	}
}

func TestClassifyMaxRetriesEnvOverride(t *testing.T) {
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "")
	if got := classifyMaxRetries(); got != threatModelMaxRetries {
		t.Fatalf("default retries = %d, want %d", got, threatModelMaxRetries)
	}
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "4")
	if got := classifyMaxRetries(); got != 4 {
		t.Fatalf("env retries = %d, want 4", got)
	}
	t.Setenv("AITRIAGE_CLASSIFY_RETRIES", "not-a-number")
	if got := classifyMaxRetries(); got != threatModelMaxRetries {
		t.Fatalf("invalid env retries = %d, want fallback %d", got, threatModelMaxRetries)
	}
}

// The class code of a display id comes from the rule, not from words in the
// message: nginx_missing_csp on a supervisord.conf used to become CS-XSS-003
// because its advice mentions XSS.
func TestClassCodeComesFromTheRuleNotTheMessage(t *testing.T) {
	cases := []struct {
		finding EnrichedFinding
		want    string
	}{
		{EnrichedFinding{ID: "nginx_missing_csp", Type: "deploy", Source: "aitriage", Message: "nginx_missing_csp. Advice: add a CSP header to mitigate XSS"}, "MISC"},
		{EnrichedFinding{ID: "B602", Type: "external", Source: "bandit", Message: "[bandit] subprocess_popen_with_shell_equals_true"}, "CMDI"},
		{EnrichedFinding{ID: "generic-api-key", Type: "external", Source: "gitleaks", Message: "[gitleaks] Detected a Generic API Key"}, "SECRETS"},
		{EnrichedFinding{ID: "CVE-2023-50447", Type: "external", Source: "trivy", Package: "pillow", Message: "[trivy] Arbitrary code execution via PIL.ImageMath.eval"}, "DEP"},
		{EnrichedFinding{ID: "port-53", Type: "network", Source: "aitriage", Message: "Port 53 (dns): open"}, "NET"},
	}
	for _, tc := range cases {
		if got := classCode(tc.finding); got != tc.want {
			t.Errorf("classCode(%s) = %q, want %q", tc.finding.ID, got, tc.want)
		}
	}
}

func TestAssignVulnIDsStableAcrossRuns(t *testing.T) {
	build := func() []EnrichedFinding {
		findings := []EnrichedFinding{
			{ID: "T1", Type: "external", Source: "trivy", Severity: "HIGH", File: "req.txt", Line: 1, Message: "[trivy] PyJWT: Authentication bypass due to forged JSON Web Tokens with a weak secret"},
			{ID: "T2", Type: "external", Source: "trivy", Severity: "HIGH", File: "req.txt", Line: 2, Message: "[trivy] PyJWT: Denial of Service via crafted JWS tokens"},
			{ID: "T3", Type: "external", Source: "trivy", Severity: "MEDIUM", File: "pkg.json", Line: 3, Message: "[trivy] Vite: Information disclosure via path traversal in dev server"},
		}
		assignVulnIDs(findings)
		return findings
	}
	base := enrichedOrderSignature(build())
	for i := 0; i < 100; i++ {
		if got := enrichedOrderSignature(build()); !reflect.DeepEqual(base, got) {
			t.Fatalf("vuln IDs unstable across runs:\nbase=%v\ngot=%v", base, got)
		}
	}
}
