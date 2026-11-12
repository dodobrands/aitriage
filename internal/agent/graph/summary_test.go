package graph

import (
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

func TestGenerateSummaryExcludesFalsePositives(t *testing.T) {
	state := &AgentState{
		EnrichedFindings: []EnrichedFinding{
			{ID: "hardcoded-secret", VulnID: "CS-SECRETS-001", Type: "core", Severity: "CRITICAL", File: "config.py", Line: 10, Message: "Hardcoded password found"},
			{ID: "math-random", VulnID: "CS-CRYPTO-001", Type: "core", Severity: "HIGH", File: "snowflake.ts", Line: 5, Message: "Math.random() used for visual effects"},
			{ID: "insecure-proxy", VulnID: "CS-CONFIG-001", Type: "core", Severity: "MEDIUM", File: "vite.config.ts", Line: 20, Message: "Proxy secure=false for docker"},
		},
		FindingDispositions: []FindingDisposition{
			{FindingIndex: 0, FindingID: "CS-SECRETS-001", Disposition: "True Positive", Rationale: "Real password in config"},
			{FindingIndex: 1, FindingID: "CS-CRYPTO-001", Disposition: "False Positive", Rationale: "Math.random used for visual snowflakes, not security"},
			{FindingIndex: 2, FindingID: "CS-CONFIG-001", Disposition: "Needs Manual Review", Rationale: "Docker local dev only, but verify"},
		},
	}

	// The headline counts come from the health-check breakdown, as in Run,
	// so they can never disagree with the gate.
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	if summary == "" {
		t.Fatal("SummaryMarkdown is empty")
	}

	// Must contain TP finding in AI prompt or AI data
	if !strings.Contains(summary, "CS-SECRETS-001") {
		t.Error("Summary should contain True Positive finding CS-SECRETS-001")
	}

	// Must contain NR finding
	if !strings.Contains(summary, "CS-CONFIG-001") {
		t.Error("Summary should contain Needs Manual Review finding CS-CONFIG-001")
	}

	// Must NOT contain FP finding in actionable sections
	if strings.Contains(summary, "CS-CRYPTO-001") {
		t.Error("Summary should NOT contain False Positive finding CS-CRYPTO-001")
	}

	// Must mention suppressed count in footer
	if !strings.Contains(summary, "1 false positive(s) suppressed") {
		t.Error("Summary footer should mention 1 suppressed false positive")
	}

	// Must contain severity matrix (new format)
	if !strings.Contains(summary, "True Positives") {
		t.Error("Summary should contain severity matrix with True Positives row")
	}

	// Must contain stats in blockquote
	if !strings.Contains(summary, "1** true positives") {
		t.Error("Summary should show 1 true positive in stats blockquote")
	}
	if !strings.Contains(summary, "1** false positives suppressed") {
		t.Error("Summary should show 1 suppressed FP in stats blockquote")
	}
}

func TestGenerateSummaryNoFindings(t *testing.T) {
	state := &AgentState{
		EnrichedFindings:    nil,
		FindingDispositions: nil,
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	if summary == "" {
		t.Fatal("SummaryMarkdown is empty")
	}
	if !strings.Contains(summary, "No actionable security findings") {
		t.Error("Summary should show 'No actionable security findings' when there are no findings")
	}
}

func TestGenerateSummaryAllFalsePositives(t *testing.T) {
	state := &AgentState{
		EnrichedFindings: []EnrichedFinding{
			{ID: "r1", VulnID: "CS-XSS-001", Type: "core", Severity: "HIGH", File: "app.ts", Line: 1, Message: "XSS in safe context"},
			{ID: "r2", VulnID: "CS-XSS-002", Type: "core", Severity: "MEDIUM", File: "app.ts", Line: 5, Message: "Another safe XSS"},
		},
		FindingDispositions: []FindingDisposition{
			{FindingIndex: 0, FindingID: "CS-XSS-001", Disposition: "False Positive", Rationale: "React auto-escapes"},
			{FindingIndex: 1, FindingID: "CS-XSS-002", Disposition: "False Positive", Rationale: "Template is safe"},
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	if !strings.Contains(summary, "No actionable security findings") {
		t.Error("Summary should show 'No actionable security findings' when all are FP")
	}
	if !strings.Contains(summary, "2 false positive(s) suppressed") {
		t.Error("Summary footer should mention 2 suppressed false positives")
	}
}

func TestGenerateSummaryRejectsUndisposedFindings(t *testing.T) {
	state := &AgentState{
		EnrichedFindings: []EnrichedFinding{
			{ID: "r1", VulnID: "CS-AUTH-001", Type: "core", Severity: "HIGH", File: "api.go", Line: 42, Message: "Missing auth"},
		},
		FindingDispositions: nil,
	}

	if err := generateSummary(state); err == nil {
		t.Fatal("generateSummary() should reject incomplete dispositions")
	}
}

func TestGenerateSummaryPipesInMessagesAreEscaped(t *testing.T) {
	state := &AgentState{
		EnrichedFindings: []EnrichedFinding{
			{ID: "r1", VulnID: "CS-MISC-001", Type: "core", Severity: "HIGH", File: "x.go", Line: 1, Message: "Issue with | pipe char"},
		},
		FindingDispositions: []FindingDisposition{
			{FindingIndex: 0, FindingID: "CS-MISC-001", Disposition: "True Positive", Rationale: "Real issue"},
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	// The AI prompt restores pipes for readability, but the message is stored escaped internally.
	// Verify the finding appears in the summary (AI prompt or AI data block).
	if !strings.Contains(state.SummaryMarkdown, "CS-MISC-001") {
		t.Error("Finding CS-MISC-001 should appear in the summary")
	}
	// The AI data JSON block should have the pipe unescaped in the title field
	if !strings.Contains(state.SummaryMarkdown, "Issue with | pipe char") {
		t.Error("AI data block should contain unescaped pipe in JSON title")
	}
}

func TestGenerateSummaryHasThreeBlocks(t *testing.T) {
	state := &AgentState{
		EnrichedFindings: []EnrichedFinding{
			{ID: "r1", VulnID: "CS-SQLI-001", Type: "core", Severity: "CRITICAL", File: "db.py", Line: 10, Message: "SQL Injection via string concat"},
		},
		FindingDispositions: []FindingDisposition{
			{FindingIndex: 0, FindingID: "CS-SQLI-001", Disposition: "True Positive", Rationale: "Confirmed exploitable"},
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown

	// Block 1: Human Summary
	if !strings.Contains(summary, "🛡 Security Assessment") {
		t.Error("Missing Block 1: Human Summary header")
	}
	if !strings.Contains(summary, "Top Critical Issues") {
		t.Error("Missing Block 1: Top Critical Issues section")
	}

	// Block 2: AI Remediation Prompt
	if !strings.Contains(summary, "AI Remediation Prompt") {
		t.Error("Missing Block 2: AI Remediation Prompt header")
	}
	if !strings.Contains(summary, "SecureCoder") {
		t.Error("Missing Block 2: SecureCoder reference in prompt")
	}
	if !strings.Contains(summary, "Do not stop after the plan") {
		t.Error("Missing Block 2: instruction to implement after planning")
	}
	if !strings.Contains(summary, "Needs Manual Review") {
		t.Error("Missing Block 2: manual-review safety boundary")
	}
	if strings.Contains(summary, "DO NOT write actual code") {
		t.Error("Block 2 must not prohibit implementation")
	}

	// Block 3: AI Agent Data
	if !strings.Contains(summary, "AI Agent Data") {
		t.Error("Missing Block 3: AI Agent Data header")
	}
	if !strings.Contains(summary, `"id": "CS-SQLI-001"`) {
		t.Error("Missing Block 3: JSON finding in AI data block")
	}

	// Verify order: Human → Prompt → AI Data
	humanIdx := strings.Index(summary, "🛡 Security Assessment")
	promptIdx := strings.Index(summary, "AI Remediation Prompt")
	dataIdx := strings.Index(summary, "AI Agent Data")
	if humanIdx >= promptIdx {
		t.Error("Block 1 (Human) should come before Block 2 (Prompt)")
	}
	if promptIdx >= dataIdx {
		t.Error("Block 2 (Prompt) should come before Block 3 (AI Data)")
	}
}

func TestGenerateSummaryReportsProviderUsageWithoutInventingCost(t *testing.T) {
	state := &AgentState{
		TotalUsage: llm.Usage{
			PromptTokens:     32777,
			CompletionTokens: 32189,
			TotalTokens:      88735,
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	if !strings.Contains(summary, "88735 total · 32777 prompt · 32189 completion · 23769 reasoning/other · cache telemetry: provider_did_not_report") {
		t.Fatalf("summary does not contain complete provider usage: %s", summary)
	}
	if strings.Contains(strings.ToLower(summary), "est. cost") || strings.Contains(summary, "$0.") {
		t.Fatalf("summary must not invent a cost: %s", summary)
	}
}

func TestGenerateSummaryReportsVerdictCacheStats(t *testing.T) {
	state := &AgentState{
		VerdictCacheStats: VerdictCacheStats{
			Enabled:                   true,
			Hits:                      7,
			Misses:                    3,
			Stores:                    3,
			SkippedSensitive:          1,
			InvalidatedFalsePositives: 2,
			Saved:                     true,
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	want := "AITriage verdict cache: 7 hits · 3 misses · 3 stored · 1 sensitive skipped · 2 stale FP invalidated · saved=true"
	if !strings.Contains(summary, want) {
		t.Fatalf("summary does not contain verdict cache stats %q: %s", want, summary)
	}
}

func TestGenerateSummaryReportsArtifactCacheStats(t *testing.T) {
	state := &AgentState{
		ArtifactCacheStats: ArtifactCacheStats{
			Enabled:             true,
			ExactHit:            true,
			RestoredPoC:         true,
			RestoredReport:      true,
			RestoredFixSpec:     true,
			Stores:              0,
			SkippedSensitive:    1,
			CorruptCacheIgnored: true,
			Saved:               false,
		},
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}

	summary := state.SummaryMarkdown
	want := "AITriage artifact cache: exact hit · restored poc=true report=true fixspec=true · stored=0 · sensitive skipped=1 · corrupt ignored=true · miss_reason=n/a · saved=false · uncached verdicts=0 · eligibility skipped=false · integrity failed=false"
	if !strings.Contains(summary, want) {
		t.Fatalf("summary does not contain artifact cache stats %q: %s", want, summary)
	}
}
