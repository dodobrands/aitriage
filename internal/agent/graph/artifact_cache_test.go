package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func TestArtifactCacheDisabledByDefault(t *testing.T) {
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_CACHE_DIR", "")

	cache := newArtifactBundleCache()
	if cache.enabled || cache.Stats().Enabled {
		t.Fatalf("artifact cache should be disabled by default: %+v", cache.Stats())
	}
}

func TestArtifactCacheStoreAndExactHit(t *testing.T) {
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", t.TempDir())
	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "# report"
	state.AIFixSpec = "# fixspec"
	state.PoCResults = []PoCResult{{VulnerabilityType: "x", Severity: "HIGH", Conclusion: "Needs Manual Review"}}

	key, miss := buildArtifactCacheKey(state)
	if miss != "" {
		t.Fatalf("buildArtifactCacheKey miss = %q", miss)
	}
	cache := newArtifactBundleCache()
	cache.Store(state, key)
	cache.Save()
	if stats := cache.Stats(); stats.Stores != 1 || !stats.Saved {
		t.Fatalf("store stats = %+v, want one saved store", stats)
	}

	reloaded := newArtifactBundleCache()
	restored := &AgentState{}
	if !reloaded.Restore(restored, key) {
		t.Fatalf("expected artifact cache hit, stats=%+v", reloaded.Stats())
	}
	if restored.ReportMarkdown != "# report" || restored.AIFixSpec != "# fixspec" || len(restored.PoCResults) != 1 {
		t.Fatalf("restored state = %+v, want full bundle", restored)
	}
	if stats := reloaded.Stats(); !stats.ExactHit || !stats.RestoredPoC || !stats.RestoredReport || !stats.RestoredFixSpec {
		t.Fatalf("restore stats = %+v, want exact restored bundle", stats)
	}
}

func TestArtifactCacheKeyInvalidatesOnDispositionAndPolicyChange(t *testing.T) {
	t.Setenv("AITRIAGE_LLM_PROVIDER", "provider-a")
	t.Setenv("AITRIAGE_MODEL", "model-a")
	base := artifactCacheTestState("True Positive")
	key1, miss := buildArtifactCacheKey(base)
	if miss != "" {
		t.Fatalf("base key miss = %q", miss)
	}

	changedDisposition := artifactCacheTestState("Needs Manual Review")
	key2, miss := buildArtifactCacheKey(changedDisposition)
	if miss != "" {
		t.Fatalf("changed disposition key miss = %q", miss)
	}
	if key1 == key2 {
		t.Fatal("artifact cache key should change when disposition changes")
	}

	changedPolicy := artifactCacheTestState("True Positive")
	changedPolicy.Policy = healthcheck.Policy{Profile: "strict", FailOn: healthcheck.FailOnAny}
	key3, miss := buildArtifactCacheKey(changedPolicy)
	if miss != "" {
		t.Fatalf("changed policy key miss = %q", miss)
	}
	if key1 == key3 {
		t.Fatal("artifact cache key should change when policy changes")
	}

	t.Setenv("AITRIAGE_MODEL", "model-b")
	changedModel := artifactCacheTestState("True Positive")
	key4, miss := buildArtifactCacheKey(changedModel)
	if miss != "" {
		t.Fatalf("changed model key miss = %q", miss)
	}
	if key1 == key4 {
		t.Fatal("artifact cache key should change when model changes")
	}

	t.Setenv("AITRIAGE_LLM_PROVIDER", "provider-b")
	changedProvider := artifactCacheTestState("True Positive")
	key5, miss := buildArtifactCacheKey(changedProvider)
	if miss != "" {
		t.Fatalf("changed provider key miss = %q", miss)
	}
	if key4 == key5 {
		t.Fatal("artifact cache key should change when provider changes")
	}
}

// A cached report names display ids, which follow the flagged line's content
// rather than the fingerprint; a bundle must not be restored under ids it does
// not contain. The id echoed in a disposition is not part of the key.
func TestArtifactCacheKeyFollowsDisplayIDs(t *testing.T) {
	base := artifactCacheTestState("True Positive")
	key1, miss := buildArtifactCacheKey(base)
	if miss != "" {
		t.Fatalf("base key miss = %q", miss)
	}

	echoed := artifactCacheTestState("True Positive")
	echoed.FindingDispositions[0].FindingID = "CS-AUTH-1A2B3C"
	if key, _ := buildArtifactCacheKey(echoed); key != key1 {
		t.Fatal("artifact cache key must not depend on the id a disposition echoes")
	}

	renamed := artifactCacheTestState("True Positive")
	renamed.EnrichedFindings[0].VulnID = "CS-AUTH-1A2B3C"
	key2, miss := buildArtifactCacheKey(renamed)
	if miss != "" {
		t.Fatalf("renamed key miss = %q", miss)
	}
	if key1 == key2 {
		t.Fatal("artifact cache key must change when a finding's display id changes")
	}
}

func TestArtifactCacheRestoreDistinguishesEmptyCacheFromKeyMiss(t *testing.T) {
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", t.TempDir())

	empty := newArtifactBundleCache()
	if empty.Restore(&AgentState{}, "v2:deadbeef") {
		t.Fatal("empty cache should miss")
	}
	if reason := empty.Stats().MissReason; reason != "no_entries_loaded" {
		t.Fatalf("empty cache miss reason = %q, want no_entries_loaded", reason)
	}

	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "# report"
	state.AIFixSpec = "# fixspec"
	key, miss := buildArtifactCacheKey(state)
	if miss != "" {
		t.Fatalf("key miss = %q", miss)
	}
	warm := newArtifactBundleCache()
	warm.Store(state, key)
	warm.Save()

	populated := newArtifactBundleCache()
	if populated.Restore(&AgentState{}, "v2:other-key") {
		t.Fatal("unknown key should miss")
	}
	if reason := populated.Stats().MissReason; reason != "key_miss" {
		t.Fatalf("populated cache miss reason = %q, want key_miss", reason)
	}
	if populated.Stats().Key != "" {
		t.Fatalf("stats key is set by the orchestrator, not Restore: %q", populated.Stats().Key)
	}
}

func TestVerdictCacheNamespaceUsesResolvedLLMIdentity(t *testing.T) {
	t.Setenv("AITRIAGE_LLM_PROVIDER", "")
	t.Setenv("AITRIAGE_LLM_MODEL", "")
	t.Setenv("AITRIAGE_MODEL", "")

	base := defaultVerdictCacheKeyContext("")

	ctxA := base
	withVerdictCacheLLMIdentity(&AgentState{LLMProvider: "openai", LLMModel: "model-a"})(&ctxA)
	ctxB := base
	withVerdictCacheLLMIdentity(&AgentState{LLMProvider: "openai", LLMModel: "model-b"})(&ctxB)
	if ctxA.namespace() == ctxB.namespace() {
		t.Fatal("different resolved models must produce different verdict namespaces")
	}

	// State identity overrides env-derived values.
	t.Setenv("AITRIAGE_LLM_MODEL", "env-model")
	ctxEnv := defaultVerdictCacheKeyContext("")
	withVerdictCacheLLMIdentity(&AgentState{LLMModel: "state-model"})(&ctxEnv)
	if ctxEnv.Model != "state-model" {
		t.Fatalf("state identity must override env, got model %q", ctxEnv.Model)
	}

	// Empty state falls back to env-derived values.
	ctxFallback := defaultVerdictCacheKeyContext("")
	withVerdictCacheLLMIdentity(&AgentState{})(&ctxFallback)
	if ctxFallback.Model != "env-model" {
		t.Fatalf("empty state identity must keep env fallback, got model %q", ctxFallback.Model)
	}

	// DisableThinking is part of the namespace.
	ctxThinking := base
	withVerdictCacheLLMIdentity(&AgentState{LLMProvider: "openai", LLMModel: "model-a", LLMDisableThinking: true})(&ctxThinking)
	if ctxA.namespace() == ctxThinking.namespace() {
		t.Fatal("disable_thinking must change the verdict namespace")
	}
}

func TestArtifactCacheKeyReflectsResolvedLLMIdentity(t *testing.T) {
	t.Setenv("AITRIAGE_LLM_PROVIDER", "")
	t.Setenv("AITRIAGE_LLM_MODEL", "")
	t.Setenv("AITRIAGE_MODEL", "")

	stateA := artifactCacheTestState("True Positive")
	stateA.LLMProvider, stateA.LLMModel = "openai", "model-a"
	keyA, miss := buildArtifactCacheKey(stateA)
	if miss != "" {
		t.Fatalf("key A miss = %q", miss)
	}

	stateB := artifactCacheTestState("True Positive")
	stateB.LLMProvider, stateB.LLMModel = "openai", "model-b"
	keyB, miss := buildArtifactCacheKey(stateB)
	if miss != "" {
		t.Fatalf("key B miss = %q", miss)
	}
	if keyA == keyB {
		t.Fatal("artifact cache key must change with the resolved model identity")
	}
}

func TestArtifactCachePrunesOldestEntriesBeyondCap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", dir)

	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "# report"
	state.AIFixSpec = "# fixspec"

	cache := newArtifactBundleCache()
	for i := 0; i < maxArtifactBundleEntries+3; i++ {
		cache.Store(state, fmt.Sprintf("v2:test-key-%02d", i))
	}
	cache.Save()

	reloaded := newArtifactBundleCache()
	if got := reloaded.Stats().LoadedEntries; got != maxArtifactBundleEntries {
		t.Fatalf("loaded entries = %d, want pruned to %d", got, maxArtifactBundleEntries)
	}

	// Atomic write must not leave temp files behind.
	names, err := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if err != nil || len(names) != 0 {
		t.Fatalf("temp files left after save: %v (err=%v)", names, err)
	}
}

func TestArtifactCacheEnsuresFileOnInit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", dir)

	// The cache file must exist from the moment the cache is enabled: CI save
	// steps gate on it, and a run that dies mid-way (job timeout, provider
	// hang) must still be able to persist the co-located verdict cache.
	_ = newArtifactBundleCache()
	path := filepath.Join(dir, "artifact_bundle_cache.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not created on init: %v", err)
	}

	reloaded := newArtifactBundleCache()
	if stats := reloaded.Stats(); stats.CorruptCacheIgnored || stats.LoadedEntries != 0 {
		t.Fatalf("empty cache file reload stats = %+v, want clean empty load", stats)
	}

	// A sensitive-skipped store must not clobber the file with a bad state.
	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "token " + ("sk" + "-" + strings.Repeat("a", 24)) + " should not be cached"
	state.AIFixSpec = "# fixspec"
	key, miss := buildArtifactCacheKey(state)
	if miss != "" {
		t.Fatalf("key miss = %q", miss)
	}
	cache := newArtifactBundleCache()
	cache.Store(state, key)
	cache.Save()
	if stats := cache.Stats(); stats.Stores != 0 || stats.SkippedSensitive != 1 {
		t.Fatalf("sensitive store stats = %+v, want skipped store", stats)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file missing after skipped store: %v", err)
	}
}

func TestArtifactCacheCorruptCacheIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "artifact_bundle_cache.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}

	cache := newArtifactBundleCache()
	if !cache.Stats().CorruptCacheIgnored {
		t.Fatalf("corrupt cache should be ignored, stats=%+v", cache.Stats())
	}
}

func TestArtifactCacheSkipsSensitiveBundle(t *testing.T) {
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", t.TempDir())
	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "token " + ("sk" + "-" + strings.Repeat("a", 24)) + " should not be cached"
	state.AIFixSpec = "# fixspec"
	key, miss := buildArtifactCacheKey(state)
	if miss != "" {
		t.Fatalf("key miss = %q", miss)
	}

	cache := newArtifactBundleCache()
	cache.Store(state, key)
	if stats := cache.Stats(); stats.Stores != 0 || stats.SkippedSensitive != 1 {
		t.Fatalf("sensitive store stats = %+v, want skipped", stats)
	}
}

func TestArtifactCacheStoresSafePackageNameBundle(t *testing.T) {
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", t.TempDir())
	state := artifactCacheTestState("True Positive")
	state.ReportMarkdown = "Use flask-limiter or slowapi for rate limiting."
	state.AIFixSpec = "# fixspec"
	key, miss := buildArtifactCacheKey(state)
	if miss != "" {
		t.Fatalf("key miss = %q", miss)
	}

	cache := newArtifactBundleCache()
	cache.Store(state, key)
	cache.Save()
	if stats := cache.Stats(); stats.Stores != 1 || stats.SkippedSensitive != 0 || !stats.Saved {
		t.Fatalf("safe store stats = %+v, want saved store", stats)
	}
}

func TestRunArtifactCacheWarmThenExactHitSkipsSecondaryLLMStages(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", dir)
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", dir)
	pinConcurrency(t)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	warmLLM := newArtifactRunLLM(t)
	warmState := artifactRunState(project)
	if err := Run(context.Background(), warmState, warmLLM); err != nil {
		t.Fatalf("warm Run() error = %v", err)
	}
	for _, stage := range []string{"poc", "report", "fixspec"} {
		if warmLLM.calls[stage] == 0 {
			t.Fatalf("warm run did not call %s stage: calls=%v", stage, warmLLM.calls)
		}
	}
	if warmState.ArtifactCacheStats.Stores != 1 || !warmState.ArtifactCacheStats.Saved {
		t.Fatalf("warm artifact stats = %+v, want saved store", warmState.ArtifactCacheStats)
	}

	hitLLM := newArtifactRunLLM(t)
	hitState := artifactRunState(project)
	if err := Run(context.Background(), hitState, hitLLM); err != nil {
		t.Fatalf("hit Run() error = %v", err)
	}
	for _, stage := range []string{"poc", "report", "fixspec"} {
		if hitLLM.calls[stage] != 0 {
			t.Fatalf("artifact hit should skip %s LLM stage, calls=%v", stage, hitLLM.calls)
		}
	}
	if !hitState.ArtifactCacheStats.ExactHit || !hitState.ArtifactCacheStats.RestoredReport || !hitState.ArtifactCacheStats.RestoredFixSpec {
		t.Fatalf("hit artifact stats = %+v, want exact restored hit", hitState.ArtifactCacheStats)
	}
	// The restored artifacts must be byte-identical to what the warm run stored
	// (LLM narrative + deterministic canonical section), proving no drift.
	if hitState.ReportMarkdown != warmState.ReportMarkdown || hitState.AIFixSpec != warmState.AIFixSpec {
		t.Fatalf("hit artifacts not byte-identical to warm:\nreport hit=%q warm=%q", hitState.ReportMarkdown, warmState.ReportMarkdown)
	}
	if !strings.Contains(hitState.ReportMarkdown, "Canonical Finding Inventory") || !strings.Contains(hitState.ReportMarkdown, hitState.EnrichedFindings[0].VulnID) {
		t.Fatalf("restored report missing canonical section: %q", hitState.ReportMarkdown)
	}
}

func TestRunArtifactCacheStrictFallbackNotEligible(t *testing.T) {
	dir := t.TempDir()
	// The verdict cache is on: the second run serves R1 from it and asks
	// about R2 alone, which gets the same outcome as in the warm run.
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", t.TempDir())
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", dir)
	pinConcurrency(t)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	// A classifier whose verdict for one finding is rejected every time forces
	// an NR fallback, which is not cacheable — so the bundle must not be
	// stored (strict mode).
	warmState := fallbackRunState(project)
	if err := Run(context.Background(), warmState, newFallbackRunLLM(t)); err != nil {
		t.Fatalf("warm Run() error = %v", err)
	}
	if warmState.ArtifactCacheStats.UncachedVerdicts == 0 {
		t.Fatalf("expected uncached verdicts from NR fallback, got stats=%+v", warmState.ArtifactCacheStats)
	}
	if !warmState.ArtifactCacheStats.EligibilitySkipped || warmState.ArtifactCacheStats.Stores != 0 {
		t.Fatalf("strict mode should skip storing the bundle, stats=%+v", warmState.ArtifactCacheStats)
	}

	// A second run must NOT get an exact hit (nothing eligible was stored).
	hitLLM := newFallbackRunLLM(t)
	hitState := fallbackRunState(project)
	if err := Run(context.Background(), hitState, hitLLM); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if hitState.VerdictCacheStats.Hits == 0 {
		t.Fatalf("second run verdict cache = %+v, want R1 served from it", hitState.VerdictCacheStats)
	}
	if hitState.ArtifactCacheStats.ExactHit {
		t.Fatalf("second run must not exact-hit an ineligible bundle, stats=%+v", hitState.ArtifactCacheStats)
	}
}

func artifactCacheTestState(disposition string) *AgentState {
	finding := EnrichedFinding{ID: "R1", VulnID: "CS-MISC-001", Type: "core", Severity: "HIGH", File: "app.go", Line: 1, Message: "Issue"}
	fp := Fingerprint(finding)
	return &AgentState{
		EnrichedFindings: []EnrichedFinding{finding},
		FindingDispositions: []FindingDisposition{{
			FindingIndex: 0,
			FindingID:    "CS-MISC-001",
			Disposition:  disposition,
			Rationale:    "r",
			Confidence:   "high",
			Fingerprint:  fp,
		}},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnNever},
	}
}

func artifactRunState(project string) *AgentState {
	return &AgentState{
		ProjectPath: project,
		CoreFindings: []core.CheckResult{{
			ID:       "R1",
			Name:     "Issue",
			Status:   core.Absent,
			Evidence: "unsafe behavior",
			Severity: "HIGH",
			File:     "app.go",
			Line:     1,
		}},
		Policy: healthcheck.Policy{FailOn: healthcheck.FailOnNever},
	}
}

type artifactRunLLM struct {
	t     *testing.T
	calls map[string]int
}

func newArtifactRunLLM(t *testing.T) *artifactRunLLM {
	return &artifactRunLLM{t: t, calls: make(map[string]int)}
}

func (m *artifactRunLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	if len(messages) == 0 {
		m.t.Fatal("empty messages")
	}
	system := messages[0].Content
	switch {
	case strings.Contains(system, "Current Task: Threat Model & Finding Classification"):
		m.calls["threat_model"]++
		return `{"component_overview":"test","entry_points":[],"trust_boundaries":{"authentication":"n/a","authorization":"n/a","implicit_trust":"n/a"},"sensitive_data_paths":[],"privileged_actions":[],"priority_areas":[],"finding_dispositions":[{"finding_index":0,"disposition":"True Positive","rationale":"r"}]}`, llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	case strings.Contains(system, "Current Task: Finding Classification"):
		m.calls["classification"]++
		batch := parseClassificationPromptFindings(messages[1].Content)
		return classifyAll(batch, "True Positive"), llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	case strings.Contains(system, "Current Task: PoC Verification"):
		m.calls["poc"]++
		return pocResultsJSON(1), llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	case strings.Contains(system, "Current Task: Compile Security Report"):
		m.calls["report"]++
		return "# report\n", llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	case strings.Contains(system, "Generate AI IDE Fix Plan"):
		m.calls["fixspec"]++
		return "# fixspec\n", llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	default:
		m.t.Fatalf("unexpected LLM prompt: %s", system)
		return "", llm.Usage{}, nil
	}
}

// fallbackRunState has two findings for fallbackRunLLM: R1, which it
// classifies, and R2, which it never gives an accepted verdict.
func fallbackRunState(project string) *AgentState {
	state := artifactRunState(project)
	state.CoreFindings = append(state.CoreFindings, core.CheckResult{
		ID: "R2", Name: "Other issue", Status: core.Absent, Evidence: "other unsafe behavior", Severity: "HIGH", File: "app.go", Line: 1,
	})
	return state
}

// fallbackRunLLM behaves like artifactRunLLM but answers R1 with
// r1Disposition and R2 with r2Disposition. By default R2 gets a False
// Positive without evidence: its own verdict, rejected every time, which ends
// as an uncacheable NR fallback whether R2 is asked about with R1 or alone.
// An empty r2Disposition leaves R2 out of every reply, which leaves the triage
// incomplete.
type fallbackRunLLM struct {
	inner                        *artifactRunLLM
	r1Disposition, r2Disposition string
}

func newFallbackRunLLM(t *testing.T) *fallbackRunLLM {
	return &fallbackRunLLM{inner: newArtifactRunLLM(t), r1Disposition: "True Positive", r2Disposition: "False Positive"}
}

func (m *fallbackRunLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	if len(messages) > 0 && strings.Contains(messages[0].Content, "Current Task: Finding Classification") {
		m.inner.calls["classification"]++
		var entries []string
		for _, item := range parsePromptBatchFromUser(messages[1].Content) {
			disposition := m.r1Disposition
			if item.Finding.ID == "R2" {
				disposition = m.r2Disposition
			}
			if disposition == "" {
				continue
			}
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"finding_id":%q,"disposition":%q,"confidence":"high","rationale":"r"}`,
				item.FindingIndex, item.FindingID, disposition))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}, nil
	}
	return m.inner.Chat(ctx, messages)
}

func parseClassificationPromptFindings(user string) []classificationPromptFinding {
	i := strings.Index(user, "[")
	if i < 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(user[i:]))
	var findings []classificationPromptFinding
	_ = dec.Decode(&findings)
	return findings
}
