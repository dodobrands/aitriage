package graph

import (
	"context"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// With no model configured, the verdict cache keys on the model the requests
// name, which the client reports before the run: verdicts of one default
// model are never served to a run on another default, and a run on the same
// default reuses them.
func TestVerdictCacheKeysOnTheDefaultModelTheRequestsName(t *testing.T) {
	hermeticRun(t)
	t.Setenv("AITRIAGE_CACHE_DIR", t.TempDir())
	for _, name := range []string{"AITRIAGE_LLM_PROVIDER", "AITRIAGE_LLM_MODEL", "AITRIAGE_MODEL"} {
		t.Setenv(name, "")
	}
	findings := makeFindings(3)
	run := func(defaultModel string) VerdictCacheStats {
		t.Helper()
		state := &AgentState{LLMProvider: "openai"} // no model configured
		state.RecordLLMSettings(reportingLLM{provider: "openai", model: defaultModel, temperature: "0"})
		var usage llm.Usage
		_, _, _, stats, err := ClassifyFindingsWithAudit(context.Background(), "", "p", "", findings, &fakeLLM{t: t}, &usage, 40, withVerdictCacheLLMIdentity(state))
		if err != nil {
			t.Fatal(err)
		}
		return stats
	}

	if stats := run("gpt-4o"); stats.Stores != 3 {
		t.Fatalf("first run stats = %+v, want 3 verdicts stored", stats)
	}
	if stats := run("gpt-6-luna"); stats.Hits != 0 || stats.Stores != 3 {
		t.Fatalf("a run on another default model: stats = %+v, want no verdict reused", stats)
	}
	if stats := run("gpt-4o"); stats.Hits != 3 {
		t.Fatalf("a run on the same default model: stats = %+v, want its 3 verdicts reused", stats)
	}

	// Two defaults are two namespaces; a model set in the configuration keys
	// as it did before the client reported it.
	namespace := func(state *AgentState) string {
		ctx := defaultVerdictCacheKeyContext("")
		withVerdictCacheLLMIdentity(state)(&ctx)
		return ctx.namespace()
	}
	unset := func(model string) *AgentState {
		return &AgentState{LLMProvider: "openai", LLMRequestProvider: "openai", LLMRequestModel: model, LLMTemperature: "0"}
	}
	if namespace(unset("gpt-4o")) == namespace(unset("gpt-6-luna")) {
		t.Fatal("two default models share a verdict namespace")
	}
	configured := &AgentState{LLMProvider: "openai", LLMModel: "gpt-4o", LLMTemperature: "0"}
	reported := &AgentState{LLMProvider: "openai", LLMModel: "gpt-4o", LLMRequestProvider: "openai", LLMRequestModel: "gpt-4o", LLMTemperature: "0"}
	if namespace(configured) != namespace(reported) {
		t.Fatal("a configured model changed its namespace once the client reported it")
	}
}
