package graph

import (
	"context"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
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

// defaultModelLLM is a stage stub whose requests name the provider's default
// model because none is configured.
type defaultModelLLM struct {
	*stageLLM
	provider, model string
}

func (c defaultModelLLM) RequestModel() (string, string) { return c.provider, c.model }

func (c defaultModelLLM) UsesDefaultModel() bool { return true }

// A run that relies on the OpenAI default, which AITriage 1.16 changes, is
// warned in the summary as well as on stderr. A run on a default that is not
// about to change gets no warning.
func TestRunWarnsInTheSummaryWhenItReliesOnTheOpenAIDefault(t *testing.T) {
	const warning = "No OpenAI model is set, so AITriage uses gpt-4o, whose snapshots OpenAI shuts down on 2027-01-14. AITriage 1.16 will default to gpt-6-luna; set llm.model to choose a model."
	for _, tc := range []struct {
		provider, model string
		warns           bool
	}{
		{provider: "openai", model: llm.DefaultOpenAIModel, warns: true},
		{provider: "anthropic", model: llm.DefaultAnthropicModel},
		{provider: "gemini", model: llm.DefaultGeminiModel},
	} {
		hermeticRun(t)
		state := degradedRunState(t, healthcheck.FailOnNever)
		if err := Run(context.Background(), state, defaultModelLLM{stageLLM: newStageLLM(t), provider: tc.provider, model: tc.model}); err != nil {
			t.Fatalf("%s: Run() error = %v", tc.provider, err)
		}
		if got := strings.Contains(state.SummaryMarkdown, "> **Warning:** "+warning); got != tc.warns {
			t.Fatalf("%s: summary carries the warning: %v, want %v\n%s", tc.provider, got, tc.warns, state.SummaryMarkdown)
		}
		if tc.warns && (len(state.DeprecationWarnings) != 1 || state.DeprecationWarnings[0] != warning) {
			t.Fatalf("%s: warnings = %q, want the OpenAI default warning once", tc.provider, state.DeprecationWarnings)
		}
		if !tc.warns && len(state.DeprecationWarnings) != 0 {
			t.Fatalf("%s: warnings = %q, want none", tc.provider, state.DeprecationWarnings)
		}
	}
}
