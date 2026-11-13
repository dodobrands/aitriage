package graph

import (
	"encoding/json"
	"strings"
	"testing"
)

// reportingLLM is a client that knows the model and temperature its requests
// carry.
type reportingLLM struct {
	stageUsageMockLLM
	provider, model, temperature string
}

func (c reportingLLM) EffectiveTemperature() string { return c.temperature }

func (c reportingLLM) RequestModel() (string, string) { return c.provider, c.model }

func TestRecordLLMSettings(t *testing.T) {
	state := &AgentState{LLMProvider: "gemini"}
	state.RecordLLMSettings(reportingLLM{provider: "gemini", model: "gemini-2.5-flash", temperature: "0.4"})
	if state.LLMTemperature != "0.4" || state.LLMRequestProvider != "gemini" || state.LLMRequestModel != "gemini-2.5-flash" {
		t.Fatalf("recorded %q %q %q, want the client's gemini, gemini-2.5-flash, 0.4", state.LLMRequestProvider, state.LLMRequestModel, state.LLMTemperature)
	}
	if state.LLMProvider != "gemini" || state.LLMModel != "" {
		t.Fatalf("the configured identity changed to %q %q", state.LLMProvider, state.LLMModel)
	}
	// A client that sets no temperature and does not know its model, such as
	// a host agent, leaves the provider default and the configured identity.
	host := &AgentState{}
	host.RecordLLMSettings(stageUsageMockLLM{})
	if host.LLMTemperature != "provider default" || host.LLMRequestProvider != "" || host.LLMRequestModel != "" {
		t.Fatalf("recorded %q %q %q, want provider default and no model", host.LLMRequestProvider, host.LLMRequestModel, host.LLMTemperature)
	}
	var none *AgentState
	none.RecordLLMSettings(reportingLLM{temperature: "0"}) // must not panic
}

// Verdicts sampled at one temperature are not served to a run at another.
func TestVerdictCacheNamespaceFollowsTheTemperature(t *testing.T) {
	namespace := func(temperature string) string {
		ctx := defaultVerdictCacheKeyContext("")
		withVerdictCacheLLMIdentity(&AgentState{LLMProvider: "openai", LLMModel: "model-a", LLMTemperature: temperature})(&ctx)
		return ctx.namespace()
	}
	seen := map[string]string{}
	for _, temperature := range []string{"", "0", "0.7", "provider default"} {
		ns := namespace(temperature)
		if other, dup := seen[ns]; dup {
			t.Fatalf("temperature %q and %q share the namespace %s", temperature, other, ns)
		}
		seen[ns] = temperature
	}
	if namespace("0") != namespace(" 0 ") {
		t.Fatal("surrounding spaces changed the namespace")
	}

	// A caller that records no temperature keeps the key it had before the
	// field existed.
	ctx := defaultVerdictCacheKeyContext("")
	withVerdictCacheLLMIdentity(&AgentState{LLMProvider: "openai", LLMModel: "model-a"})(&ctx)
	data, err := json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "temperature") {
		t.Fatalf("key context without a temperature names one: %s", data)
	}

	zero, _ := buildArtifactCacheKey(&AgentState{LLMTemperature: "0"})
	providerDefault, _ := buildArtifactCacheKey(&AgentState{LLMTemperature: "provider default"})
	if zero == "" || zero == providerDefault {
		t.Fatalf("artifact cache keys %q and %q, want them to differ by temperature", zero, providerDefault)
	}
}

// triage-findings.json says which provider, model and temperature served the
// requests, and never names the endpoint.
func TestTriageArtifactRecordsTheModelAndTemperature(t *testing.T) {
	const endpoint = "https://llm.example.test/v1"
	for _, tc := range []struct {
		name                         string
		state                        AgentState
		provider, model, temperature string
	}{
		{
			name:     "what the client reported",
			state:    AgentState{LLMProvider: "openai", LLMBaseURL: endpoint, LLMRequestProvider: "openai", LLMRequestModel: "gpt-4o", LLMTemperature: "0"},
			provider: "openai", model: "gpt-4o", temperature: "0",
		},
		{
			name:     "the configured identity when the client does not know its model",
			state:    AgentState{LLMProvider: "anthropic", LLMModel: "configured-model", LLMBaseURL: endpoint, LLMTemperature: "provider default"},
			provider: "anthropic", model: "configured-model", temperature: "provider default",
		},
	} {
		artifact, err := BuildTriageFindingsArtifact(&tc.state)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			LLMUsage map[string]json.RawMessage `json:"llm_usage"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		for field, want := range map[string]string{"provider": tc.provider, "model": tc.model, "temperature": tc.temperature} {
			var got string
			if err := json.Unmarshal(decoded.LLMUsage[field], &got); err != nil || got != want {
				t.Errorf("%s: llm_usage.%s = %s, want %q", tc.name, field, decoded.LLMUsage[field], want)
			}
		}
		if strings.Contains(string(data), "llm.example.test") {
			t.Errorf("%s: the artifact names the endpoint", tc.name)
		}
	}
	artifact, err := BuildTriageFindingsArtifact(&AgentState{})
	if err != nil {
		t.Fatal(err)
	}
	if u := artifact.LLMUsage; u.Temperature != "" || u.Provider != "" || u.Model != "" {
		t.Fatalf("an unrecorded run reports %+v", u)
	}
}
