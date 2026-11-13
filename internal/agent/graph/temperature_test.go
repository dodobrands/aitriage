package graph

import (
	"encoding/json"
	"strings"
	"testing"
)

// reportingLLM is a client that knows the temperature its requests carry.
type reportingLLM struct {
	stageUsageMockLLM
	temperature string
}

func (c reportingLLM) EffectiveTemperature() string { return c.temperature }

func TestRecordLLMTemperature(t *testing.T) {
	state := &AgentState{}
	state.RecordLLMTemperature(reportingLLM{temperature: "0.4"})
	if state.LLMTemperature != "0.4" {
		t.Fatalf("recorded %q, want the client's 0.4", state.LLMTemperature)
	}
	// A client that sets no temperature, such as a host agent, leaves the
	// provider default.
	state.RecordLLMTemperature(stageUsageMockLLM{})
	if state.LLMTemperature != "provider default" {
		t.Fatalf("recorded %q, want provider default", state.LLMTemperature)
	}
	var none *AgentState
	none.RecordLLMTemperature(reportingLLM{temperature: "0"}) // must not panic
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

// triage-findings.json says which temperature the requests carried.
func TestTriageArtifactRecordsTheTemperature(t *testing.T) {
	for _, temperature := range []string{"0", "provider default"} {
		artifact, err := BuildTriageFindingsArtifact(&AgentState{LLMTemperature: temperature})
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			LLMUsage struct {
				Temperature *string `json:"temperature"`
			} `json:"llm_usage"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.LLMUsage.Temperature == nil || *decoded.LLMUsage.Temperature != temperature {
			t.Fatalf("llm_usage.temperature = %v, want %q", decoded.LLMUsage.Temperature, temperature)
		}
	}
	artifact, err := BuildTriageFindingsArtifact(&AgentState{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.LLMUsage.Temperature != "" {
		t.Fatalf("an unrecorded temperature became %q", artifact.LLMUsage.Temperature)
	}
}
