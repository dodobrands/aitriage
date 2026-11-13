package pipeline

import (
	"context"
	"testing"
)

// temperatureLLM answers like recordingLLM and reports the model and the
// temperature its requests carry. With dropAfterFirst it reports the provider
// default once it has served a request, as a client does after an endpoint
// refused the temperature.
type temperatureLLM struct {
	recordingLLM
	temperature    string
	dropAfterFirst bool
}

func (c *temperatureLLM) EffectiveTemperature() string {
	if c.dropAfterFirst && len(c.modelPrompts()) > 0 {
		return "provider default"
	}
	return c.temperature
}

func (c *temperatureLLM) RequestModel() (string, string) { return "openai", "gpt-4o" }

// The run records the model and temperature the client sends, and what the
// requests ended up carrying when the client dropped the temperature mid-run.
func TestRunStateRecordsTheClientModelAndTemperature(t *testing.T) {
	t.Setenv("AITRIAGE_CONCURRENCY", "1")
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	for _, tc := range []struct {
		name   string
		client *temperatureLLM
		want   string
	}{
		{name: "sent", client: &temperatureLLM{temperature: "0.25"}, want: "0.25"},
		{name: "dropped mid-run", client: &temperatureLLM{temperature: "0", dropAfterFirst: true}, want: "provider default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project, rich := decisionsFixture(t)
			state := BuildState(Options{ProjectPath: project, LLM: LLMIdentity{Provider: "openai"}}, rich)
			res, err := RunState(context.Background(), state, tc.client)
			if err != nil {
				t.Fatalf("RunState() error = %v", err)
			}
			if state.LLMTemperature != tc.want {
				t.Fatalf("state temperature = %q, want %q", state.LLMTemperature, tc.want)
			}
			artifact, err := res.Artifact()
			if err != nil {
				t.Fatal(err)
			}
			if u := artifact.LLMUsage; u.Temperature != tc.want || u.Provider != "openai" || u.Model != "gpt-4o" {
				t.Fatalf("llm_usage = %+v, want openai, gpt-4o, temperature %q", u, tc.want)
			}
			if state.LLMModel != "" {
				t.Fatalf("the cache-key model changed to %q", state.LLMModel)
			}
		})
	}

	// A client that sets no temperature and does not know its model, such as
	// a host agent, leaves the provider default and the configured identity.
	project, rich := decisionsFixture(t)
	state := BuildState(Options{ProjectPath: project, LLM: LLMIdentity{Provider: "anthropic", Model: "configured-model"}}, rich)
	res, err := RunState(context.Background(), state, &recordingLLM{})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := res.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	if u := artifact.LLMUsage; u.Temperature != "provider default" || u.Provider != "anthropic" || u.Model != "configured-model" {
		t.Fatalf("llm_usage = %+v, want the configured identity and provider default", u)
	}
}
