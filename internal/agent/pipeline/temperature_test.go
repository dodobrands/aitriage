package pipeline

import (
	"context"
	"testing"
)

// temperatureLLM answers like recordingLLM and reports the temperature its
// requests carry. With dropAfterFirst it reports the provider default once it
// has served a request, as a client does after an endpoint refused the
// temperature.
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

// The run records the temperature the client sends, and what the requests
// ended up carrying when the client dropped it mid-run.
func TestRunStateRecordsTheClientTemperature(t *testing.T) {
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
			state := BuildState(Options{ProjectPath: project}, rich)
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
			if artifact.LLMUsage.Temperature != tc.want {
				t.Fatalf("llm_usage.temperature = %q, want %q", artifact.LLMUsage.Temperature, tc.want)
			}
		})
	}

	// A client that sets no temperature leaves the provider default.
	project, rich := decisionsFixture(t)
	state := BuildState(Options{ProjectPath: project}, rich)
	if _, err := RunState(context.Background(), state, &recordingLLM{}); err != nil {
		t.Fatal(err)
	}
	if state.LLMTemperature != "provider default" {
		t.Fatalf("state temperature = %q, want provider default", state.LLMTemperature)
	}
}
