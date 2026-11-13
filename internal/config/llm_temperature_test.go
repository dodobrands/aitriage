package config

import "testing"

// llm.temperature comes from .aitriage.yaml, AITRIAGE_LLM_TEMPERATURE wins
// over it, and nothing configured leaves it empty for the client's default.
// (A --temperature flag wins over both; the agent command applies it.)
func TestLoadConfigLLMTemperature(t *testing.T) {
	t.Setenv("AITRIAGE_LLM_TEMPERATURE", "")
	if got := LoadConfig(t.TempDir()).LLM.Temperature; got != "" {
		t.Fatalf("temperature with nothing configured = %q, want empty", got)
	}

	dir := t.TempDir()
	writeConfig(t, dir, ".aitriage.yaml", "llm:\n  provider: openai\n  temperature: 0.5\n")
	if got := LoadConfig(dir).LLM.Temperature; got != "0.5" {
		t.Fatalf("temperature from .aitriage.yaml = %q, want 0.5", got)
	}

	t.Setenv("AITRIAGE_LLM_TEMPERATURE", " 0.7 ")
	if got := LoadConfig(dir).LLM.Temperature; got != "0.7" {
		t.Fatalf("AITRIAGE_LLM_TEMPERATURE over .aitriage.yaml = %q, want 0.7", got)
	}

	t.Setenv("AITRIAGE_LLM_TEMPERATURE", "")
	other := t.TempDir()
	writeConfig(t, other, ".aitriage.yaml", "llm:\n  temperature: default\n")
	if got := LoadConfig(other).LLM.Temperature; got != "default" {
		t.Fatalf("temperature: default = %q, want default", got)
	}
}
