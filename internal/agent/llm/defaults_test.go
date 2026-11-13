package llm

import (
	"strings"
	"testing"
)

// Groq and Ollama serve models of their own. A configuration that names none
// stops when the client is built, with the settings that name a model,
// instead of sending the OpenAI default to a server that does not have it.
func TestGroqAndOllamaNeedAModel(t *testing.T) {
	for _, provider := range []string{"groq", "ollama"} {
		for _, model := range []string{"", "  "} {
			c, err := NewClient(Config{Provider: provider, Model: model, APIKey: "test-key-not-real", BaseURL: "http://127.0.0.1:1/v1"})
			if err == nil {
				t.Fatalf("%s with model %q built a client that names %q", provider, model, func() string { _, m := RequestModel(c); return m }())
			}
			for _, want := range []string{provider, "--model", "llm.model"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: error %q does not name %s", provider, err, want)
				}
			}
		}
		if _, err := NewClient(Config{Provider: provider, Model: "llama-3.3-70b-versatile", APIKey: "test-key-not-real", BaseURL: "http://127.0.0.1:1/v1"}); err != nil {
			t.Fatalf("%s with a model: %v", provider, err)
		}
	}
	// OpenAI has a default model.
	if _, err := NewClient(Config{Provider: "openai", APIKey: "test-key-not-real"}); err != nil {
		t.Fatalf("openai without a model: %v", err)
	}
}
