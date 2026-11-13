package llm

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const openAIDefaultWarningText = "No OpenAI model is set, so AITriage uses gpt-4o, whose snapshots OpenAI shuts down on 2027-01-14. AITriage 1.16 will default to gpt-6-luna; set llm.model to choose a model."

// With no model set, OpenAI requests name gpt-4o, which takes the AITriage
// temperature. A run that relies on it is told which model it uses and, as
// the deprecation policy asks before a default changes, that AITriage 1.16
// changes it. Building the client prints nothing: the run prints the notices.
func TestOpenAIDefaultIsGPT4oUntilTheWarnedChange(t *testing.T) {
	f := answering(t, openAIReply)
	var log bytes.Buffer
	c := NewRetryClient(openAICompatible(t, Config{Provider: "openai"}, f, &log), 3)
	if err := chatOnce(t, c); err != nil {
		t.Fatal(err)
	}
	if model, _ := f.field(0, "model"); string(model) != `"gpt-4o"` {
		t.Fatalf("model = %s, want gpt-4o", model)
	}
	if got := f.seen(); !sameTemperatures(got, "0") {
		t.Fatalf("requests sent %v, want temperature 0", got)
	}
	if log.Len() != 0 {
		t.Fatalf("building the client printed %q, want nothing", log.String())
	}

	info, warning := DefaultModelNotices(c)
	if info != "No model set; using gpt-4o, the default for openai" {
		t.Fatalf("info = %q", info)
	}
	if warning != openAIDefaultWarningText {
		t.Fatalf("warning = %q, want %q", warning, openAIDefaultWarningText)
	}
	var out bytes.Buffer
	if got := PrintDefaultModelNotices(&out, c); got != openAIDefaultWarningText {
		t.Fatalf("PrintDefaultModelNotices returned %q, want the warning", got)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], info) || !strings.HasSuffix(lines[1], openAIDefaultWarningText) {
		t.Fatalf("printed %q, want the info line and the warning", out.String())
	}
}

// A run that relies on any provider default is told which model judged its
// findings; only the OpenAI default is about to change. A configured model,
// even one that equals a default, and a client that does not know its model,
// such as a host agent, print nothing.
func TestDefaultModelNotices(t *testing.T) {
	f := answering(t, openAIReply)
	for _, tc := range []struct {
		name   string
		client Client
		info   string
		warns  bool
	}{
		{name: "openai default", client: openAICompatible(t, Config{Provider: "openai"}, f, io.Discard), info: "No model set; using gpt-4o, the default for openai", warns: true},
		{name: "gemini default", client: openAICompatible(t, Config{Provider: "gemini"}, f, io.Discard), info: "No model set; using gemini-3.5-flash-lite, the default for gemini"},
		{name: "anthropic default", client: claude(Config{}, f, io.Discard), info: "No model set; using claude-sonnet-5-5, the default for anthropic"},
		{name: "openai model set to the default", client: openAICompatible(t, Config{Provider: "openai", Model: "gpt-4o"}, f, io.Discard)},
		{name: "openai model set", client: openAICompatible(t, Config{Provider: "openai", Model: "gpt-6-luna"}, f, io.Discard)},
		{name: "gemini model set", client: openAICompatible(t, Config{Provider: "gemini", Model: "gemini-2.5-flash"}, f, io.Discard)},
		{name: "anthropic model set", client: claude(Config{Model: "claude-opus-5-5"}, f, io.Discard)},
		{name: "ollama model set", client: openAICompatible(t, Config{Provider: "ollama", Model: "llama3.1"}, f, io.Discard)},
		{name: "host agent", client: &mockClient{}},
	} {
		for _, client := range []Client{tc.client, NewRetryClient(tc.client, 3)} {
			info, warning := DefaultModelNotices(client)
			if info != tc.info || (warning != "") != tc.warns {
				t.Errorf("%s (%T): info %q, warning %q; want info %q, warning %v", tc.name, client, info, warning, tc.info, tc.warns)
			}
			var out bytes.Buffer
			PrintDefaultModelNotices(&out, client)
			wantLines := 0
			if tc.info != "" {
				wantLines = 1
			}
			if tc.warns {
				wantLines = 2
			}
			if lines := strings.Count(out.String(), "\n"); lines != wantLines {
				t.Errorf("%s (%T): printed %q, want %d line(s)", tc.name, client, out.String(), wantLines)
			}
		}
	}
}

// Groq and Ollama serve models of their own. A configuration that names none
// stops when the client is built, with the settings that name a model,
// instead of sending the OpenAI default to a server that does not have it.
// Groq and Ollama without a model keep working as in earlier releases (a
// gateway may choose the model itself), and the run warns to set one.
func TestGroqAndOllamaWithoutAModelWarn(t *testing.T) {
	for _, provider := range []string{"groq", "ollama"} {
		c, err := NewClient(Config{Provider: provider, APIKey: "test-key-not-real", BaseURL: "http://127.0.0.1:1/v1"})
		if err != nil {
			t.Fatalf("%s without a model: %v", provider, err)
		}
		if _, model := RequestModel(c); model != DefaultOpenAIModel {
			t.Errorf("%s without a model requests %q, want %q as before", provider, model, DefaultOpenAIModel)
		}
		_, warning := DefaultModelNotices(c)
		for _, want := range []string{provider, DefaultOpenAIModel, "llm.model", "--model"} {
			if !strings.Contains(warning, want) {
				t.Errorf("%s: warning %q does not name %s", provider, warning, want)
			}
		}
		configured, err := NewClient(Config{Provider: provider, Model: "llama-3.3-70b-versatile", APIKey: "test-key-not-real", BaseURL: "http://127.0.0.1:1/v1"})
		if err != nil {
			t.Fatalf("%s with a model: %v", provider, err)
		}
		if info, warning := DefaultModelNotices(configured); info != "" || warning != "" {
			t.Errorf("%s with a model printed %q / %q, want nothing", provider, info, warning)
		}
	}
	// OpenAI has a default model.
	if _, err := NewClient(Config{Provider: "openai", APIKey: "test-key-not-real"}); err != nil {
		t.Fatalf("openai without a model: %v", err)
	}
}
