package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// A native agent run with no model set sends its OpenAI requests to gpt-4o,
// records it, and warns in the summary, as on stderr, that AITriage 1.16
// changes that default.
func TestAgentWarnsWhenItReliesOnTheOpenAIDefault(t *testing.T) {
	var (
		mu     sync.Mutex
		models []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		models = append(models, body.Model)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"{\"finding_dispositions\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(server.Close)

	for _, name := range []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
		"AITRIAGE_LLM_MODEL", "AITRIAGE_LLM_TEMPERATURE", "AITRIAGE_LLM_DISABLE_THINKING", "AITRIAGE_LLM_TIMEOUT", "AITRIAGE_GATING",
		"AITRIAGE_RUNTIME", "AITRIAGE_REPORTS_DIR", "AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR", "GITHUB_ACTIONS"} {
		t.Setenv(name, "")
	}
	// No external scanners: the scan only has to give the model a finding.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AITRIAGE_LLM_PROVIDER", "openai")
	t.Setenv("AITRIAGE_LLM_BASE_URL", server.URL)
	t.Setenv("AITRIAGE_LLM_API_KEY", "test-key-not-real")

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte("result = eval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previousModel, previousRuntime, previousNoChat := agentModel, agentRuntime, agentNoChat
	t.Cleanup(func() { agentModel, agentRuntime, agentNoChat = previousModel, previousRuntime, previousNoChat })
	agentModel, agentRuntime, agentNoChat = "", "native", true
	outputs := t.TempDir()
	setAgentOutputs(t, outputs)

	cmd := &cobra.Command{Use: "agent"}
	cmd.SetContext(context.Background())
	// The fake's empty verdicts leave the triage incomplete (exit 2); the
	// artifacts are written either way.
	_ = runAgent(cmd, []string{project})

	mu.Lock()
	sent := append([]string(nil), models...)
	mu.Unlock()
	if len(sent) == 0 {
		t.Fatal("no request reached the provider")
	}
	for _, model := range sent {
		if model != "gpt-4o" {
			t.Fatalf("requests named %v, want gpt-4o", sent)
		}
	}
	summary, err := os.ReadFile(filepath.Join(outputs, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	const warning = "> **Warning:** No OpenAI model is set, so AITriage uses gpt-4o, whose snapshots OpenAI shuts down on 2027-01-14. AITriage 1.16 will default to gpt-6-luna; set llm.model to choose a model."
	if strings.Count(string(summary), warning) != 1 {
		t.Fatalf("summary does not carry the warning once:\n%s", summary)
	}
	data, err := os.ReadFile(filepath.Join(outputs, "triage-findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		LLMUsage struct {
			Model string `json:"model"`
		} `json:"llm_usage"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil || artifact.LLMUsage.Model != "gpt-4o" {
		t.Fatalf("llm_usage.model = %q (%v), want gpt-4o", artifact.LLMUsage.Model, err)
	}
}
