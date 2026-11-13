package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// --temperature is checked when the command line is parsed, and the
// containerised agent gets it with the other LLM settings.
func TestAgentTemperatureFlag(t *testing.T) {
	previous, previousPreaudit := agentTemperature, preauditTemperature
	t.Cleanup(func() { agentTemperature, preauditTemperature = previous, previousPreaudit })

	for _, cmd := range []*cobra.Command{agentCmd, preauditCmd} {
		flag := cmd.Flags().Lookup("temperature")
		if flag == nil {
			t.Fatalf("%s has no --temperature flag", cmd.Name())
		}
		if err := cmd.Flags().Set("temperature", "warm"); err == nil {
			t.Fatalf("%s --temperature accepted an invalid value", cmd.Name())
		}
		if err := cmd.Flags().Set("temperature", "0.3"); err != nil {
			t.Fatalf("%s --temperature 0.3: %v", cmd.Name(), err)
		}
	}

	args, err := agentContainerCommandArgs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(args, " "); !strings.Contains(joined, "--temperature 0.3") {
		t.Fatalf("inner agent args do not forward --temperature:\n%s", joined)
	}
	if err := agentTemperature.Set(""); err != nil {
		t.Fatal(err)
	}
	args, err = agentContainerCommandArgs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(args, " "); strings.Contains(joined, "--temperature") {
		t.Fatalf("an unset --temperature reached the inner agent:\n%s", joined)
	}
	if !slices.Contains(agentEnvAllowlist, "AITRIAGE_LLM_TEMPERATURE") {
		t.Fatal("AITRIAGE_LLM_TEMPERATURE is not forwarded into the agent container")
	}
}

// fakeChatAPI is an OpenAI-compatible chat API that records the temperature
// of every request. While refusing, it answers 400 to a request that carries
// one, as a model that takes no temperature does.
type fakeChatAPI struct {
	mu           sync.Mutex
	temperatures []string
	refusing     bool
}

func (f *fakeChatAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&body)
	raw, sent := body["temperature"]
	f.mu.Lock()
	if sent {
		f.temperatures = append(f.temperatures, string(raw))
	} else {
		f.temperatures = append(f.temperatures, "none")
	}
	refuse := f.refusing && sent
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if refuse {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"Unsupported parameter: 'temperature' is not supported with this model.","type":"invalid_request_error","param":"temperature","code":"unsupported_parameter"}}`)
		return
	}
	// The verdicts do not matter here, only what the requests carried.
	_, _ = io.WriteString(w, `{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"{\"finding_dispositions\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
}

func (f *fakeChatAPI) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := f.temperatures
	f.temperatures = nil
	return seen
}

// The temperature a native agent run sends comes from --temperature, else
// AITRIAGE_LLM_TEMPERATURE, else llm.temperature in .aitriage.yaml, else the
// default 0, and triage-findings.json records it. A model that refuses it
// gets the request again without it, and the record says so.
func TestAgentTemperatureReachesTheProvider(t *testing.T) {
	api := &fakeChatAPI{}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	for _, name := range []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
		"AITRIAGE_LLM_DISABLE_THINKING", "AITRIAGE_LLM_TIMEOUT", "AITRIAGE_GATING", "AITRIAGE_RUNTIME", "AITRIAGE_REPORTS_DIR",
		"AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR", "GITHUB_ACTIONS"} {
		t.Setenv(name, "")
	}
	// No external scanners: the scan only has to give the model a finding.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AITRIAGE_LLM_PROVIDER", "openai")
	t.Setenv("AITRIAGE_LLM_MODEL", "test-model")
	t.Setenv("AITRIAGE_LLM_BASE_URL", server.URL)
	t.Setenv("AITRIAGE_LLM_API_KEY", "test-key-not-real")

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte("result = eval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(project, ".aitriage.yaml")
	if err := os.WriteFile(configFile, []byte("llm:\n  temperature: 0.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	previousTemperature, previousRuntime, previousNoChat := agentTemperature, agentRuntime, agentNoChat
	t.Cleanup(func() {
		agentTemperature, agentRuntime, agentNoChat = previousTemperature, previousRuntime, previousNoChat
	})
	agentRuntime, agentNoChat = "native", true
	outputs := t.TempDir()
	setAgentOutputs(t, outputs)

	run := func(flag, env string) ([]string, string) {
		t.Helper()
		if err := agentTemperature.Set(flag); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AITRIAGE_LLM_TEMPERATURE", env)
		cmd := &cobra.Command{Use: "agent"}
		cmd.SetContext(context.Background())
		// The fake's empty verdicts leave the triage incomplete (exit 2); the
		// artifacts are written either way.
		_ = runAgent(cmd, []string{project})
		data, err := os.ReadFile(filepath.Join(outputs, "triage-findings.json"))
		if err != nil {
			t.Fatalf("triage-findings.json: %v", err)
		}
		var artifact struct {
			LLMUsage struct {
				Provider    string `json:"provider"`
				Model       string `json:"model"`
				Temperature string `json:"temperature"`
			} `json:"llm_usage"`
		}
		if err := json.Unmarshal(data, &artifact); err != nil {
			t.Fatal(err)
		}
		if artifact.LLMUsage.Provider != "openai" || artifact.LLMUsage.Model != "test-model" {
			t.Fatalf("llm_usage names %q %q, want openai test-model", artifact.LLMUsage.Provider, artifact.LLMUsage.Model)
		}
		if strings.Contains(string(data), server.URL) || strings.Contains(string(data), "test-key-not-real") {
			t.Fatal("triage-findings.json names the endpoint or the key")
		}
		return api.take(), artifact.LLMUsage.Temperature
	}
	expect := func(name string, sent []string, recorded string, wantRecorded string, want ...string) {
		t.Helper()
		t.Logf("%s: requests carried %v, recorded %q", name, sent, recorded)
		if len(sent) < len(want) {
			t.Fatalf("%s: requests carried %v, want at least %d", name, sent, len(want))
		}
		for i, got := range sent {
			wantHere := want[min(i, len(want)-1)]
			if got != wantHere {
				t.Fatalf("%s: request %d carried temperature %s, want %s (all: %v)", name, i, got, wantHere, sent)
			}
		}
		if recorded != wantRecorded {
			t.Fatalf("%s: llm_usage.temperature = %q, want %q", name, recorded, wantRecorded)
		}
	}

	sent, recorded := run("0.9", "0.7")
	expect("flag", sent, recorded, "0.9", "0.9")
	sent, recorded = run("", "0.7")
	expect("environment", sent, recorded, "0.7", "0.7")
	sent, recorded = run("", "")
	expect(".aitriage.yaml", sent, recorded, "0.5", "0.5")

	if err := os.Remove(configFile); err != nil {
		t.Fatal(err)
	}
	sent, recorded = run("", "")
	expect("default", sent, recorded, "0", "0")
	sent, recorded = run("default", "")
	expect("--temperature default", sent, recorded, "provider default", "none")

	api.mu.Lock()
	api.refusing = true
	api.mu.Unlock()
	sent, recorded = run("", "")
	expect("refused", sent, recorded, "provider default", "0", "none")
}
