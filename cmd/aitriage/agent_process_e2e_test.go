package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	rt "github.com/dodobrands/aitriage/internal/runtime"
)

func TestE2E_DefaultAgentUsesFullContainerBundle(t *testing.T) {
	if testing.Short() || !dockerImageAvailable(t) {
		t.Skip("requires Docker and the resolved AITriage runtime image")
	}
	bin := buildBinary(t)
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "README.md"), "# clean fixture\n")

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		system := ""
		if len(request.Messages) > 0 {
			system = request.Messages[0].Content
		}
		content := "No actionable findings."
		switch {
		case strings.Contains(system, "Threat Model & Finding Classification"):
			content = `{"component_overview":"test fixture","priority_areas":[]}`
		case strings.Contains(system, "Finding Classification"):
			// Omissions are safely converted to Needs Manual Review after bounded
			// retries; this E2E tests transport/runtime, not model quality.
			content = `{"finding_dispositions":[]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-test", "object": "chat.completion", "created": time.Now().Unix(), "model": "test",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	llmHost := "host.docker.internal"
	if runtime.GOOS == "linux" {
		// Docker Engine does not provide Docker Desktop's host alias. The
		// launcher uses the default bridge, whose gateway reaches this fixture.
		gateway, err := exec.Command("docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
		if err != nil || net.ParseIP(strings.TrimSpace(string(gateway))) == nil {
			t.Fatalf("resolve Docker bridge gateway for the LLM fixture: %v (%q)", err, gateway)
		}
		llmHost = strings.TrimSpace(string(gateway))
	}
	cmd := exec.Command(bin, "agent", project, "--no-chat", "--fail-on", "never")
	cmd.Env = append(os.Environ(),
		"AITRIAGE_IMAGE="+rt.ResolveImage(Version),
		"AITRIAGE_LLM_PROVIDER=ollama",
		fmt.Sprintf("AITRIAGE_LLM_BASE_URL=http://%s:%d/v1/", llmHost, port),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("default container agent failed: %v\n%s", err, out)
	}
	containerName := fmt.Sprintf("aitriage-agent-%d-1", cmd.Process.Pid)
	if err := exec.Command("docker", "container", "inspect", containerName).Run(); err == nil {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		t.Fatalf("one-shot agent container %s was not removed", containerName)
	}

	entries, err := os.ReadDir(filepath.Join(project, "aitriage-reports"))
	if err != nil {
		t.Fatal(err)
	}
	var runDir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "run-") {
			runDir = filepath.Join(project, "aitriage-reports", entry.Name())
			break
		}
	}
	if runDir == "" {
		t.Fatalf("default agent did not create a run bundle: %v\n%s", entries, out)
	}
	for _, artifact := range []string{"manifest.json", "aitriage.sarif", "triage-findings.json", "summary.md", "report.md", "fixspec.md"} {
		if _, statErr := os.Stat(filepath.Join(runDir, artifact)); statErr != nil {
			t.Errorf("default agent artifact %s missing: %v", artifact, statErr)
		}
	}
	data, err := os.ReadFile(filepath.Join(runDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifestLite
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ScannerCoverage != "full" {
		t.Fatalf("agent scanner coverage = %q, want full: %s", manifest.ScannerCoverage, data)
	}
	statuses := map[string]string{}
	for _, scanner := range manifest.Scanners {
		statuses[scanner.Scanner] = scanner.Status
	}
	for _, scanner := range []string{"aitriage", "semgrep", "trivy_fs", "trivy_config", "gitleaks", "bandit"} {
		if statuses[scanner] != "completed" {
			t.Errorf("agent scanner %s = %q, want completed (all=%v)", scanner, statuses[scanner], statuses)
		}
	}
}
