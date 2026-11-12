package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dockerImageAvailable runs container E2E only against an explicitly selected
// image. This prevents a stale locally cached release tag from making ordinary
// `go test ./...` exercise code from a different revision.
func dockerImageAvailable(t *testing.T) bool {
	t.Helper()
	image := strings.TrimSpace(os.Getenv("AITRIAGE_IMAGE"))
	if image == "" {
		return false
	}
	if exec.Command("docker", "info").Run() != nil {
		return false
	}
	return exec.Command("docker", "image", "inspect", image).Run() == nil
}

// TestE2E_ContainerRunFullScannerBundle is the definitive fix for the reported
// bug: over the container runtime, aitriage_run_start actually runs the full
// scanner bundle (semgrep/trivy/gitleaks/bandit) — none is silently "missing" —
// and records a scanner execution manifest in the run bundle on the host.
func TestE2E_ContainerRunFullScannerBundle(t *testing.T) {
	if testing.Short() || !dockerImageAvailable(t) {
		t.Skip("requires Docker and the resolved AITriage runtime image")
	}
	bin := buildBinary(t)

	// Minimal fixture that gives each scanner something to look at.
	proj := t.TempDir()
	writeFile(t, filepath.Join(proj, "app.py"),
		"import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n\nAWS_KEY = \"AKIA"+"Z7Q4XWVB3NMK2PLT\"\n")
	writeFile(t, filepath.Join(proj, "requirements.txt"), "flask==0.5\n")
	writeFile(t, filepath.Join(proj, ".env"), "DATABASE_URL=postgres://admin:S3cretDbPass@db:5432/app\n")
	writeFile(t, filepath.Join(proj, "xss_unsafe.py"), `from fastapi import FastAPI
from fastapi.responses import HTMLResponse
app = FastAPI()
@app.get("/hello")
def hello(name: str):
    return HTMLResponse(f"<h1>{name}</h1>")
`)
	writeFile(t, filepath.Join(proj, "xss_safe.py"), `import html
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
app = FastAPI()
@app.get("/hello")
def hello(name: str):
    return HTMLResponse(f"<h1>{html.escape(name)}</h1>")
`)
	// External scanners inspect the whole tree, but test-only assertions and
	// fixture credentials are filtered before AI triage. This prevents a normal
	// remediation test suite from exploding into dozens of false positives.
	writeFile(t, filepath.Join(proj, "tests", "test_security.py"),
		"def test_status():\n    assert 200 == 200\n    dummy_token = 'test-only-token'\n    assert dummy_token\n")
	// Generated artifacts may contain code snippets, PoCs and secret evidence.
	// None of the six scanners may read them back as project source.
	trap := filepath.Join(proj, "aitriage-reports", "selfscan-trap")
	if err := os.MkdirAll(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(trap, "selfscan_trap.py"),
		"import subprocess\nsubprocess.call(input(), shell=True)\nslack_token = \"xoxb-"+
			"123456789012-123456789012-abcdefghijklmnopqrstuvwx\"\n")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	serverCmd := exec.CommandContext(ctx, bin, "serve", "--runtime", "container", "--profile", "safe", "--scan-root", proj)
	transport := &mcp.CommandTransport{Command: serverCmd}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to container MCP: %v", err)
	}
	defer func() {
		_ = cs.Close()
		time.Sleep(300 * time.Millisecond)
		if serverCmd.Process != nil {
			name := fmt.Sprintf("aitriage-mcp-%d-1", serverCmd.Process.Pid)
			if inspectErr := exec.Command("docker", "container", "inspect", name).Run(); inspectErr == nil {
				_ = exec.Command("docker", "rm", "-f", name).Run()
				t.Errorf("MCP container %s was orphaned after stdio close", name)
			}
		}
	}()

	// run_start triggers the full scan inside the container. It may return a
	// pending request (scanners OK) or a fail-closed error (a scanner failed);
	// either way the scanner manifest is written to the bundle before triage.
	_, _ = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "aitriage_run_start",
		Arguments: map[string]any{"host_client": "codex"},
	})

	// Locate the single run bundle on the host and read its manifest.
	reportsDir := filepath.Join(proj, "aitriage-reports")
	manifest := findRunManifest(t, reportsDir)

	if manifest.ScannerCoverage != "full" {
		t.Fatalf("scanner coverage = %q, want full", manifest.ScannerCoverage)
	}
	// Every logical scanner execution must complete. In particular, one Trivy
	// mode must not hide a failure in the other.
	byScanner := map[string]string{}
	for _, s := range manifest.Scanners {
		byScanner[s.Scanner] = s.Status
	}
	if len(byScanner) == 0 {
		t.Fatalf("no scanner execution manifest recorded: %+v", manifest)
	}
	for _, must := range []string{"aitriage", "semgrep", "trivy_fs", "trivy_config", "gitleaks", "bandit"} {
		if byScanner[must] != "completed" {
			t.Errorf("scanner %q status = %q, want completed (container bundle)", must, byScanner[must])
		}
	}
	for name, status := range byScanner {
		if status == "missing" {
			t.Errorf("scanner %q is MISSING in the container — the bundle is incomplete", name)
		}
	}
	assertGeneratedBundleDoesNotReference(t, reportsDir, "selfscan_trap.py")
	assertGeneratedScanDoesNotReference(t, reportsDir, "test_security.py")
	assertGeneratedScanReferences(t, reportsDir, "FAST-XSS")
	assertGeneratedScanReferences(t, reportsDir, "xss_unsafe.py")
	assertGeneratedScanDoesNotReference(t, reportsDir, "xss_safe.py")
	t.Logf("container scanner coverage=%q manifest=%v", manifest.ScannerCoverage, byScanner)
}

func assertGeneratedScanReferences(t *testing.T, reportsDir, marker string) {
	t.Helper()
	foundScan := false
	foundMarker := false
	err := filepath.WalkDir(reportsDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "scan.json" {
			return nil
		}
		foundScan = true
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), marker) {
			foundMarker = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !foundScan {
		t.Fatal("no scan.json artifact found")
	}
	if !foundMarker {
		t.Fatalf("scan.json does not reference expected marker %q", marker)
	}
}

func assertGeneratedScanDoesNotReference(t *testing.T, reportsDir, marker string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(reportsDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "scan.json" {
			return nil
		}
		found = true
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), marker) {
			t.Errorf("scan artifact %s references test-only finding %q", path, marker)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no scan.json artifact found")
	}
}

func assertGeneratedBundleDoesNotReference(t *testing.T, reportsDir, marker string) {
	t.Helper()
	err := filepath.WalkDir(reportsDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "selfscan-trap" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), marker) {
			t.Errorf("generated artifact %s references %q: scanner self-scan regression", path, marker)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type manifestLite struct {
	ScannerCoverage string `json:"scanner_coverage"`
	Scanners        []struct {
		Scanner string `json:"scanner"`
		Status  string `json:"status"`
		Version string `json:"version"`
	} `json:"scanners"`
}

func findRunManifest(t *testing.T, reportsDir string) manifestLite {
	t.Helper()
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		t.Fatalf("reports dir not created on host: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(reportsDir, e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var m manifestLite
		if json.Unmarshal(b, &m) == nil && len(m.Scanners) > 0 {
			return m
		}
	}
	t.Fatalf("no run manifest with scanners found under %s", reportsDir)
	return manifestLite{}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
