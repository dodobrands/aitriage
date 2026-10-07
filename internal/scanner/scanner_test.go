package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
)

func TestScanReturnsReport(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dummy file that might trigger a finding, e.g., a hardcoded secret pattern
	err := os.WriteFile(tmpDir+"/main.go", []byte("package main\n\nfunc main() {\n\tsecret := \"AKIAIOSFODNN7EXAMPLE\"\n}\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create dummy file: %v", err)
	}

	report, err := scanner.Scan(context.Background(), tmpDir, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if report.TotalFiles == 0 {
		t.Error("Expected TotalFiles > 0")
	}
	if len(report.Results) == 0 {
		t.Error("Expected findings in the dummy project")
	}
}

func TestScanExcludesTestMockFixtureAndSpecFiles(t *testing.T) {
	tmpDir := t.TempDir()
	testOnly := map[string]string{
		"main_test.go":       "package main\nvar token = \"AKIAIOSFODNN7EXAMPLE\"\n",
		"tests/test_auth.py": "api_key = 'sk-proj-123456789012345678901234567890'\n",
		"fixtures/leaked.ts": "const token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'\n",
		"src/auth.spec.js": "const secret = 'xoxb-" +
			"123456789012-123456789012-abcdefghijklmnopqrstuvwx'\n",
	}
	for name, content := range testOnly {
		path := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "contest.go"), []byte("package main\nvar safe = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := scanner.Scan(context.Background(), tmpDir, scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Results {
		if finding.File != "" {
			t.Fatalf("test-like source produced finding %s in %s", finding.ID, finding.File)
		}
	}
}

func TestScanProductionSubstringNamesRemainInScope(t *testing.T) {
	tmpDir := t.TempDir()
	for _, name := range []string{"contest.go", "latest.py"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("api_key = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	report, err := scanner.Scan(context.Background(), tmpDir, scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, finding := range report.Results {
		found[filepath.Base(finding.File)] = true
	}
	for _, name := range []string{"contest.go", "latest.py"} {
		if !found[name] {
			t.Fatalf("production file %s was incorrectly excluded", name)
		}
	}
}

func TestScanAppliesHealthCheckPolicyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(tmpDir+"/main.go", []byte("package main\n\nfunc main() {\n\tsecret := \"AKIAIOSFODNN7EXAMPLE\"\n}\n"), 0644); err != nil {
		t.Fatalf("Failed to create dummy file: %v", err)
	}
	if err := os.WriteFile(tmpDir+"/.aitriage.yaml", []byte(`
health_check:
  profile: strict
  fail_on: never
  minimum_score: 100
`), 0644); err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	report, err := scanner.Scan(context.Background(), tmpDir, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if report.HealthCheck.Policy.Profile != healthcheck.PolicyStrict {
		t.Fatalf("profile = %q; want strict", report.HealthCheck.Policy.Profile)
	}
	if report.HealthCheck.Policy.FailOn != healthcheck.FailOnNever {
		t.Fatalf("fail_on = %q; want never", report.HealthCheck.Policy.FailOn)
	}
	if !report.HealthCheck.Verdict.Passed {
		t.Fatalf("verdict failed despite fail_on=never: %+v", report.HealthCheck.Verdict)
	}
}

func TestCoreScannerSettingsAffectScan(t *testing.T) {
	root := t.TempDir()
	generated := filepath.Join(root, "generated")
	if err := os.MkdirAll(generated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "package.json"), []byte(`{"name":"app","dependencies":{"react":"*"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Scan(context.Background(), root, scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range report.Results {
		if r.ID == "ENTR-02" {
			found = true
		}
	}
	if !found {
		t.Fatal("control scan must report missing lockfile")
	}
	for _, opts := range []scanner.ScanOptions{{MinSeverity: "CRITICAL"}, {ExcludePaths: []string{"generated/**"}}} {
		report, err := scanner.Scan(context.Background(), root, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Results {
			if r.ID == "ENTR-02" {
				t.Fatalf("settings were ignored: %+v", opts)
			}
		}
	}
}
