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
	err := os.WriteFile(tmpDir+"/main.go", []byte("package main\n\nfunc main() {\n\tsecret := \"AKIA"+"Z7Q4XWVB3NMK2PLT\"\n}\n"), 0644)
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
		"main_test.go":       "package main\nvar token = \"AKIA" + "Z7Q4XWVB3NMK2PLT\"\n",
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
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("api_key = \"AKIA"+"Z7Q4XWVB3NMK2PLT\"\n"), 0o600); err != nil {
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
	if err := os.WriteFile(tmpDir+"/main.go", []byte("package main\n\nfunc main() {\n\tsecret := \"AKIA"+"Z7Q4XWVB3NMK2PLT\"\n}\n"), 0644); err != nil {
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

// A file over 1,500 lines (ENTR-12) is a code-quality finding: under
// quality_findings: report it is reported but neither scored nor gating;
// under block, the default, it counts like any other finding.
func TestScanAppliesQualityFindingsConfig(t *testing.T) {
	scan := func(config string) scanner.ScanReport {
		t.Helper()
		dir := t.TempDir()
		var source []byte
		for i := 0; i < 1600; i++ {
			source = append(source, "value = compute()\n"...)
		}
		if err := os.WriteFile(filepath.Join(dir, "service.py"), source, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".aitriage.yaml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
		report, err := scanner.Scan(context.Background(), dir, scanner.ScanOptions{})
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		return report
	}

	gate := "health_check:\n  profile: strict\n  fail_on: any\n"
	reported := scan(gate + "  quality_findings: report\n")
	found := false
	for _, r := range reported.Results {
		if r.ID == "ENTR-12" {
			found = r.Subcategory == healthcheck.SubcategoryQuality
		}
	}
	if !found {
		t.Fatalf("results = %+v, want ENTR-12 with subcategory quality", reported.Results)
	}
	hc := reported.HealthCheck
	if !hc.Verdict.Passed || hc.Score != 100 || hc.Breakdown.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 1 {
		t.Fatalf("score %d, verdict %+v, breakdown %+v; want ENTR-12 reported only", hc.Score, hc.Verdict, hc.Breakdown)
	}

	for _, settings := range []string{gate, gate + "  quality_findings: block\n"} {
		blocked := scan(settings).HealthCheck
		if blocked.Verdict.Passed || blocked.Score == 100 || blocked.Breakdown.CountByRule["entr-12"] != 1 {
			t.Fatalf("%s: score %d, verdict %+v; want ENTR-12 to gate", settings, blocked.Score, blocked.Verdict)
		}
	}
}

// A swallowed exception is not code quality: `except Exception: pass` around
// a token check turns a failed check into a pass. FAST-LAZY-EXC, as the
// built-in catalog defines it, is scored and gates under quality_findings:
// report exactly as under block.
func TestScanGatesASwallowedExceptionUnderQualityReport(t *testing.T) {
	scan := func(settings string) scanner.ScanReport {
		t.Helper()
		dir := t.TempDir()
		source := "import jwt\n\n\ndef current_user(token, key):\n    claims = None\n    try:\n        claims = jwt.decode(token, key, algorithms=[\"HS256\"])\n    except Exception:\n        pass\n    return claims\n"
		if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".aitriage.yaml"), []byte(settings), 0o644); err != nil {
			t.Fatal(err)
		}
		report, err := scanner.Scan(context.Background(), dir, scanner.ScanOptions{ForceStack: "fastapi"})
		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		return report
	}

	gate := "health_check:\n  fail_on: any\n"
	reported := scan(gate + "  quality_findings: report\n")
	found := false
	for _, r := range reported.Results {
		if r.ID == "FAST-LAZY-EXC" {
			found = true
			if r.Subcategory == healthcheck.SubcategoryQuality {
				t.Fatalf("FAST-LAZY-EXC has subcategory %q, want it scored and gated", r.Subcategory)
			}
		}
	}
	if !found {
		t.Fatalf("results = %+v, want FAST-LAZY-EXC on the swallowed exception", reported.Results)
	}
	hc := reported.HealthCheck
	if hc.Verdict.Passed || hc.Breakdown.CountByRule["fast-lazy-exc"] != 1 || hc.Breakdown.ReportOnlyByKind[healthcheck.ReportOnlyQuality] != 0 {
		t.Fatalf("under report: verdict %+v, breakdown %+v; want FAST-LAZY-EXC to gate", hc.Verdict, hc.Breakdown)
	}
	if blocked := scan(gate + "  quality_findings: block\n").HealthCheck; blocked.Score != hc.Score {
		t.Fatalf("score under report %d, under block %d; want quality_findings to change nothing", hc.Score, blocked.Score)
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
