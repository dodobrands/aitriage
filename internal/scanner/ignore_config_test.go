package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner"
)

func writeScanFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// With the "aitriage init" defaults (vendor/, dist/) the project's own
// src/vendors/ disappeared from the scan, secrets included: the entries were
// matched as substrings of every directory path.
func TestScanKeepsProjectCodeThatSharesANameWithAnIgnoredPath(t *testing.T) {
	root := writeScanFixture(t, map[string]string{
		".aitriage.yaml":     "ignore:\n  paths:\n    - vendor/\n    - dist/\n    - generated/\n",
		"src/vendors/api.py": "api_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
		"generated/api.py":   "api_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
	})

	report, err := scanner.Scan(context.Background(), root, scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, r := range report.Results {
		if r.File != "" {
			rel, _ := filepath.Rel(root, r.File)
			found[filepath.ToSlash(rel)] = true
		}
	}
	if !found["src/vendors/api.py"] {
		t.Errorf("findings in src/vendors/api.py were dropped by the vendor/ entry (files with findings: %v)", found)
	}
	if found["generated/api.py"] {
		t.Error("generated/ is ignored, but its file was scanned")
	}
}

// The engine skips an ignored YAML rule, but its secret and scaffolding
// heuristics were added without that check, so ignore.rules could not silence
// them in "aitriage scan".
func TestScanHonoursIgnoreRulesForBuiltInHeuristics(t *testing.T) {
	root := writeScanFixture(t, map[string]string{
		".aitriage.yaml": "ignore:\n  rules:\n    - secret-aws-akid\n",
		"app/main.go":    "package main\n\nvar key = \"AKIAIOSFODNN7EXAMPLE\"\n",
	})

	report, err := scanner.Scan(context.Background(), root, scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Results {
		if r.ID == "SECRET-AWS-AKID" {
			t.Fatalf("ignored heuristic reported: %+v", r)
		}
	}
	if report.IgnoredByConfig["secret-aws-akid"] != 1 {
		t.Errorf("ignored by config = %v; want the entry counted once", report.IgnoredByConfig)
	}
}

// Web scans pass exclusions as ScanOptions.ExcludePaths. They follow git's
// rules like ignore.paths: a pattern with a slash before its last character is
// anchored at the root, so a nested copy of the same path is still scanned.
func TestScanExcludePathsAreAnchoredLikeGit(t *testing.T) {
	root := writeScanFixture(t, map[string]string{
		"app/legacy/old.py":          "api_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
		"services/app/legacy/new.py": "api_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
	})

	report, err := scanner.Scan(context.Background(), root, scanner.ScanOptions{ExcludePaths: []string{"app/legacy/"}})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range report.Results {
		if r.File == "" {
			continue
		}
		rel := r.File
		if filepath.IsAbs(rel) {
			rel, _ = filepath.Rel(root, rel)
		}
		found[filepath.ToSlash(rel)] = true
	}
	if found["app/legacy/old.py"] {
		t.Error("app/legacy/old.py is excluded by app/legacy/, but it was scanned")
	}
	if !found["services/app/legacy/new.py"] {
		t.Errorf("services/app/legacy/new.py was dropped by the root-anchored app/legacy/ (files with findings: %v)", found)
	}
}
