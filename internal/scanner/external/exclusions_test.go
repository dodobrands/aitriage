package external

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pilot user reported gitleaks flagging a vendored AWS SDK and a .env that
// .gitignore already covered. Both are out of the audited application's scope,
// and both were reported because external scanners never saw the project's
// ignore rules.

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	ResetScopeFilterCache()
	t.Cleanup(ResetScopeFilterCache)
	return root
}

func TestFilterOutOfScopeDropsGitignoredAndVendoredFindings(t *testing.T) {
	root := writeProject(t, map[string]string{
		".gitignore":       ".env\n/secrets/\n",
		".env":             "API_KEY=abc\n",
		"app/main.go":      "package main\n",
		"secrets/keys.txt": "key\n",
	})

	findings := []UnifiedFinding{
		{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, ".env"), Line: 9},
		{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "vendor/aws/aws-sdk-php/src/data/ebs/api-2.json"), Line: 3},
		{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "public/assets/vendor/libs/quill.js"), Line: 2},
		{Source: "semgrep", RuleID: "node-check", File: filepath.Join(root, "node_modules/left-pad/index.js"), Line: 1},
		{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "secrets/keys.txt"), Line: 1},
		{Source: "semgrep", RuleID: "sql-injection", File: filepath.Join(root, "app/main.go"), Line: 42},
	}

	kept := FilterOutOfScope(root, findings)

	if len(kept) != 1 {
		for _, f := range kept {
			t.Logf("kept: %s", f.File)
		}
		t.Fatalf("kept %d findings; want only the one in the project's own source", len(kept))
	}
	if kept[0].RuleID != "sql-injection" {
		t.Errorf("kept %q; want the application's own finding", kept[0].RuleID)
	}
}

func TestFilterOutOfScopeKeepsProjectLevelFindings(t *testing.T) {
	root := writeProject(t, map[string]string{".gitignore": ".env\n"})

	kept := FilterOutOfScope(root, []UnifiedFinding{
		{Source: "aitriage", RuleID: "ENTR-02", Message: "no lockfile"},
	})

	if len(kept) != 1 {
		t.Fatalf("dropped a project-level finding that has no file path")
	}
}

func TestFilterOutOfScopeHonorsAitriageIgnore(t *testing.T) {
	root := writeProject(t, map[string]string{
		".aitriageignore":  "generated/\n",
		"generated/api.go": "package generated\n",
	})

	kept := FilterOutOfScope(root, []UnifiedFinding{
		{Source: "semgrep", File: filepath.Join(root, "generated/api.go"), Line: 1},
	})

	if len(kept) != 0 {
		t.Fatalf("kept %d findings from an .aitriageignore'd path", len(kept))
	}
}

func TestScanVendoredCodeOptOut(t *testing.T) {
	t.Setenv("AITRIAGE_RESPECT_GITIGNORE", "false")
	root := writeProject(t, map[string]string{
		".gitignore": ".env\n",
		".env":       "API_KEY=abc\n",
	})

	kept := FilterOutOfScope(root, []UnifiedFinding{
		{Source: "gitleaks", File: filepath.Join(root, ".env"), Line: 1},
	})

	if len(kept) != 1 {
		t.Fatalf("AITRIAGE_RESPECT_GITIGNORE=false must still report ignored files")
	}
}

func TestScopeFilterHandlesContainerPaths(t *testing.T) {
	root := writeProject(t, map[string]string{".gitignore": ".env\n"})
	filter := NewScopeFilter(root)

	// Container runs report paths under the mounted source root.
	if filter.InScope("/workspace/.env") {
		t.Errorf("a gitignored file reported under the container mount stayed in scope")
	}
	if filter.InScope("/workspace/vendor/aws/api.json") {
		t.Errorf("vendored code reported under the container mount stayed in scope")
	}
	if !filter.InScope("/workspace/app/main.go") {
		t.Errorf("application source under the container mount was dropped")
	}
}

func TestExclusionArgsCoverVendoredDirectories(t *testing.T) {
	semgrep := SemgrepExcludeArgs()
	var sawVendor, sawNodeModules bool
	for _, arg := range semgrep {
		switch arg {
		case "vendor":
			sawVendor = true
		case "node_modules":
			sawNodeModules = true
		}
	}
	if !sawVendor || !sawNodeModules {
		t.Errorf("semgrep exclude args = %v; want vendor and node_modules", semgrep)
	}

	pattern := GitleaksAllowlistPattern()
	for _, want := range []string{"vendor", "node_modules", "aitriage-reports"} {
		if !strings.Contains(pattern, want) {
			t.Errorf("gitleaks allowlist %q is missing %q", pattern, want)
		}
	}
}
