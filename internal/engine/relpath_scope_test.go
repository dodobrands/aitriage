package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// A project checked out under a directory named "build" (as some CI systems
// do, e.g. .../agent/build/) is still the project's own code: the secret
// heuristic must judge vendored segments inside the project only.
func TestSecretHeuristicIgnoresTheCheckoutLocation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent", "build")
	file := filepath.Join(root, "app", "settings.py")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("api_key = \"f9Kd82LmQz7Xp3Vn6Rt1Yw4Bc8Hj5Ns2\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := &Engine{}
	results := e.evaluateEntropy(&core.FileInfo{Path: file, RelPath: "app/settings.py", Extension: ".py"})
	if len(results) == 0 {
		t.Fatalf("hardcoded secret under a checkout in %s was not reported", root)
	}
}

func TestIsVendoredPathUsesProjectSegmentsOnly(t *testing.T) {
	cases := map[string]bool{
		"vendor/github.com/x/y.go":     true,
		"web/node_modules/pkg/i.js":    true,
		"dist/bundle.js":               true,
		"src/vendors/api.py":           false, // a project directory, not vendored code
		"build/package/Dockerfile":     false, // committed build/ belongs to the project
		"app/settings.py":              false,
		"distribution/settings.py":     false,
		"services/.next-gen/server.ts": false,
	}
	for path, want := range cases {
		if got := isVendoredPath(path); got != want {
			t.Errorf("isVendoredPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// Rule exclude_paths fragments describe locations inside the project. A
// project cloned under a parent directory that happens to contain a fragment
// (".../scripts/...", ".../seed-service/...") must keep the rule everywhere.
func TestRuleExcludePathsIgnoreTheCheckoutLocation(t *testing.T) {
	rule := Rule{ID: "TEST-RULE", ExcludePaths: []string{"seed", "scripts/"}}

	inProject := &core.FileInfo{Path: "/ci/scripts/seed-service/app/main.py", RelPath: "app/main.py"}
	if matchesExcludedPath(rule, inProject) {
		t.Fatalf("rule excluded for %s although only the checkout location matches", inProject.Path)
	}

	excluded := &core.FileInfo{Path: "/ci/project/scripts/deploy.py", RelPath: "scripts/deploy.py"}
	if !matchesExcludedPath(rule, excluded) {
		t.Fatalf("rule not excluded for %s, which is under scripts/ inside the project", excluded.RelPath)
	}
}
