package nfr_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

func writeProjectFiles(t *testing.T, files map[string]string) string {
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
	external.ResetScopeFilterCache()
	t.Cleanup(external.ResetScopeFilterCache)
	return root
}

func ruleIDs(t *testing.T, root string) map[string]bool {
	t.Helper()
	findings, err := nfr.CheckNFR(root)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	return ids
}

const fastAPIApp = "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/items')\ndef items():\n    return []\n"

// A rate limiter or auth middleware inside a path the project excluded is not
// part of the application, so it must not satisfy the application's NFRs.
func TestCheckNFRIgnoresEvidenceInsideIgnoredPaths(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{
		".aitriage.yaml":                        "ignore:\n  paths:\n    - wp-content/plugins/akismet/\n",
		"main.py":                               fastAPIApp,
		"wp-content/plugins/akismet/limiter.py": "rate_limit = 10\nauth_middleware = None\n",
	})

	ids := ruleIDs(t, root)
	for _, want := range []string{"NFR-API-001", "NFR-API-003"} {
		if !ids[want] {
			t.Errorf("%s not reported; evidence inside an ignored path was counted (got %v)", want, ids)
		}
	}
}

// Endpoints that exist only inside an excluded path do not make the project
// an API that needs rate limiting or authentication.
func TestCheckNFRIgnoresEndpointsInsideIgnoredPaths(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{
		".aitriage.yaml":     "ignore:\n  paths:\n    - examples/\n",
		"examples/server.py": fastAPIApp,
		"lib.py":             "def helper():\n    return 1\n",
	})

	ids := ruleIDs(t, root)
	for _, unwanted := range []string{"NFR-API-001", "NFR-API-003"} {
		if ids[unwanted] {
			t.Errorf("%s reported for an endpoint inside an ignored path", unwanted)
		}
	}
}
