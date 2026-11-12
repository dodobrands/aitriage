package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSecretFindingsKeepsDetectorIDs(t *testing.T) {
	results := []core.CheckResult{
		{ID: "SECRET-ASSIGN"}, {ID: "SECRET-AWS-AKID"}, {ID: "SECRET-LEAK-LOG"},
		{ID: "ENTROPY-SECRET"}, {ID: "ENTR-SLOP-01"}, {ID: "NFR-API-001"}, {ID: "DJANGO-SECRET"},
	}
	got := secretFindings(results)
	if len(got) != 4 {
		t.Fatalf("got %d secret findings, want 4 (three SECRET-* and the legacy alias): %+v", len(got), got)
	}
	for _, r := range got {
		if !strings.HasPrefix(r.ID, "SECRET-") && r.ID != "ENTROPY-SECRET" {
			t.Errorf("non-secret finding kept: %s", r.ID)
		}
	}
}

// The tool filtered on ENTROPY-SECRET, an id the engine never emits, so it
// reported zero secrets for every project.
func TestSecretsToolReportsDetectorFindings(t *testing.T) {
	root := t.TempDir()
	value := strings.Join([]string{"sk_", "live_", "AornV2XNpMtoaEI9V7Pxp6rv"}, "")
	if err := os.WriteFile(filepath.Join(root, "payments.js"), []byte("export const key = '"+value+"';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cs := connectClient(t, Config{Profile: ProfileSafe, ScanRoot: root})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "aitriage_secrets", Arguments: map[string]any{"path": "."}})
	if err != nil {
		t.Fatalf("aitriage_secrets: %v", err)
	}
	if res.IsError {
		t.Fatalf("aitriage_secrets returned a tool error: %s", toolText(res))
	}
	var out secretsResult
	decodeStructured(t, res, &out)
	if out.Count == 0 || len(out.Found) != out.Count {
		t.Fatalf("expected the hardcoded key to be reported, got %+v", out)
	}
	found := false
	for _, r := range out.Found {
		if !strings.HasPrefix(r.ID, "SECRET-") {
			t.Errorf("non-secret finding in the result: %s", r.ID)
		}
		if r.ID == "SECRET-STRIPE" {
			found = true
		}
	}
	if !found {
		t.Errorf("SECRET-STRIPE missing from %+v", out.Found)
	}
}

func toolText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}
