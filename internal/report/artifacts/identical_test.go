package artifacts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
)

// The Web UI and the AI IDE tool render reports through this package, so the
// same findings must produce the same document wherever it was asked for. If
// they diverged, two people auditing one repository would hand over two
// different answers and have no way to tell which was right.

func twoSurfacesRenderingTheSameFindings(t *testing.T, format Format) ([]byte, []byte) {
	t.Helper()

	findings := []models.Finding{
		{RuleID: "SQLI-001", Title: "SQL injection in invoices", Severity: "CRITICAL",
			FilePath: ptr("billing/invoice.php"), LineNumber: ptr(12), Status: "open"},
		{RuleID: "CVE-2026-1", Title: "Vulnerable dependency", Severity: "HIGH",
			FilePath: ptr("composer.lock"), Status: "open"},
		{RuleID: "GEN-KEY", Title: "Generic API key", Severity: "CRITICAL",
			FilePath: ptr("vendor/lib.js"), LineNumber: ptr(2), Status: "false_positive"},
	}
	scope := Scope{ProductID: 1, ProductName: "billing", RepoPath: "/srv/billing"}

	// Two independent calls stand in for the two surfaces: neither holds state,
	// so identical inputs must give identical output.
	web, err := Render(context.Background(), format, scope, findings)
	if err != nil {
		t.Fatalf("render (web): %v", err)
	}
	ide, err := Render(context.Background(), format, scope, findings)
	if err != nil {
		t.Fatalf("render (ide): %v", err)
	}
	return web.Body, ide.Body
}

func TestSARIFIsByteIdenticalAcrossSurfaces(t *testing.T) {
	web, ide := twoSurfacesRenderingTheSameFindings(t, FormatSARIF)

	if string(web) != string(ide) {
		t.Fatal("the same findings produced different SARIF for two surfaces")
	}
	// Guard against a renderer that is stable only because it is empty.
	var log struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(web, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d run(s)", len(log.Runs))
	}
}

func TestCSVIsByteIdenticalAcrossSurfaces(t *testing.T) {
	web, ide := twoSurfacesRenderingTheSameFindings(t, FormatCSV)

	if string(web) != string(ide) {
		t.Error("the same findings produced different CSV for two surfaces")
	}
	if !strings.Contains(string(web), "SQLI-001") {
		t.Error("the CSV lost its findings")
	}
}

// The executive document carries a generation timestamp, so it is not byte
// identical. Everything that describes the findings still must be.
func TestExecutiveDocumentAgreesOnSubstance(t *testing.T) {
	web, ide := twoSurfacesRenderingTheSameFindings(t, FormatExecutive)

	stripTimestamps := func(body []byte) string {
		var kept []string
		for _, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, "Generated:") {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n")
	}

	if stripTimestamps(web) != stripTimestamps(ide) {
		t.Error("two surfaces described the same findings differently")
	}
}

// Findings must not be reordered by chance: an artifact that shuffles between
// runs cannot be diffed, and a reviewer cannot tell a real change from noise.
func TestOrderingIsDeterministic(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "LOW-1", Severity: "LOW", Title: "a", Status: "open"},
		{RuleID: "CRIT-1", Severity: "CRITICAL", Title: "b", Status: "open"},
		{RuleID: "MED-1", Severity: "MEDIUM", Title: "c", Status: "open"},
		{RuleID: "HIGH-1", Severity: "HIGH", Title: "d", Status: "open"},
	}
	scope := Scope{ProductID: 1, ProductName: "app"}

	first, err := Render(context.Background(), FormatExecutive, scope, findings)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	body := string(first.Body)

	// Severity order is the reading order a reviewer expects.
	positions := []int{
		strings.Index(body, "CRIT-1"),
		strings.Index(body, "HIGH-1"),
		strings.Index(body, "MED-1"),
		strings.Index(body, "LOW-1"),
	}
	for i := 1; i < len(positions); i++ {
		if positions[i] < 0 || positions[i] < positions[i-1] {
			t.Fatalf("findings are not ordered by severity: positions %v", positions)
		}
	}
}
