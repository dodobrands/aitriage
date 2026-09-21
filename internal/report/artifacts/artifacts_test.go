package artifacts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
)

// Report generation used to be a stub: it recorded a row and the download button
// fell back to a severity histogram covering every product at once. A team with
// two repositories could not produce a report for one of them.

func ptr[T any](v T) *T { return &v }

func sampleFindings() []models.Finding {
	return []models.Finding{
		{RuleID: "SQLI-001", Title: "SQL injection in order lookup", Severity: "CRITICAL",
			FilePath: ptr("app/orders.php"), LineNumber: ptr(42), Status: "verified"},
		{RuleID: "XSS-004", Title: "Reflected XSS in search", Severity: "HIGH",
			FilePath: ptr("app/search.php"), LineNumber: ptr(17), Status: "open"},
		{RuleID: "GEN-API-KEY", Title: "Generic API key", Severity: "CRITICAL",
			FilePath: ptr("vendor/lib/quill.js"), LineNumber: ptr(2), Status: "false_positive"},
	}
}

func TestExecutiveReportStatesItsOwnScope(t *testing.T) {
	scope := Scope{ProductID: 7, ProductName: "billing-api", RepoPath: "/srv/billing-api"}

	doc, err := Render(context.Background(), FormatExecutive, scope, sampleFindings())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := string(doc.Body)

	for _, want := range []string{"billing-api", "/srv/billing-api"} {
		if !strings.Contains(body, want) {
			t.Errorf("report does not state its scope %q", want)
		}
	}
	if !strings.Contains(body, "No AI triage is required") {
		t.Error("report does not say it was produced without AI")
	}
	if !strings.Contains(body, "not been reviewed") && !strings.Contains(body, "not yet triaged") {
		t.Error("report does not explain the unreviewed findings it counts as open")
	}
}

func TestExecutiveReportSeparatesConfirmedFromUnreviewed(t *testing.T) {
	scope := Scope{ProductID: 1, ProductName: "app"}

	doc, err := Render(context.Background(), FormatExecutive, scope, sampleFindings())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := string(doc.Body)

	if !strings.Contains(body, "Needs review") {
		t.Error("report has no needs-review column")
	}
	if !strings.Contains(body, "Suppressed") {
		t.Error("report does not account for suppressed findings")
	}
	// The false positive must be visible as context, not silently dropped.
	if !strings.Contains(body, "GEN-API-KEY") {
		t.Error("a suppressed finding vanished from the report instead of being listed")
	}
}

func TestExecutiveReportEscapesFindingText(t *testing.T) {
	scope := Scope{ProductID: 1, ProductName: "app"}
	findings := []models.Finding{
		{RuleID: "X", Title: `<script>alert(1)</script>`, Severity: "HIGH", FilePath: ptr("a.js")},
	}

	doc, err := Render(context.Background(), FormatExecutive, scope, findings)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(string(doc.Body), "<script>alert(1)</script>") {
		t.Error("finding text was interpolated into the report without escaping")
	}
}

func TestSARIFCarriesSuppressionsRatherThanDroppingThem(t *testing.T) {
	scope := Scope{ProductID: 1, ProductName: "app", RepoPath: "/srv/app"}

	doc, err := Render(context.Background(), FormatSARIF, scope, sampleFindings())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Level        string `json:"level"`
				Suppressions []struct {
					Kind string `json:"kind"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc.Body, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q; want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results in 1 run, got %d run(s)", len(log.Runs))
	}

	var suppressed int
	for _, r := range log.Runs[0].Results {
		if len(r.Suppressions) > 0 {
			suppressed++
			if r.RuleID != "GEN-API-KEY" {
				t.Errorf("unexpected suppression on %q", r.RuleID)
			}
		}
		if r.RuleID == "SQLI-001" && r.Level != "error" {
			t.Errorf("CRITICAL mapped to level %q; want error", r.Level)
		}
	}
	if suppressed != 1 {
		t.Errorf("suppressed results = %d; want exactly the false positive", suppressed)
	}
}

func TestCSVRowsCarryTriageState(t *testing.T) {
	body := string(RenderCSV(sampleFindings()))

	if !strings.HasPrefix(body, "\ufeff") {
		t.Error("CSV has no UTF-8 BOM; Excel will mangle non-ASCII text")
	}
	for _, want := range []string{"confirmed", "needs review", "suppressed"} {
		if !strings.Contains(body, want) {
			t.Errorf("CSV does not record the %q triage state", want)
		}
	}
}

func TestSBOMWithoutARepositoryPathFailsClearly(t *testing.T) {
	scope := Scope{ProductID: 3, ProductName: "no-path"}

	_, err := Render(context.Background(), FormatCycloneDX, scope, nil)
	if err == nil {
		t.Fatal("an SBOM without a project path must fail rather than emit an empty inventory")
	}
	if !strings.Contains(err.Error(), "no repository path") {
		t.Errorf("error = %q; it should say what is missing", err)
	}
}

func TestFormatAliases(t *testing.T) {
	// The UI offers "PDF"; AITriage embeds no PDF engine and renders a
	// print-ready document instead, which the browser prints better than we could.
	for input, want := range map[string]Format{
		"SARIF":     FormatSARIF,
		"sarif":     FormatSARIF,
		"pdf":       FormatExecutive,
		"cyclonedx": FormatCycloneDX,
		"cdx":       FormatCycloneDX,
		"spdx":      FormatSPDX,
		"csv":       FormatCSV,
	} {
		got, ok := NormalizeFormat(input)
		if !ok || got != want {
			t.Errorf("NormalizeFormat(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	if _, ok := NormalizeFormat("SARIF v2.1.0"); ok {
		t.Error("a display name must not be accepted as a format id")
	}
}

func TestScopeSlugIsFilesystemSafe(t *testing.T) {
	scope := Scope{ProductID: 1, ProductName: "Acme / Billing API (prod)"}
	slug := scope.Slug()

	if strings.ContainsAny(slug, " /()") {
		t.Errorf("slug %q is not safe for a filename", slug)
	}
	if strings.TrimSpace(slug) == "" {
		t.Error("slug is empty")
	}
}
