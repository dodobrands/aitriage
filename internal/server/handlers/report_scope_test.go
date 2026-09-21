package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
)

// The pilot connected two repositories and every report he produced merged both
// of them, "что ломает вообще структуру". A report must cover exactly one
// repository unless the operator deliberately widens it.

func productFindings(product string) []models.Finding {
	switch product {
	case "billing":
		return []models.Finding{
			{RuleID: "SQLI-001", Title: "SQL injection in invoices", Severity: "CRITICAL",
				FilePath: ptr("billing/invoice.php"), LineNumber: ptr(12), Status: "open"},
			{RuleID: "AUTHZ-002", Title: "Missing authorization check", Severity: "HIGH",
				FilePath: ptr("billing/admin.php"), LineNumber: ptr(88), Status: "open"},
		}
	default:
		return []models.Finding{
			{RuleID: "XSS-009", Title: "Reflected XSS in storefront", Severity: "HIGH",
				FilePath: ptr("shop/search.php"), LineNumber: ptr(31), Status: "open"},
		}
	}
}

func TestReportCoversOnlyTheSelectedRepository(t *testing.T) {
	billing := artifactScope{ProductID: 1, ProductName: "billing", RepoPath: "/srv/billing"}

	doc, err := renderArtifact(context.Background(), formatSARIF, billing, productFindings("billing"))
	if err != nil {
		t.Fatalf("renderArtifact: %v", err)
	}

	var log struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc.Body, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	for _, r := range log.Runs[0].Results {
		if r.RuleID == "XSS-009" {
			t.Fatal("a finding from the other repository leaked into the report")
		}
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("results = %d; want the 2 findings of this repository", len(log.Runs[0].Results))
	}
}

func TestArtifactFilenamesDistinguishRepositories(t *testing.T) {
	billing := artifactScope{ProductID: 1, ProductName: "billing"}
	shop := artifactScope{ProductID: 2, ProductName: "shop"}

	a, err := renderArtifact(context.Background(), formatSARIF, billing, productFindings("billing"))
	if err != nil {
		t.Fatalf("renderArtifact(billing): %v", err)
	}
	b, err := renderArtifact(context.Background(), formatSARIF, shop, productFindings("shop"))
	if err != nil {
		t.Fatalf("renderArtifact(shop): %v", err)
	}

	if !strings.Contains(a.Filename, "billing") || !strings.Contains(b.Filename, "shop") {
		t.Errorf("filenames %q and %q do not identify their repository", a.Filename, b.Filename)
	}
}

func TestAllProductsScopeIsLabelledExplicitly(t *testing.T) {
	all := artifactScope{AllProducts: true}

	doc, err := renderArtifact(context.Background(), formatExecutive, all,
		append(productFindings("billing"), productFindings("shop")...))
	if err != nil {
		t.Fatalf("renderArtifact: %v", err)
	}

	// Merging repositories stays possible, but the document must say so rather
	// than letting a reader assume it describes one application.
	if !strings.Contains(string(doc.Body), "all products") {
		t.Error("a multi-repository report does not state that it covers all products")
	}
	if !strings.Contains(all.slug(), "all-products") {
		t.Errorf("slug = %q; a merged report must be distinguishable by filename", all.slug())
	}
}
