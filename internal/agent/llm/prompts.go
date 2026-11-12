package llm

import (
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/entropy"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// RichScanResult contains all scanning contexts for LLM and generators
type RichScanResult struct {
	Report        scanner.ScanReport
	External      []external.UnifiedFinding
	NFR           []nfr.NFRFinding
	Deploy        []deployaudit.DeployFinding
	Network       []network.NetworkFinding
	CriticalFiles []entropy.CriticalFile
	HistoryLeaks  []entropy.HistoryLeak
	Diagram       string
	ProjectPath   string
	// ScannerExecutions records, per scanner, whether it actually ran (completed),
	// was missing, failed, timed out, or was not applicable — so a full audit can
	// never silently skip a mandatory scanner.
	ScannerExecutions []external.ScannerExecution
}

// MissingRequiredScanners returns the required external scanners that did not
// complete (missing/failed/timed_out). not_applicable is an allowed outcome and
// is not reported as missing.
func (r RichScanResult) MissingRequiredScanners() []string {
	status := map[string]external.ScannerStatus{}
	for _, e := range r.ScannerExecutions {
		status[e.Scanner] = e.Status
	}
	var missing []string
	for _, req := range external.RequiredScannerExecutions {
		if status[req] != external.StatusCompleted && status[req] != external.StatusNotApplicable {
			missing = append(missing, req)
		}
	}
	return missing
}

// BuildAnalysisPrompt constructs the analysis prompt from scan results.
func BuildAnalysisPrompt(rich RichScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("I've scanned the project at: %s\n\n", rich.ProjectPath))

	if len(rich.Report.Results) > 0 {
		sb.WriteString(fmt.Sprintf("\n### Core Check Findings (%d):\n", len(rich.Report.Results)))
		for i, r := range rich.Report.Results {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s (Rule ID: %s)\n", i+1, r.Severity, r.Name, r.ID))
			sb.WriteString(fmt.Sprintf("   File: %s:%d\n", r.File, r.Line))
			sb.WriteString(fmt.Sprintf("   Evidence: %s\n", r.Evidence))
		}
	}

	if len(rich.External) > 0 {
		sb.WriteString(fmt.Sprintf("\n### External Scanner Findings (%d):\n", len(rich.External)))
		for i, e := range rich.External {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s (Tool: %s, Rule: %s)\n", i+1, e.Severity, e.Message, e.Source, e.RuleID))
			sb.WriteString(fmt.Sprintf("   File: %s:%d\n", e.File, e.Line))
		}
	}

	if len(rich.NFR) > 0 {
		sb.WriteString(fmt.Sprintf("\n### NFR Issues (%d):\n", len(rich.NFR)))
		for i, n := range rich.NFR {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s (Rule: %s)\n", i+1, n.Severity, n.Name, n.RuleID))
			sb.WriteString(fmt.Sprintf("   Message: %s\n", n.Message))
		}
	}

	if len(rich.Deploy) > 0 {
		sb.WriteString(fmt.Sprintf("\n### Deploy Config Issues (%d):\n", len(rich.Deploy)))
		for i, d := range rich.Deploy {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, d.Severity, d.Issue))
			sb.WriteString(fmt.Sprintf("   File: %s:%d\n", d.File, d.Line))
			sb.WriteString(fmt.Sprintf("   Advice: %s\n", d.Advice))
		}
	}

	if len(rich.Network) > 0 {
		sb.WriteString(fmt.Sprintf("\n### Live Network Probe (%d open ports):\n", len(rich.Network)))
		for i, n := range rich.Network {
			sb.WriteString(fmt.Sprintf("%d. [%s] Port %d (%s)\n", i+1, n.Severity, n.Port, n.Service))
			sb.WriteString(fmt.Sprintf("   Message: %s\n", n.Message))
		}
	}

	if len(rich.CriticalFiles) > 0 {
		sb.WriteString(fmt.Sprintf("\n### Critical Files (%d):\n", len(rich.CriticalFiles)))
		for i, cf := range rich.CriticalFiles {
			sb.WriteString(fmt.Sprintf("%d. %s [%s] - %s (Commits: %d, Authors: %d)\n", i+1, cf.Path, cf.Risk, cf.Reason, cf.CommitCount, cf.AuthorCount))
		}
	}

	if len(rich.HistoryLeaks) > 0 {
		sb.WriteString(fmt.Sprintf("\n### Git History Leaks (%d):\n", len(rich.HistoryLeaks)))
		for i, hl := range rich.HistoryLeaks {
			sb.WriteString(fmt.Sprintf("%d. %s in %s (Commit %s by %s): %s\n", i+1, hl.Pattern, hl.FilePath, hl.CommitHash, hl.Author, hl.LinePreview))
		}
	}

	if rich.Diagram != "" {
		sb.WriteString(fmt.Sprintf("\n### Architecture Schema:\n```mermaid\n%s\n```\n", rich.Diagram))
	}

	if sb.Len() < 100 {
		return fmt.Sprintf("Project at %s has been scanned. No security issues found.", rich.ProjectPath)
	}

	sb.WriteString("\nPlease analyze these findings, prioritize them, and provide specific remediation recommendations. Connect the architecture diagram with the findings if possible.")
	return sb.String()
}
