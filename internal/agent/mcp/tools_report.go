package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/report/artifacts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An agent could scan a project but not produce the document a human hands to a
// reviewer or a marketplace — report generation existed only in the Web UI. That
// made the agent a dead end: it found the problems and then told the user to go
// somewhere else to write them up.
//
// The renderers live in internal/report/artifacts and are shared with the Web
// surface, so the same findings produce the same document wherever it is asked
// for.

type reportInput struct {
	Path string `json:"path,omitempty"`
	// Format: sarif, csv, executive (or pdf, which renders the same print-ready
	// document), cyclonedx, spdx.
	Format string `json:"format,omitempty"`
	// Output is an optional file path, relative to the project. When empty the
	// artifact is written under aitriage-reports/.
	Output string `json:"output,omitempty"`
}

type reportResult struct {
	Format      string `json:"format"`
	File        string `json:"file"`
	Findings    int    `json:"findings"`
	Bytes       int    `json:"bytes"`
	ContentType string `json:"content_type"`
	Summary     string `json:"summary"`
}

// reportsDirName is where AITriage keeps everything it generates. Writing there
// keeps the project's own tree untouched and is already gitignored by the
// connectors.
const reportsDirName = "aitriage-reports"

func registerReportTool(srv *mcp.Server, guard *PathGuard) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "aitriage_report",
		Description: "Generate a security report artifact for a project: SARIF for code scanning, " +
			"CSV for review, a print-ready executive document for a reviewer or marketplace, " +
			"or a CycloneDX/SPDX SBOM. Runs the deterministic scanners and needs no LLM. " +
			"The file is written under aitriage-reports/ and its path is returned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input reportInput) (*mcp.CallToolResult, reportResult, error) {
		path, err := guard.Resolve(input.Path)
		if err != nil {
			return nil, reportResult{}, err
		}

		requested := strings.TrimSpace(input.Format)
		if requested == "" {
			requested = "sarif"
		}
		format, ok := artifacts.NormalizeFormat(requested)
		if !ok {
			return nil, reportResult{}, fmt.Errorf(
				"unsupported format %q (use sarif, csv, executive, cyclonedx or spdx)", input.Format)
		}

		rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
			ProjectPath: path,
			RunExternal: true,
		})

		scope := artifacts.Scope{
			ProductName: filepath.Base(path),
			RepoPath:    path,
		}
		doc, err := artifacts.Render(ctx, format, scope, findingsFromScan(&rich))
		if err != nil {
			return nil, reportResult{}, err
		}

		target, err := reportOutputPath(path, input.Output, doc.Filename)
		if err != nil {
			return nil, reportResult{}, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, reportResult{}, fmt.Errorf("could not create the report directory: %v", err)
		}
		if err := os.WriteFile(target, doc.Body, 0o600); err != nil {
			return nil, reportResult{}, fmt.Errorf("could not write the report: %v", err)
		}

		count := len(findingsFromScan(&rich))
		return nil, reportResult{
			Format:      string(format),
			File:        target,
			Findings:    count,
			Bytes:       len(doc.Body),
			ContentType: doc.ContentType,
			Summary: fmt.Sprintf("%s report for %s: %d finding(s), written to %s. Nothing in it is triaged — a scanner finding is a hypothesis until someone confirms it.",
				strings.ToUpper(string(format)), scope.Label(), count, target),
		}, nil
	})
}

// reportOutputPath resolves where the artifact is written, refusing anything
// outside the project so a tool call cannot scatter files across the disk.
func reportOutputPath(projectPath, requested, defaultName string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return filepath.Join(projectPath, reportsDirName, defaultName), nil
	}

	candidate := requested
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(projectPath, candidate)
	}
	candidate = filepath.Clean(candidate)

	if candidate != projectPath && !strings.HasPrefix(candidate, projectPath+string(os.PathSeparator)) {
		return "", fmt.Errorf("output path %q is outside the project", requested)
	}
	return candidate, nil
}

// findingsFromScan maps a deterministic scan into the shape the shared renderers
// consume. Nothing here has been triaged, so every finding is reported open —
// the artifact says so explicitly rather than implying the findings are proven.
func findingsFromScan(rich *llm.RichScanResult) []models.Finding {
	out := make([]models.Finding, 0)

	for _, r := range rich.Report.Results {
		if r.Status != core.Absent {
			continue
		}
		out = append(out, models.Finding{
			RuleID:      r.ID,
			Title:       r.Name,
			Severity:    r.Severity,
			Status:      "open",
			FilePath:    optionalString(r.File),
			LineNumber:  optionalInt(r.Line),
			Description: optionalString(r.Suggestion),
		})
	}

	for _, f := range rich.External {
		out = append(out, models.Finding{
			RuleID:      f.RuleID,
			Title:       firstNonEmptyString(f.Message, f.RuleID),
			Severity:    f.Severity,
			Status:      "open",
			FilePath:    optionalString(f.File),
			LineNumber:  optionalInt(f.Line),
			CWEID:       optionalString(f.CWE),
			Description: optionalString(f.Suggestion),
		})
	}

	for _, f := range rich.NFR {
		out = append(out, models.Finding{
			RuleID:      f.RuleID,
			Title:       firstNonEmptyString(f.Name, f.RuleID),
			Severity:    f.Severity,
			Status:      "open",
			Description: optionalString(f.Advice),
		})
	}

	for _, f := range rich.Deploy {
		out = append(out, models.Finding{
			RuleID:      f.Issue,
			Title:       f.Issue,
			Severity:    f.Severity,
			Status:      "open",
			FilePath:    optionalString(f.File),
			LineNumber:  optionalInt(f.Line),
			Description: optionalString(f.Advice),
		})
	}

	return out
}

func optionalString(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

func optionalInt(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
