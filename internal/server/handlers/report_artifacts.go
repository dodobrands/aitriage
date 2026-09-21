package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/report/sbom"
	"github.com/dodobrands/aitriage/internal/scanner"
)

// Report artifacts are rendered from the triaged findings held in the database,
// which is the authoritative record of what a human or the AI decided about each
// finding. Nothing in this file calls an LLM: a team without an API key must
// still be able to produce a complete, defensible security report.

// artifactFormat is a normalized report format identifier.
type artifactFormat string

const (
	formatSARIF     artifactFormat = "sarif"
	formatCSV       artifactFormat = "csv"
	formatExecutive artifactFormat = "executive"
	formatCycloneDX artifactFormat = "cyclonedx"
	formatSPDX      artifactFormat = "spdx"
)

// normalizeFormat maps user-supplied format names onto the supported set.
// "pdf" maps to the print-ready executive document: AITriage does not embed a
// PDF engine, and the browser's own "Print to PDF" produces a better document
// than a hand-rolled one.
func normalizeFormat(value string) (artifactFormat, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sarif":
		return formatSARIF, true
	case "csv":
		return formatCSV, true
	case "pdf", "executive", "html":
		return formatExecutive, true
	case "cyclonedx", "cdx":
		return formatCycloneDX, true
	case "spdx":
		return formatSPDX, true
	default:
		return "", false
	}
}

// artifact is a rendered report ready to be written to an HTTP response.
type artifact struct {
	ContentType string
	Filename    string
	Body        []byte
}

// isSuppressed reports whether a finding must not be counted as an open issue.
// It mirrors the health-check semantics: false positives, accepted risks and
// closed items are context, not outstanding work.
func isSuppressed(f models.Finding) bool {
	switch strings.ToLower(strings.TrimSpace(f.Status)) {
	case "false_positive", "risk_accepted", "resolved", "closed", "mitigated":
		return true
	}
	return f.RiskAccepted
}

// needsReview reports whether a finding was never triaged to a verdict. These
// are the findings that keep a gate red even when nothing is confirmed, so
// every artifact states their number explicitly.
func needsReview(f models.Finding) bool {
	if isSuppressed(f) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f.Status)) {
	case "verified", "confirmed", "true_positive":
		return false
	}
	return true
}

// artifactScope describes exactly which findings an artifact covers, so the
// document itself can state its own boundary instead of leaving the reader to
// guess whether it is one repository or all of them.
type artifactScope struct {
	ProductID   int64
	ProductName string
	RepoPath    string
	AllProducts bool
}

func (s artifactScope) label() string {
	if s.AllProducts {
		return "all products"
	}
	if strings.TrimSpace(s.ProductName) == "" {
		return fmt.Sprintf("product %d", s.ProductID)
	}
	return s.ProductName
}

func (s artifactScope) slug() string {
	if s.AllProducts {
		return "all-products"
	}
	base := strings.TrimSpace(s.ProductName)
	if base == "" {
		base = fmt.Sprintf("product-%d", s.ProductID)
	}
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-' || r == '/' || r == '.':
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return fmt.Sprintf("product-%d", s.ProductID)
	}
	return slug
}

// severityCounts is an ordered severity tally.
type severityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func (c *severityCounts) add(severity string) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		c.Critical++
	case "HIGH":
		c.High++
	case "MEDIUM":
		c.Medium++
	case "LOW":
		c.Low++
	default:
		c.Info++
	}
}

func (c severityCounts) total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// renderArtifact produces the requested document for the given scope.
func renderArtifact(ctx context.Context, format artifactFormat, scope artifactScope, findings []models.Finding) (artifact, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	base := fmt.Sprintf("aitriage-%s-%s", scope.slug(), stamp)

	switch format {
	case formatSARIF:
		body, err := renderSARIF(scope, findings)
		if err != nil {
			return artifact{}, err
		}
		return artifact{ContentType: "application/sarif+json", Filename: base + ".sarif.json", Body: body}, nil

	case formatCSV:
		return artifact{ContentType: "text/csv; charset=utf-8", Filename: base + ".csv", Body: renderCSV(findings)}, nil

	case formatExecutive:
		return artifact{ContentType: "text/html; charset=utf-8", Filename: base + ".html", Body: renderExecutiveHTML(scope, findings)}, nil

	case formatCycloneDX, formatSPDX:
		return renderSBOM(ctx, format, scope, base)

	default:
		return artifact{}, fmt.Errorf("unsupported report format: %s", format)
	}
}

// renderSARIF emits SARIF 2.1.0 describing the open findings. Suppressed
// findings are carried with a SARIF suppression rather than dropped, so a
// reviewer can see what was dismissed and why.
func renderSARIF(scope artifactScope, findings []models.Finding) ([]byte, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifactLocation struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
		Region           *sarifRegion          `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifSuppression struct {
		Kind          string `json:"kind"`
		Justification string `json:"justification,omitempty"`
	}
	type sarifResult struct {
		RuleID       string             `json:"ruleId"`
		Level        string             `json:"level"`
		Message      sarifMessage       `json:"message"`
		Locations    []sarifLocation    `json:"locations,omitempty"`
		Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name,omitempty"`
		ShortDescription sarifMessage `json:"shortDescription"`
		FullDescription  sarifMessage `json:"fullDescription,omitempty"`
		HelpURI          string       `json:"helpUri,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifInvocation struct {
		ExecutionSuccessful bool   `json:"executionSuccessful"`
		WorkingDirectory    string `json:"workingDirectory,omitempty"`
	}
	type sarifRun struct {
		Tool        sarifTool         `json:"tool"`
		Invocations []sarifInvocation `json:"invocations,omitempty"`
		Results     []sarifResult     `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	rules := make([]sarifRule, 0)
	seenRule := make(map[string]bool)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := strings.TrimSpace(f.RuleID)
		if ruleID == "" {
			ruleID = "AITRIAGE-UNSPECIFIED"
		}
		if !seenRule[ruleID] {
			seenRule[ruleID] = true
			rule := sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
			}
			if f.Description != nil && strings.TrimSpace(*f.Description) != "" {
				rule.FullDescription = sarifMessage{Text: *f.Description}
			}
			rules = append(rules, rule)
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title},
		}
		if f.FilePath != nil && strings.TrimSpace(*f.FilePath) != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: strings.TrimPrefix(*f.FilePath, "/")},
				},
			}
			if f.LineNumber != nil && *f.LineNumber > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: *f.LineNumber}
			}
			result.Locations = []sarifLocation{loc}
		}
		if isSuppressed(f) {
			justification := strings.ToLower(strings.TrimSpace(f.Status))
			if f.RiskAcceptedReason != nil && strings.TrimSpace(*f.RiskAcceptedReason) != "" {
				justification = *f.RiskAcceptedReason
			}
			result.Suppressions = []sarifSuppression{{Kind: "external", Justification: justification}}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:        sarifTool{Driver: sarifDriver{Name: "AITriage", InformationURI: "https://github.com/dodobrands/aitriage", Rules: rules}},
			Invocations: []sarifInvocation{{ExecutionSuccessful: true, WorkingDirectory: scope.RepoPath}},
			Results:     results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}

// renderCSV emits one row per finding, including triage state, so the sheet can
// be handed to a reviewer without further processing.
func renderCSV(findings []models.Finding) []byte {
	var buf bytes.Buffer
	// Excel opens UTF-8 CSV correctly only with a BOM; reports are read by
	// non-technical reviewers, so the BOM is worth the three bytes.
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"Rule ID", "Title", "Severity", "Status", "Triage", "File", "Line", "CWE", "CVE", "Description"})

	for _, f := range findings {
		var triage string
		switch {
		case isSuppressed(f):
			triage = "suppressed"
		case needsReview(f):
			triage = "needs review"
		default:
			triage = "confirmed"
		}
		_ = w.Write([]string{
			f.RuleID,
			f.Title,
			strings.ToUpper(f.Severity),
			f.Status,
			triage,
			derefString(f.FilePath),
			derefInt(f.LineNumber),
			derefString(f.CWEID),
			derefString(f.CVEID),
			collapseWhitespace(derefString(f.Description)),
		})
	}
	w.Flush()
	return buf.Bytes()
}

// renderSBOM scans the product's working tree to build a dependency inventory.
// An SBOM describes what the project depends on, which findings alone cannot
// answer, so this is the one artifact that reads the source tree.
func renderSBOM(ctx context.Context, format artifactFormat, scope artifactScope, base string) (artifact, error) {
	path := strings.TrimSpace(scope.RepoPath)
	if path == "" {
		return artifact{}, fmt.Errorf("an SBOM needs the project path, but product %q has no repository path configured", scope.label())
	}

	report, err := scanner.Scan(ctx, path, scanner.ScanOptions{})
	if err != nil {
		return artifact{}, fmt.Errorf("dependency scan of %s failed: %w", path, err)
	}

	var (
		body []byte
		name string
	)
	if format == formatCycloneDX {
		body, err = sbom.CycloneDX(report, path)
		name = base + ".cyclonedx.json"
	} else {
		body, err = sbom.SPDX(report, path)
		name = base + ".spdx.json"
	}
	if err != nil {
		return artifact{}, err
	}
	return artifact{ContentType: "application/json", Filename: name, Body: body}, nil
}

// renderExecutiveHTML builds a self-contained, print-ready report. It is the
// document a team hands to a reviewer or a marketplace, so it states its own
// scope, the triage state of every finding, and what AITriage did not verify.
func renderExecutiveHTML(scope artifactScope, findings []models.Finding) []byte {
	var open, suppressed, review severityCounts
	for _, f := range findings {
		switch {
		case isSuppressed(f):
			suppressed.add(f.Severity)
		case needsReview(f):
			review.add(f.Severity)
			open.add(f.Severity)
		default:
			open.add(f.Severity)
		}
	}

	ordered := make([]models.Finding, len(findings))
	copy(ordered, findings)
	sort.SliceStable(ordered, func(i, j int) bool {
		return severityRank(ordered[i].Severity) < severityRank(ordered[j].Severity)
	})

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>`)
	b.WriteString(html.EscapeString("Security Report — " + scope.label()))
	b.WriteString(`</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 40px; font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; color: #18181b; background: #fff; }
  .wrap { max-width: 1000px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #e4e4e7; }
  .meta { color: #52525b; font-size: 13px; margin-bottom: 24px; }
  .meta strong { color: #18181b; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; background: #fafafa; font-weight: 600; }
  th, td { padding: 8px 10px; border-bottom: 1px solid #e4e4e7; vertical-align: top; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .tiles { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0 8px; }
  .tile { flex: 1 1 120px; border: 1px solid #e4e4e7; border-radius: 8px; padding: 12px 14px; }
  .tile .n { font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .tile .l { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: #71717a; }
  .sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: .04em; }
  .critical { background: #fee2e2; color: #991b1b; }
  .high     { background: #ffedd5; color: #9a3412; }
  .medium   { background: #fef3c7; color: #854d0e; }
  .low      { background: #e0f2fe; color: #075985; }
  .info     { background: #f4f4f5; color: #3f3f46; }
  .note { border-left: 3px solid #d4d4d8; padding: 10px 14px; background: #fafafa; color: #3f3f46; font-size: 13px; margin: 16px 0; }
  .path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #3f3f46; word-break: break-all; }
  footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #e4e4e7; color: #71717a; font-size: 12px; }
  @media print { body { padding: 0; } .tile { break-inside: avoid; } tr { break-inside: avoid; } }
</style>
</head>
<body><div class="wrap">
`)

	fmt.Fprintf(&b, "<h1>Security Report</h1>\n<div class=\"meta\">")
	fmt.Fprintf(&b, "Scope: <strong>%s</strong>", html.EscapeString(scope.label()))
	if scope.RepoPath != "" {
		fmt.Fprintf(&b, "<br>Repository: <span class=\"path\">%s</span>", html.EscapeString(scope.RepoPath))
	}
	fmt.Fprintf(&b, "<br>Generated: %s<br>Produced by AITriage static analysis. No AI triage is required to generate this document.",
		html.EscapeString(time.Now().UTC().Format("2006-01-02 15:04:05 MST")))
	b.WriteString("</div>\n")

	b.WriteString("<h2>Summary</h2>\n<div class=\"tiles\">")
	for _, tile := range []struct {
		label string
		n     int
	}{
		{"Total", len(findings)},
		{"Open", open.total()},
		{"Needs review", review.total()},
		{"Suppressed", suppressed.total()},
	} {
		fmt.Fprintf(&b, "<div class=\"tile\"><div class=\"n\">%d</div><div class=\"l\">%s</div></div>", tile.n, html.EscapeString(tile.label))
	}
	b.WriteString("</div>\n")

	b.WriteString("<table><thead><tr><th>Severity</th><th class=\"num\">Open</th><th class=\"num\">Needs review</th><th class=\"num\">Suppressed</th></tr></thead><tbody>\n")
	for _, row := range []struct {
		name                   string
		class                  string
		open, review, suppress int
	}{
		{"Critical", "critical", open.Critical, review.Critical, suppressed.Critical},
		{"High", "high", open.High, review.High, suppressed.High},
		{"Medium", "medium", open.Medium, review.Medium, suppressed.Medium},
		{"Low", "low", open.Low, review.Low, suppressed.Low},
		{"Info", "info", open.Info, review.Info, suppressed.Info},
	} {
		fmt.Fprintf(&b, "<tr><td><span class=\"sev %s\">%s</span></td><td class=\"num\">%d</td><td class=\"num\">%d</td><td class=\"num\">%d</td></tr>\n",
			row.class, row.name, row.open, row.review, row.suppress)
	}
	b.WriteString("</tbody></table>\n")

	if review.total() > 0 {
		fmt.Fprintf(&b, "<div class=\"note\"><strong>%d finding(s) are not yet triaged.</strong> "+
			"A finding reported by a scanner is a hypothesis until someone confirms it against the code. "+
			"These are counted as open because they are unresolved, not because they are proven exploitable.</div>\n",
			review.total())
	}

	b.WriteString("<h2>Findings</h2>\n")
	if len(ordered) == 0 {
		b.WriteString("<p>No findings were recorded for this scope.</p>\n")
	} else {
		b.WriteString("<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th><th>State</th></tr></thead><tbody>\n")
		for _, f := range ordered {
			var state string
			switch {
			case isSuppressed(f):
				state = "Suppressed (" + html.EscapeString(f.Status) + ")"
			case needsReview(f):
				state = "Needs review"
			default:
				state = "Confirmed"
			}
			location := derefString(f.FilePath)
			if location != "" && f.LineNumber != nil && *f.LineNumber > 0 {
				location += ":" + strconv.Itoa(*f.LineNumber)
			}
			if location == "" {
				location = "—"
			}
			fmt.Fprintf(&b, "<tr><td><span class=\"sev %s\">%s</span></td><td class=\"path\">%s</td><td>%s</td><td class=\"path\">%s</td><td>%s</td></tr>\n",
				severityClass(f.Severity),
				html.EscapeString(strings.ToUpper(strings.TrimSpace(f.Severity))),
				html.EscapeString(f.RuleID),
				html.EscapeString(f.Title),
				html.EscapeString(location),
				state)
		}
		b.WriteString("</tbody></table>\n")
	}

	b.WriteString("<footer>Generated by AITriage. Severity reflects scanner classification; triage state reflects review decisions recorded in AITriage.</footer>\n")
	b.WriteString("</div></body></html>\n")
	return []byte(b.String())
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

func severityClass(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func derefInt(v *int) string {
	if v == nil || *v == 0 {
		return ""
	}
	return strconv.Itoa(*v)
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
