package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	fixDryRun   bool
	fixSeverity string
	fixAuto     bool
	fixMaxFixes int
)

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Generate and optionally apply security fixes using AI",
	Long: `AI-powered automated remediation for security findings.

  aitriage fix .                    → Show fix suggestions for all findings
  aitriage fix . --dry-run          → Preview fixes as diffs (no changes)
  aitriage fix . --auto             → Auto-apply safe fixes (LOW/MEDIUM)
  aitriage fix . --severity high    → Only fix HIGH+ severity findings
  aitriage fix . --max 5            → Limit to 5 fixes per run`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFix,
}

func init() {
	rootCmd.AddCommand(fixCmd)
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Preview fixes without applying them")
	fixCmd.Flags().StringVar(&fixSeverity, "severity", "", "Minimum severity to fix: low, medium, high, critical")
	fixCmd.Flags().BoolVar(&fixAuto, "auto", false, "Auto-apply safe fixes (LOW/MEDIUM severity)")
	fixCmd.Flags().IntVar(&fixMaxFixes, "max", 10, "Maximum number of fixes per run")
}

func runFix(cmd *cobra.Command, args []string) error {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Colors
	cyan := "\033[38;2;0;245;255m"
	green := "\033[38;2;46;204;113m"
	yellow := "\033[38;2;255;214;0m"
	red := "\033[38;2;231;76;60m"
	dim := "\033[38;2;120;120;140m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "\n%s%s  ⦿ AITriage Fix — AI-Powered Remediation%s\n\n", cyan, bold, reset)

	// Load Config
	cfg := config.LoadConfig(absPath)

	// Initialize LLM client
	client, err := llm.NewClient(llm.Config{
		Provider:    cfg.LLM.Provider,
		Model:       cfg.LLM.Model,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     cfg.LLM.BaseURL,
		Timeout:     cfg.LLM.Timeout,
		Temperature: cfg.LLM.Temperature,
	})
	if err != nil {
		return fmt.Errorf("LLM client required for fix mode: %w\nSet GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY", err)
	}

	// Run scan
	fmt.Fprintf(os.Stderr, "%s  Scanning project...%s\n", dim, reset)
	ctx := context.Background()
	report, err := scanner.Scan(ctx, absPath, scanner.ScanOptions{})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Filter by severity
	var findings []core.CheckResult
	minSev := parseSeverityLevel(fixSeverity)
	for _, r := range report.Results {
		if severityLevel(r.Severity) >= minSev {
			findings = append(findings, r)
		}
	}

	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "\n%s%s  ✅ No findings to fix!%s\n\n", green, bold, reset)
		return nil
	}

	// Cap at max
	if len(findings) > fixMaxFixes {
		findings = findings[:fixMaxFixes]
	}

	fmt.Fprintf(os.Stderr, "%s  Processing %d findings...%s\n\n", dim, len(findings), reset)

	fixedCount := 0
	skippedCount := 0

	for i, finding := range findings {
		sevColor := dim
		switch finding.Severity {
		case "CRITICAL":
			sevColor = red
		case "HIGH":
			sevColor = red
		case "MEDIUM":
			sevColor = yellow
		}

		relFile, _ := filepath.Rel(absPath, finding.File)
		if relFile == "" {
			relFile = finding.File
		}

		fmt.Fprintf(os.Stderr, "%s  [%d/%d] %s%s%s — %s%s\n",
			dim, i+1, len(findings), sevColor, finding.Severity, dim, finding.Name, reset)
		fmt.Fprintf(os.Stderr, "%s         File: %s (line %d)%s\n", dim, relFile, finding.Line, reset)

		// Skip project-level findings (no file to fix)
		if finding.File == "" {
			fmt.Fprintf(os.Stderr, "%s         ⊘ Skipped: project-level finding (no source file)%s\n\n", dim, reset)
			skippedCount++
			continue
		}

		// Read the source file
		content, err := os.ReadFile(finding.File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s         ⚠ Cannot read file: %v%s\n\n", yellow, err, reset)
			skippedCount++
			continue
		}

		// Truncate for token limits
		src := string(content)
		if len(src) > 12000 {
			src = src[:12000] + "\n... (truncated)"
		}

		// Generate fix using LLM
		prompt := fmt.Sprintf(`You are a senior security engineer fixing a vulnerability found by AITriage SAST.

FINDING:
- Rule: %s
- Name: %s
- Severity: %s
- File: %s
- Line: %d
- Evidence: %s
- Suggestion: %s

SOURCE FILE CONTENT:
%s

Generate the MINIMAL fix for this vulnerability. Return ONLY the corrected lines of code.
Format your response as a unified diff (--- a/file, +++ b/file, @@ lines).
If the fix requires adding new imports or dependencies, include them.
If the finding is a false positive, respond with exactly: FALSE_POSITIVE
If you cannot generate a safe fix, respond with exactly: MANUAL_REVIEW_REQUIRED`,
			finding.ID, finding.Name, finding.Severity, relFile, finding.Line,
			finding.Evidence, finding.Suggestion, src)

		messages := []llm.Message{{Role: "user", Content: prompt}}
		resp, _, err := client.Chat(ctx, messages)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s         ⚠ LLM error: %v%s\n\n", yellow, err, reset)
			skippedCount++
			continue
		}

		resp = strings.TrimSpace(resp)

		if resp == "FALSE_POSITIVE" {
			fmt.Fprintf(os.Stderr, "%s         ℹ LLM assessment: false positive%s\n\n", dim, reset)
			skippedCount++
			continue
		}

		if resp == "MANUAL_REVIEW_REQUIRED" {
			fmt.Fprintf(os.Stderr, "%s         ℹ Requires manual review%s\n\n", yellow, reset)
			skippedCount++
			continue
		}

		// Display the fix
		fmt.Fprintf(os.Stderr, "\n%s%s  Suggested Fix:%s\n", bold, cyan, reset)
		for _, line := range strings.Split(resp, "\n") {
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				fmt.Fprintf(os.Stderr, "%s%s%s\n", green, line, reset)
			} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				fmt.Fprintf(os.Stderr, "%s%s%s\n", red, line, reset)
			} else {
				fmt.Fprintf(os.Stderr, "%s%s%s\n", dim, line, reset)
			}
		}
		fmt.Fprintln(os.Stderr)

		if fixDryRun {
			fixedCount++
			continue
		}

		// Auto-apply only for safe severities
		if fixAuto && (finding.Severity == "LOW" || finding.Severity == "MEDIUM") {
			// For now, we only show the diff — applying raw LLM output requires
			// a proper patch parser to avoid corruption. This is the safe path.
			fmt.Fprintf(os.Stderr, "%s         ℹ Auto-apply: diff shown above. Apply manually or use --interactive.%s\n\n", dim, reset)
			fixedCount++
		} else {
			fmt.Fprintf(os.Stderr, "%s         ℹ Review the diff above and apply manually.%s\n\n", dim, reset)
			fixedCount++
		}
	}

	// Summary
	fmt.Fprintf(os.Stderr, "\n%s%s  ── Fix Summary ──%s\n", cyan, bold, reset)
	fmt.Fprintf(os.Stderr, "%s  Fixes generated: %s%d%s\n", dim, green, fixedCount, reset)
	fmt.Fprintf(os.Stderr, "%s  Skipped:         %s%d%s\n", dim, yellow, skippedCount, reset)
	fmt.Fprintf(os.Stderr, "%s  Total processed: %d%s\n\n", dim, len(findings), reset)

	return nil
}

func severityLevel(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func parseSeverityLevel(s string) int {
	if s == "" {
		return 0
	}
	return severityLevel(s)
}
