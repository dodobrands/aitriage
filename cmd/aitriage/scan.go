package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/history"
	"github.com/dodobrands/aitriage/internal/healthpolicy"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/report/reporter"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/diff"
	"github.com/dodobrands/aitriage/internal/ui/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	scanStack      string
	scanFormat     string
	scanOutputFile string
	universalOnly  bool
	failOn         string
	failScore      int
	healthProfile  string
	noHistory      bool
	interactive    bool
	useBaseline    bool
	diffRef        string
	stagedOnly     bool
	noSummary      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for security presence checks",
	Long:  `Scan a directory to identify missing architectural security practices.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}

		// ── Docker auto-escalation (must be FIRST, before spinner) ────────
		// If external scanners are missing and Docker is available,
		// transparently re-launch inside a container. User never sees Docker.
		if interactive && dockerEscalate(path) {
			return nil
		}

		var stopSpinner chan struct{}
		var spinnerDone chan struct{}
		if scanFormat == "terminal" {
			stopSpinner = make(chan struct{})
			spinnerDone = make(chan struct{})
			go func() {
				defer close(spinnerDone)

				// ── DESIGN.md Color Palette (ANSI 256/TrueColor) ──────────
				cyan := "\033[38;2;0;245;255m"    // primary-container #00f5ff
				cyanDim := "\033[38;2;0;220;229m" // primary-fixed-dim #00dce5
				gray := "\033[38;2;132;148;149m"  // outline #849495
				text := "\033[38;2;220;228;228m"  // on-surface #dce4e4
				accent := "\033[38;2;231;196;39m" // tertiary-fixed-dim #e7c427
				blue := "\033[38;2;184;195;255m"  // secondary #b8c3ff
				bold := "\033[1m"
				reset := "\033[0m"
				clearLn := "\r\033[K"

				// Phase 1: Logo reveal (fast)
				logo := []string{
					cyan + bold + "    ╔═══════════════════════════════════╗" + reset,
					cyan + bold + "    ║" + reset + "  " + text + bold + "▄▀▄ ▀ ▀█▀ █▀▄ ▀ ▄▀▄ ▄▀▀ █▀▀" + reset + "  " + cyan + bold + "║" + reset,
					cyan + bold + "    ║" + reset + "  " + text + bold + "█▀█ █  █  █▀▄ █ █▀█ █ █ █▀▀" + reset + "  " + cyan + bold + "║" + reset,
					cyan + bold + "    ║" + reset + "  " + text + bold + "▀ ▀ ▀  ▀  ▀ ▀ ▀ ▀ ▀  ▀▀ ▀▀▀" + reset + "  " + cyan + bold + "║" + reset,
					cyan + bold + "    ╚═══════════════════════════════════╝" + reset,
				}

				// Print logo with staggered reveal
				fmt.Print("\033[?25l") // hide cursor
				for _, line := range logo {
					select {
					case <-stopSpinner:
						fmt.Print("\033[?25h") // show cursor
						fmt.Print(clearLn)
						return
					default:
					}
					fmt.Println(line)
					time.Sleep(60 * time.Millisecond)
				}
				fmt.Println()

				// Phase 2 & 3: Unified Cinematic Boot Sequence
				stages := []struct {
					label string
					color string
					delay time.Duration
				}{
					{"Initializing rule engine", cyanDim, 400 * time.Millisecond},
					{"Loading stack detectors", blue, 350 * time.Millisecond},
					{"Connecting SAST scanners", accent, 300 * time.Millisecond},
					{"Mounting security policies", cyan, 250 * time.Millisecond},
					{"Preparing AI analysis layer", text, 300 * time.Millisecond},
				}

				totalLines := len(stages) + 2 // 5 stages + 1 blank line + 1 progress bar

				// Pre-allocate space by printing newlines
				for i := 0; i < totalLines; i++ {
					fmt.Println()
				}

				frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
				thinkPhrases := []string{
					"Analyzing code patterns",
					"Evaluating attack surface",
					"Cross-referencing CVE database",
					"Mapping dependency graph",
					"Detecting hardcoded secrets",
					"Scanning container configs",
					"Validating auth mechanisms",
					"Checking encryption standards",
				}

				currentStage := 0
				stageStartTime := time.Now()
				i := 0

				for {
					select {
					case <-stopSpinner:
						// Clean up the pre-allocated space smoothly
						fmt.Printf("\033[%dA", totalLines)
						fmt.Print("\033[J")    // Clear from cursor to end of screen
						fmt.Print("\033[?25h") // Show cursor
						return
					default:
						// Move cursor up to start of our block
						fmt.Printf("\033[%dA", totalLines)

						// Advance stages based on delay
						if currentStage < len(stages) {
							if time.Since(stageStartTime) >= stages[currentStage].delay {
								currentStage++
								stageStartTime = time.Now()
							}
						}

						// Draw Stages
						for j, stage := range stages {
							if j < currentStage {
								fmt.Printf("    %s✓%s   %s%s%s\033[K\n", cyan, reset, gray, stage.label, reset)
							} else if j == currentStage {
								fmt.Printf("    %s%s%s   %s%s%s\033[K\n", stage.color, frames[i%len(frames)], reset, text, stage.label, reset)
							} else {
								fmt.Printf("    %s·%s   %s%s%s\033[K\n", gray, reset, gray, stage.label, reset)
							}
						}

						fmt.Printf("\033[K\n") // Blank line

						// Draw Progress Bar (Phase 2 or Phase 3)
						if currentStage < len(stages) {
							// Phase 2: mini loading bar for current stage
							bar := ""
							barLen := 30
							// Calculate fake progress 0-30 based on elapsed time vs delay
							elapsed := time.Since(stageStartTime)
							progress := int((elapsed.Seconds() / stages[currentStage].delay.Seconds()) * float64(barLen))
							if progress > barLen {
								progress = barLen
							}
							for b := 0; b < barLen; b++ {
								if b <= progress {
									bar += stages[currentStage].color + "█" + reset
								} else {
									bar += gray + "░" + reset
								}
							}
							fmt.Printf("    %s%s%s %s%s%s %s\033[K\n",
								stages[currentStage].color, frames[i%len(frames)], reset,
								text, stages[currentStage].label, reset,
								bar,
							)
						} else {
							// Phase 3: Infinite scanning pulse
							phrase := thinkPhrases[(i/12)%len(thinkPhrases)]
							barLen := 30
							pos := i % (barLen * 2)
							if pos >= barLen {
								pos = barLen*2 - pos
							}
							bar := ""
							for b := 0; b < barLen; b++ {
								dist := b - pos
								if dist < 0 {
									dist = -dist
								}
								if dist <= 2 {
									bar += cyan + "█" + reset
								} else if dist <= 4 {
									bar += cyanDim + "▓" + reset
								} else {
									bar += gray + "░" + reset
								}
							}
							fmt.Printf("    %s%s%s %s%-30s%s %s\033[K\n",
								cyan, frames[i%len(frames)], reset,
								text, phrase+"...", reset,
								bar,
							)
						}

						time.Sleep(80 * time.Millisecond)
						i++
					}
				}
			}()
		}

		// Load previous scan for diff (before scanning so we don't pick up this run)
		var prevRecord *history.ScanRecord
		if !noHistory {
			prevRecord, _ = history.LoadLast(path)
		}

		if interactive && term.IsTerminal(int(os.Stdout.Fd())) {
			// Always show file browser first — user selects what to scan.
			// If a path was given on CLI, open the browser in that directory.
			if stopSpinner != nil {
				close(stopSpinner)
				<-spinnerDone
			}
			fmt.Print("\033[2J\033[H")

			lipgloss.SetHasDarkBackground(true)
			m := tui.InitialBrowserModel(path, Version)
			p := tea.NewProgram(&m, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
				os.Exit(1)
			}
			return nil
		}

		// ── Diff / Staged file filtering ─────────────────────────────
		var fileFilter []string
		if stagedOnly {
			files, err := diff.StagedFiles(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ Failed to get staged files: %v\n", err)
			} else {
				fileFilter = files
				if len(files) == 0 {
					fmt.Fprintln(os.Stderr, "No staged files to scan.")
					return nil
				}
			}
		} else if diffRef != "" {
			files, err := diff.ChangedFiles(path, diffRef)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ Failed to get diff files: %v\n", err)
			} else {
				fileFilter = files
				if len(files) == 0 {
					fmt.Fprintln(os.Stderr, "No changed files to scan.")
					return nil
				}
			}
		}

		report, err := scanner.Scan(context.Background(), path, scanner.ScanOptions{
			ForceStack:    scanStack,
			UniversalOnly: universalOnly,
			FileFilter:    fileFilter,
		})

		if stopSpinner != nil {
			close(stopSpinner)
			<-spinnerDone
		}

		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		policy := scanPolicyFromFlags(cmd, report)

		// ── Baseline filtering ─────────────────────────────────────────
		if useBaseline {
			b, bErr := baseline.Load(path)
			if bErr != nil {
				fmt.Fprintf(os.Stderr, "⚠ Failed to load baseline: %v\n", bErr)
			} else if b == nil {
				fmt.Fprintln(os.Stderr, "⚠ No baseline found. Run 'aitriage baseline create .' first.")
			} else {
				fr := baseline.FilterInProject(path, report.Results, b)
				report.Results = fr.New
				if len(fr.Baseline) > 0 {
					fmt.Fprintf(os.Stderr, "  [baseline] %d findings suppressed (%d new)\n", len(fr.Baseline), len(fr.New))
				}
			}
		}
		refreshScanHealthCheck(&report, policy)

		var outWriter io.Writer = os.Stdout
		if scanOutputFile != "" {
			f, err := os.Create(scanOutputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer func() { _ = f.Close() }()
			outWriter = f

			// If we're writing structured format to a file, we should still display the gorgeous UI
			reporter.PrintTerminal(report)
		}

		switch scanFormat {
		case "json":
			reporter.PrintJSON(report, outWriter)
		case "sarif":
			reporter.PrintSARIF(report, outWriter)
		case "html":
			criticalCount := 0
			for _, r := range report.Results {
				if r.Severity == "CRITICAL" {
					criticalCount++
				}
			}
			stackNames := make([]string, len(report.Stacks))
			for i, s := range report.Stacks {
				stackNames[i] = string(s)
			}
			outName := "aitriage-report.html"
			if scanOutputFile != "" {
				outName = scanOutputFile
			}
			err := reporter.GenerateHTMLReport(outName, reporter.ReportData{
				SecurityGrade: report.SecurityGrade,
				CriticalCount: criticalCount,
				Stacks:        stackNames,
				Results:       report.Results,
			})
			if err != nil {
				_, _ = os.Stderr.WriteString("Failed to generate HTML report: " + err.Error() + "\n")
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "Report generated: %s\n", outName)
			}
		default:
			// If they didn't specify a file, or if they specified a file but asked for terminal format
			// (which makes no sense, but whatever), print it once.
			if scanOutputFile == "" {
				reporter.PrintTerminal(report)
			}
			// If scanOutputFile was given, terminal format is not written to it.
		}

		// Show diff against previous scan
		if !noHistory && prevRecord != nil {
			diffs := history.Diff(prevRecord.Report, report)
			if len(diffs) > 0 || prevRecord.Report.SecurityScore != report.SecurityScore {
				fmt.Println("\n── Diff vs previous scan (" + prevRecord.Timestamp.Format("2006-01-02 15:04") + ") ──")
				fmt.Println(history.FormatDiff(diffs, prevRecord.Report.SecurityScore, report.SecurityScore))
			}
		}

		// Save scan to history
		if !noHistory {
			if savedPath, err := history.Save(path, report); err == nil {
				fmt.Fprintf(os.Stderr, "  [history] Saved → %s\n", savedPath)
			}
		}

		// ── GitHub Actions integration ────────────────────────────────
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			printGitHubActionsAnnotations(report)
			if !noSummary {
				writeGitHubActionsSummary(report)
			}
		}

		if !report.HealthCheck.Verdict.Passed {
			printPolicyFailure(os.Stderr, report.HealthCheck.Verdict)
			cmd.SilenceErrors = true
			return ErrPolicyViolation
		}
		return nil
	},
}

func scanPolicyFromFlags(cmd *cobra.Command, report scanner.ScanReport) healthcheck.Policy {
	policy := healthpolicy.FromConfig(report.Config)
	return healthpolicy.ApplyOverrides(policy, healthpolicy.Overrides{
		Profile:         healthProfile,
		ProfileSet:      cmd.Flags().Changed("health-profile"),
		FailOn:          failOn,
		FailOnSet:       cmd.Flags().Changed("fail-on"),
		MinimumScore:    failScore,
		MinimumScoreSet: cmd.Flags().Changed("fail-score"),
	})
}

func refreshScanHealthCheck(report *scanner.ScanReport, policy healthcheck.Policy) {
	hc := healthcheck.ApplyPolicy(
		healthcheck.Evaluate(healthcheck.FromCoreResults(report.Results)),
		policy,
	)
	report.HealthCheck = hc
	report.HasCriticalFailures = hc.HasCriticalFailures
	report.SecurityScore = hc.Score
	report.SecurityGrade = hc.Grade
}

func printPolicyFailure(w io.Writer, verdict healthcheck.Verdict) {
	_, _ = fmt.Fprintf(w, "\nFAIL: %s\n", verdict.Summary)
	for _, reason := range verdict.BlockingReasons {
		_, _ = fmt.Fprintf(w, "- %s", reason.Code)
		if reason.Severity != "" {
			_, _ = fmt.Fprintf(w, " severity=%s", reason.Severity)
		}
		if reason.Source != "" {
			_, _ = fmt.Fprintf(w, " source=%s", reason.Source)
		}
		if reason.Class != "" {
			_, _ = fmt.Fprintf(w, " class=%s", reason.Class)
		}
		if reason.Threshold != 0 || reason.Count != 0 {
			_, _ = fmt.Fprintf(w, " count=%d threshold=%d", reason.Count, reason.Threshold)
		}
		_, _ = fmt.Fprintf(w, " - %s\n", reason.Message)
	}
}

func printGitHubActionsAnnotations(report scanner.ScanReport) {
	for _, r := range report.Results {
		if isSuppressedResult(r) {
			continue
		}
		relPath := r.File
		if relPath != "" && filepath.IsAbs(relPath) {
			if rel, err := filepath.Rel(report.ProjectPath, relPath); err == nil {
				relPath = rel
			}
		}

		severity := "warning"
		if r.Severity == "CRITICAL" || r.Severity == "HIGH" {
			severity = "error"
		}

		if r.File == "" {
			fmt.Printf("::%s::[%s] %s - %s\n", severity, r.ID, r.Name, r.Suggestion)
		} else {
			line := r.Line
			if line <= 0 {
				line = 1
			}
			fmt.Printf("::%s file=%s,line=%d::[%s] %s - %s\n", severity, relPath, line, r.ID, r.Name, r.Suggestion)
		}
	}
}

func isSuppressedResult(r core.CheckResult) bool {
	return r.AuditStatus == core.AuditStatusIgnored || r.AuditStatus == core.AuditStatusTriage
}

func writeGitHubActionsSummary(report scanner.ScanReport) {
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		return
	}

	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	_, _ = f.WriteString("## AITriage Security Scan Summary\n\n")
	_, _ = fmt.Fprintf(f, "**Security Gate:** %s\n\n", strings.ToUpper(report.HealthCheck.Verdict.Status))
	_, _ = fmt.Fprintf(f, "**Policy:** `%s` (`fail_on=%s`)\n\n", report.HealthCheck.Policy.Profile, report.HealthCheck.Policy.FailOn)
	_, _ = fmt.Fprintf(f, "**Health Check:** %d/100 (%s)\n\n", report.SecurityScore, report.SecurityGrade)
	hb := report.HealthCheck.Breakdown
	_, _ = fmt.Fprintf(f, "_%d active findings · %d ignored (false positives) · %d deduplicated · penalty %d · bonus %d_\n\n", hb.ActiveFindings, hb.IgnoredFindings, hb.DedupedFindings, hb.Penalty, hb.Bonus)
	if len(report.HealthCheck.Verdict.BlockingReasons) > 0 {
		_, _ = f.WriteString("### Blocking Reasons\n\n")
		for _, reason := range report.HealthCheck.Verdict.BlockingReasons {
			_, _ = fmt.Fprintf(f, "- `%s`: %s", reason.Code, reason.Message)
			if reason.Count != 0 || reason.Threshold != 0 {
				_, _ = fmt.Fprintf(f, " (count %d, threshold %d)", reason.Count, reason.Threshold)
			}
			_, _ = f.WriteString("\n")
		}
		_, _ = f.WriteString("\n")
	}

	if report.HealthCheck.Breakdown.ActiveFindings == 0 {
		_, _ = f.WriteString("No active security issues found.\n")
		return
	}

	var codeFindings []core.CheckResult
	var archFindings []core.CheckResult

	for _, r := range report.Results {
		if isSuppressedResult(r) {
			continue
		}
		if r.File == "" {
			archFindings = append(archFindings, r)
		} else {
			codeFindings = append(codeFindings, r)
		}
	}

	if len(codeFindings) > 0 {
		_, _ = f.WriteString("### Code-Level Vulnerabilities\n\n")
		_, _ = f.WriteString("| Severity | Rule ID | File | Line | Recommendation |\n")
		_, _ = f.WriteString("|----------|---------|------|------|----------------|\n")
		for _, r := range codeFindings {
			relPath := r.File
			if relPath != "" && filepath.IsAbs(relPath) {
				if rel, err := filepath.Rel(report.ProjectPath, relPath); err == nil {
					relPath = rel
				}
			}
			msg := strings.ReplaceAll(r.Suggestion, "|", "\\|")
			msg = strings.ReplaceAll(msg, "\n", " ")
			msg = strings.ReplaceAll(msg, "\r", "")

			_, _ = fmt.Fprintf(f, "| %s | %s | %s | %d | %s |\n", r.Severity, r.ID, relPath, r.Line, msg)
		}
		_, _ = f.WriteString("\n")
	}

	if len(archFindings) > 0 {
		_, _ = f.WriteString("### Project-Level & Architectural Issues\n\n")
		_, _ = f.WriteString("| Severity | Rule ID | Issue | Recommendation |\n")
		_, _ = f.WriteString("|----------|---------|-------|----------------|\n")
		for _, r := range archFindings {
			msg := strings.ReplaceAll(r.Suggestion, "|", "\\|")
			msg = strings.ReplaceAll(msg, "\n", " ")
			msg = strings.ReplaceAll(msg, "\r", "")

			name := strings.ReplaceAll(r.Name, "|", "\\|")

			_, _ = fmt.Fprintf(f, "| %s | %s | %s | %s |\n", r.Severity, r.ID, name, msg)
		}
		_, _ = f.WriteString("\n")
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&scanStack, "stack", "", "Force specific stack (e.g., nextjs, fastapi)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "terminal", "Output format: terminal, json, sarif, html")
	scanCmd.Flags().StringVarP(&scanOutputFile, "out", "o", "", "Write formatted output to a file (and display terminal output on stdout)")
	scanCmd.Flags().BoolVar(&universalOnly, "universal-only", false, "Run only universal checks (no stack-specific)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "critical", "When to exit with code 1: critical (default), any, never")
	scanCmd.Flags().IntVar(&failScore, "fail-score", 0, "Fail if Health Check score is below this threshold (0 = disabled)")
	scanCmd.Flags().StringVar(&healthProfile, "health-profile", "", "Health Check policy profile: baseline, standard, strict")
	scanCmd.Flags().BoolVar(&noHistory, "no-history", false, "Skip saving scan results to history (disables diff)")
	scanCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Launch interactive TUI dashboard")
	scanCmd.Flags().BoolVar(&useBaseline, "baseline", false, "Report only NEW findings not in the baseline")
	scanCmd.Flags().StringVar(&diffRef, "diff", "", "Scan only files changed vs a git ref (e.g., HEAD~1, origin/main)")
	scanCmd.Flags().BoolVar(&stagedOnly, "staged", false, "Scan only git-staged files (for pre-commit hooks)")
	scanCmd.Flags().BoolVar(&noSummary, "no-summary", false, "Disable writing to GITHUB_STEP_SUMMARY")
}
