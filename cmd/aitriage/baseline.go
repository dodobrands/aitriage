package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage security baseline — accept current findings to track regressions only",
	Long: `Baseline management for legacy codebases.
  
  aitriage baseline create .   → Scan and accept all current findings
  aitriage baseline show .     → Show what's in the current baseline
  aitriage baseline update .   → Re-scan and update the baseline
  aitriage baseline clear .    → Remove the baseline file`,
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create [path]",
	Short: "Create a baseline from current scan findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineCreate,
}

var baselineShowCmd = &cobra.Command{
	Use:   "show [path]",
	Short: "Show current baseline statistics",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineShow,
}

var baselineUpdateCmd = &cobra.Command{
	Use:   "update [path]",
	Short: "Re-scan and update the baseline with current findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineUpdate,
}

var baselineClearCmd = &cobra.Command{
	Use:   "clear [path]",
	Short: "Remove the baseline file",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineClear,
}

func init() {
	rootCmd.AddCommand(baselineCmd)
	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineShowCmd)
	baselineCmd.AddCommand(baselineUpdateCmd)
	baselineCmd.AddCommand(baselineClearCmd)
}

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	projectPath := args[0]
	ctx := context.Background()

	cyan := "\033[38;2;0;245;255m"
	green := "\033[38;2;46;204;113m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "\n%s%s  ⦿ AITriage Baseline — Creating...%s\n\n", cyan, bold, reset)

	// Check if baseline already exists
	existing, _ := baseline.Load(projectPath)
	if existing != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Baseline already exists (%d findings). Use 'baseline update' to refresh.\n", len(existing.Findings))
		fmt.Fprintf(os.Stderr, "  Use '--force' on scan to overwrite.\n\n")
	}

	// Every scanner, not just the built-in engine: on a real project most of the
	// noise a baseline exists to absorb comes from Semgrep, Trivy and Gitleaks.
	fmt.Fprintf(os.Stderr, "  Scanning project...\n")
	rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
		ProjectPath: projectPath,
		RunExternal: true,
	})

	b := baseline.NewFromItems(orchestrator.BaselineItems(&rich))

	if err := baseline.Save(projectPath, b); err != nil {
		return fmt.Errorf("failed to save baseline: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s%s  ✅ Baseline created: %d findings accepted%s\n", green, bold, len(b.Findings), reset)
	fmt.Fprintf(os.Stderr, "  Saved to: %s/%s\n", projectPath, baseline.BaselineFile)
	fmt.Fprintf(os.Stderr, "\n  Run %saitriage scan %s --baseline%s to report only NEW findings.\n\n", bold, projectPath, reset)

	return nil
}

func runBaselineShow(cmd *cobra.Command, args []string) error {
	projectPath := args[0]

	b, err := baseline.Load(projectPath)
	if err != nil {
		return fmt.Errorf("failed to load baseline: %w", err)
	}
	if b == nil {
		fmt.Println("No baseline found. Run 'aitriage baseline create .' first.")
		return nil
	}

	fmt.Println(b.FormatStats())
	return nil
}

func runBaselineUpdate(cmd *cobra.Command, args []string) error {
	projectPath := args[0]
	ctx := context.Background()

	cyan := "\033[38;2;0;245;255m"
	green := "\033[38;2;46;204;113m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "\n%s%s  ⦿ AITriage Baseline — Updating...%s\n\n", cyan, bold, reset)

	// Load existing baseline for comparison
	prev, _ := baseline.Load(projectPath)

	fmt.Fprintf(os.Stderr, "  Scanning project...\n")
	rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
		ProjectPath: projectPath,
		RunExternal: true,
	})

	b := baseline.NewFromItems(orchestrator.BaselineItems(&rich))
	if prev != nil {
		// Keep the original creation date: it records how long the project has
		// been operating against a baseline.
		b.CreatedAt = prev.CreatedAt
	}

	if err := baseline.Save(projectPath, b); err != nil {
		return fmt.Errorf("failed to save baseline: %w", err)
	}

	delta := ""
	if prev != nil {
		diff := len(b.Findings) - len(prev.Findings)
		if diff > 0 {
			delta = fmt.Sprintf(" (+%d new)", diff)
		} else if diff < 0 {
			delta = fmt.Sprintf(" (%d fixed)", -diff)
		} else {
			delta = " (no change)"
		}
	}

	fmt.Fprintf(os.Stderr, "\n%s%s  ✅ Baseline updated: %d findings%s%s\n\n", green, bold, len(b.Findings), delta, reset)
	return nil
}

func runBaselineClear(cmd *cobra.Command, args []string) error {
	projectPath := args[0]
	path := projectPath + "/" + baseline.BaselineFile

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No baseline to remove.")
			return nil
		}
		return err
	}

	fmt.Println("✅ Baseline removed.")
	return nil
}
