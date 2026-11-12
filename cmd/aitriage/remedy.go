package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dodobrands/aitriage/internal/agent/remedy"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/spf13/cobra"
)

var autofixApply bool

var autofixCmd = &cobra.Command{
	Use:   "autofix [path]",
	Short: "Automatically fix detected security issues",
	Long: `Scan a project and apply deterministic fixes for known security issues.

By default runs in DRY RUN mode — prints what would change without touching files.
Use --apply to write changes to disk.

Fixable rules:
  ENTR-17 / SECRET-*         — Move hardcoded secrets to env vars
  ENTR-18                    — Replace debug=True with env var check
  ENTR-02                    — Generate lockfile creation command
  FLASK-SSTI                 — Suggest passing values as template variables`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}

		fmt.Printf("\n🔍 Scanning %s for fixable issues...\n", path)
		report, err := scanner.Scan(context.Background(), path, scanner.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		fmt.Printf("   Found %d total issues in scan\n\n", len(report.Results))

		if autofixApply {
			fmt.Println("⚡ APPLY MODE — writing changes to disk")
		} else {
			fmt.Println("🔎 DRY RUN MODE — no files will be modified (use --apply to write)")
		}
		fmt.Println("─────────────────────────────────────────")

		results := remedy.AutoFix(report, autofixApply)

		applied := 0
		manual := 0
		for _, r := range results {
			if r.Applied {
				applied++
			} else if r.Err == nil {
				manual++
			}
		}

		fmt.Println("─────────────────────────────────────────")
		if autofixApply {
			fmt.Printf("\n✅ Auto-fixed: %d  |  📋 Manual review needed: %d\n\n", applied, manual)
		} else {
			fmt.Printf("\n📋 Would auto-fix: %d  |  🔧 Manual review needed: %d\n", len(results)-manual, manual)
			fmt.Printf("   Run with --apply to write changes\n\n")
		}

		// List issues that can't be auto-fixed
		fixableRules := map[string]bool{
			"ENTR-17": true, "ENTR-18": true, "ENTR-02": true, "FLASK-SSTI": true,
		}
		skipped := 0
		for _, r := range report.Results {
			if r.File != "" && !fixableRules[r.ID] && !remedy.IsSecretRule(r.ID) {
				skipped++
			}
		}
		if skipped > 0 {
			fmt.Printf("ℹ  %d issues require architectural decisions (no auto-fix available).\n", skipped)
			fmt.Printf("   Run 'aitriage scan %s' for full details.\n\n", path)
		}

		// Non-zero exit if unfixed critical issues remain after apply
		if autofixApply && report.HasCriticalFailures {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	autofixCmd.Flags().BoolVar(&autofixApply, "apply", false, "Write fixes to disk (default: dry run)")
	rootCmd.AddCommand(autofixCmd)
}
