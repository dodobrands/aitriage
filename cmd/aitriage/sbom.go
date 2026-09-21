package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dodobrands/aitriage/internal/report/sbom"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	sbomFormat string
	sbomOutput string
)

var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Generate Software Bill of Materials (SBOM)",
	Long: `Generate an SBOM from the project's dependency graph.

  aitriage sbom .                           → CycloneDX to stdout
  aitriage sbom . --format spdx             → SPDX format
  aitriage sbom . --format cyclonedx -o sbom.json → Save to file`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSBOM,
}

func init() {
	rootCmd.AddCommand(sbomCmd)
	sbomCmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx", "Output format: cyclonedx, spdx, json")
	sbomCmd.Flags().StringVarP(&sbomOutput, "output", "o", "", "Output file (default: stdout)")
}

func runSBOM(cmd *cobra.Command, args []string) error {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	ctx := context.Background()

	// Run scan to get dependencies
	report, err := scanner.Scan(ctx, projectPath, scanner.ScanOptions{})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	var output []byte

	switch strings.ToLower(sbomFormat) {
	case "cyclonedx", "cdx":
		output, err = sbom.CycloneDX(report, projectPath)
	case "spdx":
		output, err = sbom.SPDX(report, projectPath)
	case "json":
		output, err = sbom.SimpleJSON(report)
	default:
		return fmt.Errorf("unsupported format: %s (use: cyclonedx, spdx, json)", sbomFormat)
	}

	if err != nil {
		return err
	}

	if sbomOutput != "" {
		if err := os.WriteFile(sbomOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "✅ SBOM written to %s (%d components, %s format)\n", sbomOutput, len(report.Dependencies), sbomFormat)
		return nil
	}

	fmt.Print(string(output))
	return nil
}
