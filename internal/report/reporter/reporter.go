package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/fatih/color"
)

// PrintTerminal formats the ScanReport nicely for the terminal.
func PrintTerminal(report scanner.ScanReport) {
	fmt.Println()

	banner := `
   ___  _____________      _                
  / _ |/  _/_  __/ _ \____(_)__ ____ ____   
 / __ |/ /  / / / , _/ __/ / _ \/ _ \/ -_)  
/_/ |_/___/ /_/ /_/|_\__/_/\_,_/\_, /\__/   
                               /___/        
`
	if _, err := color.New(color.FgHiCyan, color.Bold).Println(banner); err != nil {
		fmt.Println(banner)
	}
	if _, err := color.New(color.BgBlack, color.FgHiBlue, color.Bold).Println("  AITRIAGE ENTERPRISE SAST ENGINE V1.0  "); err != nil {
		fmt.Println("  AITRIAGE ENTERPRISE SAST ENGINE V1.0  ")
	}
	fmt.Println("-------------------------------------------")
	fmt.Printf(" [STX] Stacks: %v\n", report.Stacks)

	scoreColor := color.FgGreen
	if report.SecurityScore < 80 {
		scoreColor = color.FgYellow
	}
	if report.SecurityScore < 50 {
		scoreColor = color.FgRed
	}

	barWidth := 20
	filled := (report.SecurityScore * barWidth) / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Printf(" [HC] Health Check: ")
	if _, err := color.New(scoreColor, color.Bold).Printf("%d/100 [%s]\n", report.SecurityScore, report.SecurityGrade); err != nil {
		fmt.Printf("%d/100 [%s]\n", report.SecurityScore, report.SecurityGrade)
	}
	if _, err := color.New(scoreColor).Printf("       [%s]\n", bar); err != nil {
		fmt.Printf("       [%s]\n", bar)
	}
	hb := report.HealthCheck.Breakdown
	fmt.Printf("       %d active (%d confirmed · %d unreviewed) · %d ignored (FP) · %d deduped · penalty %d · bonus %d\n",
		hb.ActiveFindings, hb.ConfirmedFindings, hb.NeedsReviewFindings,
		hb.IgnoredFindings, hb.DedupedFindings, hb.Penalty, hb.Bonus)
	fmt.Println("----------------------------------------")

	for _, r := range report.Results {
		switch r.Status {
		case core.Present:
			if _, err := color.New(color.FgHiGreen).Printf(" ✔ [%s] %s\n", r.ID, r.Name); err != nil {
				fmt.Printf(" ✔ [%s] %s\n", r.ID, r.Name)
			}
		case core.Unknown:
			if _, err := color.New(color.FgHiYellow).Printf(" ? [%s] %s\n", r.ID, r.Name); err != nil {
				fmt.Printf(" ? [%s] %s\n", r.ID, r.Name)
			}
			fmt.Printf("   » Suggestion: %s\n", r.Suggestion)
		default:
			if _, err := color.New(color.FgHiRed).Printf(" ✘ [%s] %s\n", r.ID, r.Name); err != nil {
				fmt.Printf(" ✘ [%s] %s\n", r.ID, r.Name)
			}
			fmt.Printf("   » Issue: %s\n", r.Suggestion)
			if r.File != "" {
				if r.Line > 0 {
					fmt.Printf("   » Location: %s:%d\n", r.File, r.Line)
				} else {
					fmt.Printf("   » Location: %s\n", r.File)
				}
			} else if r.Line > 0 {
				fmt.Printf("   » At line: %d\n", r.Line)
			}
		}
	}

	fmt.Println("----------------------------------------")

	if report.HasCriticalFailures {
		if _, err := color.New(color.BgRed, color.FgWhite, color.Bold).Println("  STATUS: AUDIT FAILED (CRITICAL ISSUES)  "); err != nil {
			fmt.Println("  STATUS: AUDIT FAILED (CRITICAL ISSUES)  ")
		}
	} else {
		if _, err := color.New(color.BgGreen, color.FgBlack, color.Bold).Println("  STATUS: AUDIT PASSED (CLEAN)      "); err != nil {
			fmt.Println("  STATUS: AUDIT PASSED (CLEAN)      ")
		}
	}
	fmt.Println()
}

// PrintJSON outputs the ScanReport as JSON.
func PrintJSON(report scanner.ScanReport, w io.Writer) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
	}
}

// SarifReport represents the simplified SARIF structure
type SarifReport struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Message   Message    `json:"message"`
	Level     string     `json:"level,omitempty"`
	Locations []Location `json:"locations,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

type Message struct {
	Text string `json:"text"`
}

// PrintSARIF outputs the ScanReport in SARIF format.
func PrintSARIF(report scanner.ScanReport, w io.Writer) {
	data, err := report.ToSARIF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate SARIF JSON: %v\n", err)
		return
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write SARIF JSON: %v\n", err)
	}
}
