package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// SARIF Format structs
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SarifMessage     `json:"shortDescription"`
	Help             SarifMessage     `json:"help"`
	Properties       *SarifProperties `json:"properties,omitempty"`
}

type SarifProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
	Level     string          `json:"level"`
}

type SarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	Uri   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// ToSARIF converts the ScanReport to the SARIF format required by GitHub code
// scanning. Paths, and the project root inside evidence, are project-relative.
//
// Dismissed findings (audit status ignored or triage) are left out. GitHub's
// SARIF upload does not honour SARIF suppressions, so a dismissed finding
// emitted as a suppressed result would come back as an open alert. Dismissals
// stay visible in triage-findings.json and the summary counts.
func (r ScanReport) ToSARIF() ([]byte, error) {
	r = r.WithRelativePaths()
	run := SarifRun{
		Tool: SarifTool{
			Driver: SarifDriver{
				Name:           "AITriage",
				Version:        "1.0.0", // Update with actual version later if needed
				InformationUri: "https://github.com/dodobrands/aitriage",
				Rules:          []SarifRule{},
			},
		},
		Results: []SarifResult{},
	}

	seenRules := make(map[string]bool)

	for _, res := range r.Results {
		if res.Status != core.Absent {
			continue
		}
		if res.AuditStatus == core.AuditStatusIgnored || res.AuditStatus == core.AuditStatusTriage {
			continue
		}
		if res.File == "" {
			// GitHub code scanning requires a location to display a result. Keep
			// project-level issues in terminal/JSON/summary output instead of
			// uploading location-less SARIF alerts.
			continue
		}

		if !seenRules[res.ID] {
			rule := SarifRule{
				ID:   res.ID,
				Name: res.Name,
				ShortDescription: SarifMessage{
					Text: res.Name,
				},
				Help: SarifMessage{
					Text:     fmt.Sprintf("%s\n\nSuggestion: %s", res.Evidence, res.Suggestion),
					Markdown: fmt.Sprintf("%s\n\n**Suggestion:** %s", res.Evidence, res.Suggestion),
				},
				Properties: &SarifProperties{
					SecuritySeverity: convertSeverity(res.Severity),
				},
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			seenRules[res.ID] = true
		}

		level := "warning"
		switch strings.ToUpper(res.Severity) {
		case "CRITICAL", "HIGH":
			level = "error"
		case "LOW":
			level = "note"
		}

		line := res.Line
		if line <= 0 {
			line = 1 // SARIF requires line > 0
		}

		result := SarifResult{
			RuleID: res.ID,
			Message: SarifMessage{
				Text: fmt.Sprintf("[%s] %s: %s", res.Severity, res.Name, res.Suggestion),
			},
			Level: level,
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							Uri: res.File,
						},
						Region: SarifRegion{
							StartLine: line,
						},
					},
				},
			},
		}
		run.Results = append(run.Results, result)
	}

	log := SarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []SarifRun{run},
	}

	return json.MarshalIndent(log, "", "  ")
}

// Map AITriage Severity to CVSS Score Scale (approximated for SARIF security-severity)
func convertSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.0"
	default:
		return "5.0"
	}
}
