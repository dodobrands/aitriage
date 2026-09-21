package external

import (
	"context"
	"encoding/json"
	"fmt"
)

type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
			Description     string `json:"Description"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// RunTrivy runs trivy and returns unified findings.
// scanType: "fs" (filesystem) or "config" (IaC configs)
func RunTrivy(ctx context.Context, path, scanType string) ([]UnifiedFinding, error) {
	if !IsInstalled("trivy") {
		return nil, fmt.Errorf("trivy not installed")
	}
	if scanType == "" {
		scanType = "fs"
	}
	args := []string{scanType, "--format", "json", "--quiet"}
	args = append(args, TrivySkipDirArgs(path)...)
	args = append(args, path)
	result, err := RunTool(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}
	var output trivyOutput
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}
	var findings []UnifiedFinding
	for _, res := range output.Results {
		if isGeneratedArtifactPath(res.Target) {
			continue
		}
		for _, v := range res.Vulnerabilities {
			findings = append(findings, UnifiedFinding{
				Source:   "trivy",
				RuleID:   v.VulnerabilityID,
				Severity: v.Severity,
				Message:  fmt.Sprintf("%s: %s", v.Title, v.Description),
				File:     res.Target,
			})
		}
	}
	return findings, nil
}
