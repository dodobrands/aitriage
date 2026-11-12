package external

import (
	"context"
	"encoding/json"
	"fmt"
)

type gitleaksOutput []struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Secret      string `json:"Secret"`
}

// RunGitleaks runs gitleaks and returns unified findings.
func RunGitleaks(ctx context.Context, path string) ([]UnifiedFinding, error) {
	if !IsInstalled("gitleaks") {
		return nil, fmt.Errorf("gitleaks not installed")
	}
	config, cleanup, err := newGitleaksConfig(path)
	if err != nil {
		return nil, fmt.Errorf("prepare gitleaks generated-artifact exclusion: %w", err)
	}
	defer cleanup()
	result, err := RunTool(ctx, "gitleaks", "detect", "--source", path,
		"--config", config, "--report-format", "json", "--report-path", "-",
		"--no-git", "--no-banner", "--redact=100")
	if err != nil {
		return nil, fmt.Errorf("gitleaks execution failed: %w", err)
	}
	if result.Stdout == "" || result.Stdout == "null" {
		return []UnifiedFinding{}, nil
	}
	var output gitleaksOutput
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}
	findings := make([]UnifiedFinding, 0, len(output))
	for _, r := range output {
		if isGeneratedArtifactPath(r.File) {
			continue
		}
		findings = append(findings, UnifiedFinding{
			Source:   "gitleaks",
			RuleID:   r.RuleID,
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("%s: %s", r.Description, maskSecret(r.Secret)),
			File:     r.File,
			Line:     r.StartLine,
		})
	}
	return findings, nil
}

func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}
