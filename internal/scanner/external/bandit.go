package external

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type banditOutput struct {
	Results []struct {
		TestID    string `json:"test_id"`
		TestName  string `json:"test_name"`
		Severity  string `json:"issue_severity"`
		Text      string `json:"issue_text"`
		Filename  string `json:"filename"`
		LineRange []int  `json:"line_range"`
	} `json:"results"`
}

// RunBandit runs bandit (Python SAST) and returns unified findings.
func RunBandit(ctx context.Context, path string) ([]UnifiedFinding, error) {
	if !IsInstalled("bandit") {
		return nil, fmt.Errorf("bandit not installed")
	}
	excluded := banditExcludePaths(path)
	result, err := RunTool(ctx, "bandit", "-r", path, "-f", "json", "-q", "-x", strings.Join(excluded, ","))
	if err != nil {
		return nil, fmt.Errorf("bandit execution failed: %w", err)
	}
	var output banditOutput
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}
	findings := make([]UnifiedFinding, 0, len(output.Results))
	for _, r := range output.Results {
		if isGeneratedArtifactPath(r.Filename) {
			continue
		}
		line := 0
		if len(r.LineRange) > 0 {
			line = r.LineRange[0]
		}
		findings = append(findings, UnifiedFinding{
			Source:   "bandit",
			RuleID:   r.TestID,
			Severity: r.Severity,
			Message:  fmt.Sprintf("%s: %s", r.TestName, r.Text),
			File:     r.Filename,
			Line:     line,
		})
	}
	return findings, nil
}
