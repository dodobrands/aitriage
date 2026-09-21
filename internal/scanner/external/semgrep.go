package external

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type semgrepOutput struct {
	Results []struct {
		RuleID string `json:"check_id"`
		Extra  struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
		Path  string `json:"path"`
		Start struct {
			Line int `json:"line"`
		} `json:"start"`
	} `json:"results"`
}

// RunSemgrep runs semgrep with a single config and returns unified findings.
// config: semgrep rules, e.g. "auto" or a path to a yaml file.
func RunSemgrep(ctx context.Context, path, config string) ([]UnifiedFinding, error) {
	if config == "" {
		config = "auto"
	}
	return RunSemgrepConfigs(ctx, path, nil, config)
}

// RunSemgrepConfigs runs semgrep with one or more configs simultaneously and
// returns unified findings. A canonical full audit passes "auto" alongside the
// trusted AITriage taint-rule config so registry rules and the built-in taint
// rules run in a single pass. taintRuleIDs is the set of canonical rule ids
// emitted by the trusted taint config; a matching check_id is normalized back to
// its canonical id so, e.g., FAST-XSS always surfaces as FAST-XSS regardless of
// how Semgrep qualifies it.
func RunSemgrepConfigs(ctx context.Context, path string, taintRuleIDs []string, configs ...string) ([]UnifiedFinding, error) {
	if !IsInstalled("semgrep") {
		return nil, fmt.Errorf("semgrep not installed")
	}
	if len(configs) == 0 {
		configs = []string{"auto"}
	}
	args := []string{"scan", "--json"}
	for _, c := range configs {
		if c == "" {
			continue
		}
		args = append(args, "--config", c)
	}
	args = append(args, SemgrepExcludeArgs()...)
	args = append(args, path)

	result, err := RunTool(ctx, "semgrep", args...)
	if err != nil {
		return nil, fmt.Errorf("semgrep execution failed: %w", err)
	}
	var output semgrepOutput
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	taint := make(map[string]bool, len(taintRuleIDs))
	for _, id := range taintRuleIDs {
		taint[id] = true
	}

	findings := make([]UnifiedFinding, 0, len(output.Results))
	for _, r := range output.Results {
		if isGeneratedArtifactPath(r.Path) {
			continue
		}
		findings = append(findings, UnifiedFinding{
			Source:   "semgrep",
			RuleID:   normalizeTaintRuleID(r.RuleID, taint),
			Severity: normalizeSeverity(r.Extra.Severity),
			Message:  r.Extra.Message,
			File:     r.Path,
			Line:     r.Start.Line,
		})
	}
	return findings, nil
}

// normalizeTaintRuleID maps a Semgrep check_id back to a canonical AITriage taint
// rule id. Semgrep reports the bare rule id for a single-file config, but may
// qualify it with the config path in other invocation modes; matching the final
// path/dotted segment keeps the emitted finding id stable and canonical.
func normalizeTaintRuleID(checkID string, taint map[string]bool) string {
	if len(taint) == 0 || taint[checkID] {
		return checkID
	}
	seg := checkID
	if i := strings.LastIndexAny(seg, "./"); i >= 0 {
		seg = seg[i+1:]
	}
	if taint[seg] {
		return seg
	}
	return checkID
}

func normalizeSeverity(s string) string {
	switch s {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	default:
		return s
	}
}
