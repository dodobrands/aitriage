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
	// Errors are the problems Semgrep met while scanning. It exits 0 with them,
	// so a run that completed may still have skipped part of a file.
	Errors []semgrepError `json:"errors"`
	// Version is the Semgrep version that produced the results.
	Version string `json:"version"`
}

// semgrepError is one entry of Semgrep's "errors" list.
type semgrepError struct {
	// Type is a string ("Timeout", "Syntax error") or an array whose first
	// element names the kind (["PartialParsing", [...]]).
	Type  json.RawMessage `json:"type"`
	Path  string          `json:"path"`
	Spans []struct {
		File string `json:"file"`
	} `json:"spans"`
}

// kind returns the error kind named by Type.
func (e semgrepError) kind() string {
	var name string
	if json.Unmarshal(e.Type, &name) == nil {
		return name
	}
	var tuple []json.RawMessage
	if json.Unmarshal(e.Type, &tuple) == nil && len(tuple) > 0 && json.Unmarshal(tuple[0], &name) == nil {
		return name
	}
	return ""
}

// file returns the file the error is about, or "" for an error that is not
// about one file (a rule that failed to load, a network problem).
func (e semgrepError) file() string {
	if strings.TrimSpace(e.Path) != "" {
		return e.Path
	}
	for _, span := range e.Spans {
		if strings.TrimSpace(span.File) != "" {
			return span.File
		}
	}
	return ""
}

// partialReason maps a Semgrep error kind to a PartialFile reason.
func partialReason(kind string) string {
	k := strings.ToLower(kind)
	switch {
	case strings.Contains(k, "timeout"):
		return PartialTimeout
	case k == "partialparsing", strings.Contains(k, "syntax error"), strings.Contains(k, "lexical error"), strings.Contains(k, "ast builder error"):
		return PartialParseError
	default:
		return PartialError
	}
}

// SemgrepScan is the result of one Semgrep pass.
type SemgrepScan struct {
	Findings []UnifiedFinding
	// PartialFiles are the files Semgrep reported errors for, with paths as
	// Semgrep printed them; ScopePartialFiles prepares them for output.
	PartialFiles []PartialFile
	// Version is the Semgrep version printed with the results, or "".
	// "semgrep --version" needs a second start of Semgrep, about five seconds.
	Version string
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
	scan, err := ScanSemgrep(ctx, path, taintRuleIDs, configs...)
	return scan.Findings, err
}

// ScanSemgrep is RunSemgrepConfigs that also returns the files Semgrep
// analysed only partly.
func ScanSemgrep(ctx context.Context, path string, taintRuleIDs []string, configs ...string) (SemgrepScan, error) {
	if !IsInstalled("semgrep") {
		return SemgrepScan{}, fmt.Errorf("semgrep not installed")
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
	args = append(args, SemgrepExcludeArgs(path)...)
	args = append(args, path)

	result, err := RunTool(ctx, "semgrep", args...)
	if err != nil {
		return SemgrepScan{}, fmt.Errorf("semgrep execution failed: %w", err)
	}
	return parseSemgrepOutput(result.Stdout, taintRuleIDs)
}

// parseSemgrepOutput reads Semgrep's JSON output.
func parseSemgrepOutput(stdout string, taintRuleIDs []string) (SemgrepScan, error) {
	var output semgrepOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		return SemgrepScan{}, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	taint := make(map[string]bool, len(taintRuleIDs))
	for _, id := range taintRuleIDs {
		taint[id] = true
	}

	scan := SemgrepScan{Findings: make([]UnifiedFinding, 0, len(output.Results)), Version: normalizeToolVersion(output.Version)}
	for _, r := range output.Results {
		if isGeneratedArtifactPath(r.Path) {
			continue
		}
		scan.Findings = append(scan.Findings, UnifiedFinding{
			Source:   "semgrep",
			RuleID:   normalizeTaintRuleID(r.RuleID, taint),
			Severity: normalizeSeverity(r.Extra.Severity),
			Message:  r.Extra.Message,
			File:     r.Path,
			Line:     r.Start.Line,
		})
	}
	for _, e := range output.Errors {
		file := e.file()
		if file == "" {
			continue
		}
		scan.PartialFiles = append(scan.PartialFiles, PartialFile{File: file, Reason: partialReason(e.kind()), Count: 1})
	}
	return scan, nil
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
