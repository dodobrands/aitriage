package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/engine/statefile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A baseline accepts today's findings as the starting line so a gate judges only
// new work. It is the standard way to adopt a scanner on an existing codebase.
//
// The capability lived only in the CLI, which meant an agent working in an IDE —
// and a person working in the Web UI — could not reach the answer to "the gate
// is red because of years of accumulated debt". All three surfaces now read and
// write the same `.aitriage-baseline.json`, so a baseline created anywhere is
// honoured everywhere.
//
// In the container runtime the project is mounted read-only. The baseline this
// tool writes then goes to a local copy under aitriage-reports, the one the Web
// UI writes there too, and every reader in the container applies it together
// with the project's own file (baseline.LoadAt).

type baselineInput struct {
	Path string `json:"path,omitempty"`
	// Action is one of: status (default), create, update, clear.
	// create and update are the same operation: both record the current scan as
	// the new starting line. Both are refused under the safe profile.
	Action string `json:"action,omitempty"`
}

type baselineResult struct {
	Action     string         `json:"action"`
	Exists     bool           `json:"exists"`
	File       string         `json:"file"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
	Summary    string         `json:"summary"`
}

// registerBaselineTool exposes baseline inspection always, and baseline writes
// only when the profile permits mutation: create, update and clear all write to
// the project tree, which the safe profile forbids by design.
func registerBaselineTool(srv *mcp.Server, guard *PathGuard, allowMutation bool) {
	description := "Inspect the accepted security baseline for a project. " +
		"A baseline records findings already accepted, so a gate reports only new ones. " +
		"Action: status."
	if allowMutation {
		description = "Manage the accepted security baseline for a project. " +
			"A baseline records findings already accepted, so a gate reports only new ones — " +
			"the standard way to adopt scanning on an existing codebase without a wall of findings nobody can act on. " +
			"Actions: status (default), create, update, clear."
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aitriage_baseline",
		Description: description,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input baselineInput) (*mcp.CallToolResult, baselineResult, error) {
		path, err := guard.Resolve(input.Path)
		if err != nil {
			return nil, baselineResult{}, err
		}

		action := strings.ToLower(strings.TrimSpace(input.Action))
		if action == "" {
			action = "status"
		}

		switch action {
		case "status":
			return nil, baselineStatusFor(path), nil

		case "create", "update":
			if !allowMutation {
				return nil, baselineResult{}, fmt.Errorf(
					"action %q writes %s and is not available under the safe profile; use action \"status\", or run `aitriage baseline %s` yourself",
					action, baseline.BaselineFile, action)
			}
			return baselineWrite(ctx, path, action)

		case "clear":
			if !allowMutation {
				return nil, baselineResult{}, fmt.Errorf(
					"action \"clear\" removes %s and is not available under the safe profile", baseline.BaselineFile)
			}
			return baselineClear(path)

		default:
			return nil, baselineResult{}, fmt.Errorf("unknown action %q (supported: status, create, update, clear)", input.Action)
		}
	})
}

func baselineStatusFor(path string) baselineResult {
	loc := baseline.Locate(path)
	existing, err := baseline.LoadAt(loc)
	if err != nil || existing == nil {
		return baselineResult{
			Action:  "status",
			File:    loc.WriteFile(),
			Summary: "No baseline. Every finding is reported as new.",
		}
	}

	result := describeBaseline("status", existing, loc)
	result.Summary = fmt.Sprintf("%d finding(s) accepted; only findings outside this set are reported as new.", result.Total)
	return withContainerNote(result, loc)
}

func baselineWrite(ctx context.Context, path, action string) (*mcp.CallToolResult, baselineResult, error) {
	loc := baseline.Locate(path)

	// Every scanner, so the baseline covers what the project actually reports.
	rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
		ProjectPath: path,
		RunExternal: true,
	})

	created := baseline.NewFromItems(orchestrator.BaselineItems(&rich))
	if existing, loadErr := baseline.LoadAt(loc); loadErr == nil && existing != nil {
		// Keep the original creation date: it records how long the project has
		// been operating against a baseline.
		created.CreatedAt = existing.CreatedAt
	}
	if err := baseline.SaveAt(loc, created); err != nil {
		return nil, baselineResult{}, fmt.Errorf("could not write baseline: %v", err)
	}

	// In the container the project's own baseline keeps applying next to the
	// copy just written, so report what applies now.
	applied := created
	if merged, loadErr := baseline.LoadAt(loc); loadErr == nil && merged != nil {
		applied = merged
	}
	result := describeBaseline(action, applied, loc)
	result.Summary = fmt.Sprintf("%d finding(s) accepted as the baseline. They stay visible in reports; only new findings are reported as regressions.",
		result.Total)
	if loc.Redirected() {
		result.Summary += " " + writtenUnderReports(loc.WriteFile())
	}
	return nil, withContainerNote(result, loc), nil
}

func baselineClear(path string) (*mcp.CallToolResult, baselineResult, error) {
	loc := baseline.Locate(path)
	target := loc.WriteFile()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return nil, baselineResult{}, fmt.Errorf("could not remove baseline: %v", err)
	}
	// A read-only project's own baseline cannot be removed from here and keeps
	// applying. Report it rather than claim that no baseline is left.
	if loc.Redirected() {
		if remaining, loadErr := baseline.LoadAt(loc); loadErr == nil && remaining != nil {
			result := describeBaseline("clear", remaining, loc)
			result.Summary = fmt.Sprintf("Removed the local copy under aitriage-reports. The project's own baseline still applies: %d finding(s) accepted.", result.Total)
			return nil, withContainerNote(result, loc), nil
		}
	}
	return nil, baselineResult{
		Action:  "clear",
		File:    target,
		Summary: "Baseline removed. Every finding is reported again.",
	}, nil
}

// withContainerNote explains, in the container runtime, how the baseline in
// effect relates to the project's own file.
func withContainerNote(result baselineResult, loc statefile.Location) baselineResult {
	switch {
	case loc.HasCopy():
		result.Summary += " " + statefile.LocalOverrideNote
	case loc.Redirected():
		result.Summary += " " + projectBaselineReadOnly
	}
	return result
}

// projectBaselineReadOnly explains why the baseline in effect cannot be
// changed by this server in the container runtime.
const projectBaselineReadOnly = "It is the project's own file, read-only in the container: a baseline created or updated here is written as a local copy under aitriage-reports that applies on top of it, and the file itself can only be changed outside the container."

// writtenUnderReports tells the agent where a container write went.
func writtenUnderReports(file string) string {
	return fmt.Sprintf("The project is read-only in the container, so this was written to %s, which is not committed.", file)
}

func describeBaseline(action string, b *baseline.Baseline, loc statefile.Location) baselineResult {
	stats := b.Stats()
	return baselineResult{
		Action:     action,
		Exists:     true,
		File:       loc.CurrentFile(),
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  b.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  b.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
