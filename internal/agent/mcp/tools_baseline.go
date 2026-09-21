package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/scanner"
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

type baselineInput struct {
	Path string `json:"path"`
	// Action is one of: status (default), create, update, clear.
	// create and update are the same operation: both record the current scan as
	// the new starting line. Both are refused under the safe profile.
	Action string `json:"action"`
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
			target := filepath.Join(path, baseline.BaselineFile)
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return nil, baselineResult{}, fmt.Errorf("could not remove baseline: %v", err)
			}
			return nil, baselineResult{
				Action:  "clear",
				File:    target,
				Summary: "Baseline removed. Every finding is reported again.",
			}, nil

		default:
			return nil, baselineResult{}, fmt.Errorf("unknown action %q (supported: status, create, update, clear)", input.Action)
		}
	})
}

func baselineStatusFor(path string) baselineResult {
	target := filepath.Join(path, baseline.BaselineFile)
	existing, err := baseline.Load(path)
	if err != nil || existing == nil {
		return baselineResult{
			Action:  "status",
			File:    target,
			Summary: "No baseline. Every finding is reported as new.",
		}
	}

	stats := existing.Stats()
	return baselineResult{
		Action:     "status",
		Exists:     true,
		File:       target,
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  existing.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  existing.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Summary:    fmt.Sprintf("%d finding(s) accepted; only findings outside this set are reported as new.", stats.Total),
	}
}

func baselineWrite(ctx context.Context, path, action string) (*mcp.CallToolResult, baselineResult, error) {
	report, err := scanner.Scan(ctx, path, scanner.ScanOptions{})
	if err != nil {
		return nil, baselineResult{}, fmt.Errorf("scan failed: %v", err)
	}

	created := baseline.New(report.Results)
	if existing, loadErr := baseline.Load(path); loadErr == nil && existing != nil {
		// Keep the original creation date: it records how long the project has
		// been operating against a baseline.
		created.CreatedAt = existing.CreatedAt
	}
	if err := baseline.Save(path, created); err != nil {
		return nil, baselineResult{}, fmt.Errorf("could not write baseline: %v", err)
	}

	stats := created.Stats()
	return nil, baselineResult{
		Action:     action,
		Exists:     true,
		File:       filepath.Join(path, baseline.BaselineFile),
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  created.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  created.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Summary: fmt.Sprintf("%d finding(s) accepted as the baseline. They stay visible in reports; only new findings are reported as regressions.",
			stats.Total),
	}, nil
}
