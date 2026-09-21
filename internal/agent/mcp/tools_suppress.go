package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Dismissing a finding used to mean different things in different surfaces: the
// Web UI wrote to its own database, this server proxied to Antigravity's
// external SecureCoder, and the CLI could not do it at all. A decision that only
// one surface can see is not a decision.
//
// aitriage_suppress writes the shared project file, so what an agent dismisses
// here is what a human sees in the Web UI and in the terminal.

type suppressInput struct {
	Path string `json:"path,omitempty"`
	// Action: list (default), add, remove.
	Action string `json:"action,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
	// Source names the scanner. Two scanners reporting the same line are
	// different findings, so dismissing one must not hide the other.
	Source string `json:"source,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	// Evidence is the matched text. Without it the dismissal covers any finding
	// of that rule in that file, which is usually broader than intended.
	Evidence string `json:"evidence,omitempty"`
	// Reason: false_positive, accepted_risk, wont_fix.
	Reason string `json:"reason,omitempty"`
	// Note is the justification. Required for an accepted risk.
	Note string `json:"note,omitempty"`
}

type suppressEntry struct {
	Fingerprint string `json:"fingerprint"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file,omitempty"`
	Reason      string `json:"reason"`
	Note        string `json:"note,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type suppressResult struct {
	Action  string          `json:"action"`
	File    string          `json:"file"`
	Total   int             `json:"total"`
	Entries []suppressEntry `json:"entries,omitempty"`
	Summary string          `json:"summary"`
}

func registerSuppressTool(srv *mcp.Server, guard *PathGuard, allowMutation bool) {
	description := "List findings this project has dismissed, with the reason each was dismissed. Action: list."
	if allowMutation {
		description = "Record or review decisions about findings: dismiss one as a false positive, " +
			"an accepted risk or won't-fix, undo a dismissal, or list what is already dismissed. " +
			"Decisions are stored in the project and shared with the Web UI and the CLI. " +
			"Actions: list (default), add, remove."
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aitriage_suppress",
		Description: description,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input suppressInput) (*mcp.CallToolResult, suppressResult, error) {
		path, err := guard.Resolve(input.Path)
		if err != nil {
			return nil, suppressResult{}, err
		}

		store, err := suppression.Load(path)
		if err != nil {
			return nil, suppressResult{}, err
		}

		action := strings.ToLower(strings.TrimSpace(input.Action))
		if action == "" {
			action = "list"
		}

		switch action {
		case "list":
			return nil, listSuppressions(path, store), nil

		case "add":
			if !allowMutation {
				return nil, suppressResult{}, fmt.Errorf(
					"dismissing a finding is not available under the safe profile: a read-only tool must not be able to mark a security finding as resolved")
			}
			if strings.TrimSpace(input.RuleID) == "" {
				return nil, suppressResult{}, fmt.Errorf("rule_id is required to dismiss a finding")
			}
			item := baseline.Item{
				Source:   input.Source,
				RuleID:   input.RuleID,
				File:     input.File,
				Line:     input.Line,
				Evidence: input.Evidence,
			}
			entry, replaced, addErr := store.Add(item, input.Reason, input.Note, "ai-ide")
			if addErr != nil {
				return nil, suppressResult{}, addErr
			}
			if saveErr := suppression.Save(path, store); saveErr != nil {
				return nil, suppressResult{}, saveErr
			}

			verb := "Dismissed"
			if replaced {
				verb = "Updated the dismissal of"
			}
			result := listSuppressions(path, store)
			result.Action = "add"
			result.Summary = fmt.Sprintf("%s %s (%s) as %s. It is now dismissed for the Web UI and the CLI too.",
				verb, entry.RuleID, entry.Source, entry.Reason)
			return nil, result, nil

		case "remove":
			if !allowMutation {
				return nil, suppressResult{}, fmt.Errorf("changing dismissals is not available under the safe profile")
			}
			identifier := strings.TrimSpace(input.RuleID)
			if identifier == "" {
				return nil, suppressResult{}, fmt.Errorf("rule_id (or a fingerprint) is required to undo a dismissal")
			}
			removed := store.Remove(identifier)
			if removed == 0 {
				return nil, suppressResult{}, fmt.Errorf("no dismissal matches %q", identifier)
			}
			if saveErr := suppression.Save(path, store); saveErr != nil {
				return nil, suppressResult{}, saveErr
			}

			result := listSuppressions(path, store)
			result.Action = "remove"
			result.Summary = fmt.Sprintf("Removed %d dismissal(s) for %s. Those findings are reported again.", removed, identifier)
			return nil, result, nil

		default:
			return nil, suppressResult{}, fmt.Errorf("unknown action %q (supported: list, add, remove)", input.Action)
		}
	})
}

func listSuppressions(path string, store *suppression.Store) suppressResult {
	entries := store.List()
	out := make([]suppressEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, suppressEntry{
			Fingerprint: entry.Fingerprint,
			Source:      entry.Source,
			RuleID:      entry.RuleID,
			File:        entry.File,
			Reason:      entry.Reason,
			Note:        entry.Note,
			CreatedAt:   entry.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	counts := store.CountByReason()
	return suppressResult{
		Action:  "list",
		File:    path + "/" + suppression.File,
		Total:   len(out),
		Entries: out,
		Summary: fmt.Sprintf("%d dismissed finding(s): %d false positive(s), %d accepted risk(s), %d won't fix.",
			len(out), counts[suppression.ReasonFalsePositive], counts[suppression.ReasonAcceptedRisk], counts[suppression.ReasonWontFix]),
	}
}
