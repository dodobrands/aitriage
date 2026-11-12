package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/statefile"
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
//
// In the container runtime the project is mounted read-only, so decisions go
// to a local copy under aitriage-reports, the one the Web UI writes there too.
// Every scan in the container applies it on top of the project's own file
// (suppression.LoadAt): local entries win for the same finding and stay in
// force after the project drops its own. The CLI on the host and CI read only
// the project file, so the copy reaches them once it is committed.
//
// A dismissal recorded without a file and without evidence covers every
// finding of its rule from that scanner anywhere in the project, including
// ones reported later. One call with nothing but a rule id used to record
// exactly that, and the summary did not say so. Adding now needs the file,
// unless the caller asks for that reach with rule_wide, and every add returns
// which findings the dismissal covers.

type suppressInput struct {
	Path string `json:"path,omitempty"`
	// Action: list (default), add, remove.
	Action string `json:"action,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
	// Source names the scanner. Two scanners reporting the same line are
	// different findings, so dismissing one must not hide the other.
	Source string `json:"source,omitempty"`
	// File is the file the finding is in. Adding needs it unless RuleWide is
	// set.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Evidence is the matched text. Without it the dismissal covers any finding
	// of that rule in that file, which is usually broader than intended.
	Evidence string `json:"evidence,omitempty"`
	// RuleWide records a dismissal that is not tied to a file: without
	// evidence it covers every finding of the rule from that source anywhere
	// in the project; with evidence, the findings reported without a file
	// (project-level checks) that carry it. It cannot be combined with File.
	RuleWide bool `json:"rule_wide,omitempty"`
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
	// Scope says which findings the dismissal just added covers.
	Scope   string `json:"scope,omitempty"`
	Summary string `json:"summary"`
}

func registerSuppressTool(srv *mcp.Server, guard *PathGuard, allowMutation bool) {
	description := "List findings this project has dismissed, with the reason each was dismissed. Action: list."
	if allowMutation {
		description = "Record or review decisions about findings: dismiss one as a false positive, " +
			"an accepted risk or won't-fix, undo a dismissal, or list what is already dismissed. " +
			"Decisions are stored in the project and shared with the Web UI and the CLI. " +
			"Actions: list (default), add, remove. " +
			"add needs the file the finding is in; pass its evidence (the matched text) too, " +
			"or the dismissal covers every finding of the rule in that file. " +
			"To dismiss a rule wherever it is reported, or a project-level finding that has no file, " +
			"leave file empty and set rule_wide to true. The result's scope says which findings a dismissal covers."
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aitriage_suppress",
		Description: description,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input suppressInput) (*mcp.CallToolResult, suppressResult, error) {
		path, err := guard.Resolve(input.Path)
		if err != nil {
			return nil, suppressResult{}, err
		}

		record, err := suppression.Open(suppression.Locate(path))
		if err != nil {
			return nil, suppressResult{}, err
		}

		action := strings.ToLower(strings.TrimSpace(input.Action))
		if action == "" {
			action = "list"
		}

		switch action {
		case "list":
			return nil, listSuppressions(record), nil

		case "add":
			if !allowMutation {
				return nil, suppressResult{}, fmt.Errorf(
					"dismissing a finding is not available under the safe profile: a read-only tool must not be able to mark a security finding as resolved")
			}
			if strings.TrimSpace(input.RuleID) == "" {
				return nil, suppressResult{}, fmt.Errorf("rule_id is required to dismiss a finding")
			}
			item := baseline.Item{
				Source: input.Source,
				RuleID: input.RuleID,
				// Relative to the project: the record is committed and must mean
				// the same thing on every machine.
				File:     baseline.RelativePath(path, input.File),
				Line:     input.Line,
				Evidence: input.Evidence,
			}
			if err := suppression.ValidateScope(item, input.RuleWide); err != nil {
				return nil, suppressResult{}, err
			}
			entry, replaced, addErr := record.Add(item, input.Reason, input.Note, "ai-ide")
			if addErr != nil {
				return nil, suppressResult{}, addErr
			}
			if saveErr := record.Save(); saveErr != nil {
				return nil, suppressResult{}, saveErr
			}

			verb := "Dismissed"
			if replaced {
				verb = "Updated the dismissal of"
			}
			result := listSuppressions(record)
			result.Action = "add"
			result.Scope = "This dismissal " + suppression.DescribeScope(item) + "."
			result.Summary = fmt.Sprintf("%s %s (%s) as %s. %s %s",
				verb, entry.RuleID, suppression.SourceName(entry.Source), entry.Reason, result.Scope, decisionsReach(record.Location))
			return nil, withLocalNote(result, record.Location), nil

		case "remove":
			if !allowMutation {
				return nil, suppressResult{}, fmt.Errorf("changing dismissals is not available under the safe profile")
			}
			identifier := strings.TrimSpace(input.RuleID)
			if identifier == "" {
				return nil, suppressResult{}, fmt.Errorf("rule_id (or a fingerprint) is required to undo a dismissal")
			}
			removed, committed := record.Remove(identifier)
			switch {
			case removed == 0 && committed > 0:
				return nil, suppressResult{}, errors.New(committedDecision(identifier))
			case removed == 0:
				return nil, suppressResult{}, fmt.Errorf("no dismissal matches %q", identifier)
			}
			if saveErr := record.Save(); saveErr != nil {
				return nil, suppressResult{}, saveErr
			}

			result := listSuppressions(record)
			result.Action = "remove"
			result.Summary = fmt.Sprintf("Removed %d dismissal(s) for %s. Those findings are reported again.", removed, identifier)
			if committed > 0 {
				result.Summary = fmt.Sprintf("Removed %d local dismissal(s) for %s. %s.", removed, identifier, committedDecision(identifier))
			}
			return nil, withLocalNote(result, record.Location), nil

		default:
			return nil, suppressResult{}, fmt.Errorf("unknown action %q (supported: list, add, remove)", input.Action)
		}
	})
}

// decisionsReach says which surfaces see a decision once it is written.
func decisionsReach(loc statefile.Location) string {
	if loc.Redirected() {
		return writtenUnderReports(loc.WriteFile())
	}
	return "It is now dismissed for the Web UI and the CLI too."
}

// committedDecision explains why a decision cannot be undone from the
// container: the project's own file records it and is read-only there.
func committedDecision(identifier string) string {
	return fmt.Sprintf("%q is still dismissed by the project's own %s, which is read-only in the container; remove it there and commit the change",
		identifier, suppression.File)
}

// withLocalNote adds, while a local copy is in effect, how it relates to the
// project's own file.
func withLocalNote(result suppressResult, loc statefile.Location) suppressResult {
	if loc.HasCopy() {
		result.Summary += " " + statefile.LocalOverrideNote
	}
	return result
}

// listSuppressions reports the dismissals that apply and the file they are
// recorded in: after a write, the file the write went to.
func listSuppressions(record *suppression.Record) suppressResult {
	store := record.Applied
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
	return withLocalNote(suppressResult{
		Action:  "list",
		File:    record.Location.CurrentFile(),
		Total:   len(out),
		Entries: out,
		Summary: fmt.Sprintf("%d dismissed finding(s): %d false positive(s), %d accepted risk(s), %d won't fix.",
			len(out), counts[suppression.ReasonFalsePositive], counts[suppression.ReasonAcceptedRisk], counts[suppression.ReasonWontFix]),
	}, record.Location)
}
