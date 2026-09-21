package mcp

import (
	"context"
	"fmt"

	"github.com/dodobrands/aitriage/internal/rules/packs"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// "What rules did this scan actually run?" decides whether a clean result means
// anything. The answer was available only from the CLI, so an agent could report
// a passing scan without being able to say what it was passing.
//
// Installing a pack is deliberately absent here. A pack is rule content fetched
// from elsewhere and written to disk; that belongs to the person at a terminal,
// not to a tool call. The error below says so rather than leaving an agent to
// guess why it cannot.

type rulesInput struct {
	// Name, when set, returns detail for one installed pack.
	Name string `json:"name,omitempty"`
}

type rulePack struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	RuleCount   int    `json:"rule_count"`
	Stack       string `json:"stack,omitempty"`
	Path        string `json:"path"`
}

type rulesResult struct {
	Packs      []rulePack `json:"packs"`
	Total      int        `json:"total"`
	TotalRules int        `json:"total_rules"`
	Summary    string     `json:"summary"`
}

func registerRulesTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "aitriage_rules",
		Description: "List the rule packs installed for AITriage, with their versions and rule counts, " +
			"or describe one pack by name. Use this to report what a scan actually covered. " +
			"Installing or removing a pack is done from the terminal with `aitriage rules install`.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input rulesInput) (*mcp.CallToolResult, rulesResult, error) {
		if input.Name != "" {
			pack, ok := packs.Find(input.Name)
			if !ok {
				return nil, rulesResult{}, fmt.Errorf("no installed rule pack named %q; call this tool without a name to see what is installed", input.Name)
			}
			return nil, rulesResult{
				Packs:      []rulePack{toRulePack(pack)},
				Total:      1,
				TotalRules: pack.RuleCount,
				Summary:    fmt.Sprintf("%s v%s: %s (%d rules).", pack.Name, pack.Version, pack.Description, pack.RuleCount),
			}, nil
		}

		installed := packs.List()
		out := make([]rulePack, 0, len(installed))
		total := 0
		for _, pack := range installed {
			out = append(out, toRulePack(pack))
			total += pack.RuleCount
		}

		summary := fmt.Sprintf("%d rule pack(s) installed, %d rule(s) in total, on top of the built-in ruleset.", len(out), total)
		if len(out) == 0 {
			summary = "No extra rule packs installed; scans run the built-in ruleset only."
		}
		return nil, rulesResult{Packs: out, Total: len(out), TotalRules: total, Summary: summary}, nil
	})
}

func toRulePack(p packs.Installed) rulePack {
	return rulePack{
		Name:        p.Name,
		Version:     p.Version,
		Description: p.Description,
		RuleCount:   p.RuleCount,
		Stack:       p.Stack,
		Path:        p.Path,
	}
}
