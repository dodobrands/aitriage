package remedy

import (
	"fmt"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

type FixItem struct {
	RuleID     string   `json:"rule_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	FixPrompt  string   `json:"fix_prompt"`
	FixExample string   `json:"fix_example"`
	References []string `json:"references"`
}

type FixPlan struct {
	GeneratedAt     time.Time `json:"generated_at"`
	TotalFindings   int       `json:"total_findings"`
	CriticalActions []FixItem `json:"critical_actions"`
	HighActions     []FixItem `json:"high_actions"`
	MediumActions   []FixItem `json:"medium_actions"`
}

// GenerateFixPlan creates a structured fix plan without an LLM.
// Uses Rule ID → template mapping from templates.go
func GenerateFixPlan(results []core.CheckResult) FixPlan {
	plan := FixPlan{
		GeneratedAt:   time.Now(),
		TotalFindings: len(results),
	}
	for _, r := range results {
		tmpl, ok := fixTemplates[r.ID]
		if !ok {
			tmpl = defaultTemplate
		}
		item := FixItem{
			RuleID:     r.ID,
			Name:       r.Name,
			Severity:   r.Severity,
			File:       r.File,
			Line:       r.Line,
			FixPrompt:  fmt.Sprintf(tmpl.Prompt, r.File, r.Line),
			FixExample: tmpl.Example,
			References: tmpl.References,
		}
		switch r.Severity {
		case "CRITICAL":
			plan.CriticalActions = append(plan.CriticalActions, item)
		case "HIGH":
			plan.HighActions = append(plan.HighActions, item)
		default:
			plan.MediumActions = append(plan.MediumActions, item)
		}
	}
	return plan
}

// ToMarkdown converts the plan to Markdown for insertion into Claude Code / Cursor
func (p FixPlan) ToMarkdown() string {
	var sb strings.Builder
	sb.WriteString("# AITriage Security Fix Plan\n")
	fmt.Fprintf(&sb, "Generated: %s\n\n", p.GeneratedAt.Format("2006-01-02 15:04"))
	fmt.Fprintf(&sb, "**Total findings: %d**\n\n", p.TotalFindings)

	if len(p.CriticalActions) > 0 {
		sb.WriteString("## 🔴 CRITICAL — Fix Immediately\n\n")
		for _, item := range p.CriticalActions {
			fmt.Fprintf(&sb, "### %s\n", item.Name)
			fmt.Fprintf(&sb, "**File:** `%s` line %d\n\n", item.File, item.Line)
			fmt.Fprintf(&sb, "**Fix prompt for AI agent:**\n```\n%s\n```\n\n", item.FixPrompt)
			if item.FixExample != "" {
				fmt.Fprintf(&sb, "**Example:**\n```\n%s\n```\n\n", item.FixExample)
			}
			if len(item.References) > 0 {
				fmt.Fprintf(&sb, "**Reference:** %s\n\n", strings.Join(item.References, ", "))
			}
		}
	}

	if len(p.HighActions) > 0 {
		sb.WriteString("## 🟠 HIGH\n\n")
		for _, item := range p.HighActions {
			fmt.Fprintf(&sb, "- **%s** (`%s:%d`) — %s\n", item.Name, item.File, item.Line, item.FixPrompt)
		}
		sb.WriteString("\n")
	}

	if len(p.MediumActions) > 0 {
		sb.WriteString("## 🟡 MEDIUM\n\n")
		for _, item := range p.MediumActions {
			fmt.Fprintf(&sb, "- **%s** (`%s:%d`) — %s\n", item.Name, item.File, item.Line, item.FixPrompt)
		}
	}

	return sb.String()
}
