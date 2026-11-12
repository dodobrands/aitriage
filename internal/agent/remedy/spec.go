package remedy

import (
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// GenerateClaudeSpec creates a CLAUDE.md formatted string from a rich scan result.
func GenerateClaudeSpec(rich llm.RichScanResult) string {
	var sb strings.Builder

	sb.WriteString("# AITriage Security Agent Specification\n\n")
	sb.WriteString("> **System Instructions:** This is an auto-generated specification based on the latest security audit. As an autonomous agent, follow these instructions to remediate the identified vulnerabilities in the project.\n\n")

	// 1. Context and Rules
	sb.WriteString("## General Rules\n")
	sb.WriteString("- Do not use `sed` or blind regex replacements. Use specific string replacement or AST-aware tools.\n")
	sb.WriteString("- After resolving an issue, document the change in `SECURITY_CHANGELOG.md`.\n")
	sb.WriteString("- Run tests after modifying critical application flows.\n\n")

	// 2. Core SAST Findings
	if len(rich.Report.Results) > 0 {
		sb.WriteString("## Core Security Findings to Fix\n\n")
		for i, r := range rich.Report.Results {
			fmt.Fprintf(&sb, "### %d. [%s] %s\n", i+1, r.Severity, r.Name)
			fmt.Fprintf(&sb, "- **File**: `%s:%d`\n", r.File, r.Line)
			fmt.Fprintf(&sb, "- **Rule ID**: `%s`\n", r.ID)
			fmt.Fprintf(&sb, "- **Evidence**: `%s`\n", r.Evidence)
			if r.Suggestion != "" {
				fmt.Fprintf(&sb, "- **Remediation Plan**: %s\n", r.Suggestion)
			}

			// Map to specific file rules for Cursor/Claude
			sb.WriteString("\n<cursor_rule>\n")
			fmt.Fprintf(&sb, "When modifying `%s`:\n- Ensure the vulnerability `%s` is patched securely.\n", r.File, r.ID)
			fmt.Fprintf(&sb, "- Context: %s\n", r.Evidence)
			sb.WriteString("</cursor_rule>\n\n")
		}
	}

	// 3. External Scanner Findings
	if len(rich.External) > 0 {
		sb.WriteString("## Sub-Scanner Security Findings\n\n")
		for i, e := range rich.External {
			fmt.Fprintf(&sb, "### %d. [%s] %s (%s)\n", i+1, e.Severity, e.Message, e.Source)
			fmt.Fprintf(&sb, "- **File**: `%s:%d`\n", e.File, e.Line)
			fmt.Fprintf(&sb, "- **Rule**: `%s`\n\n", e.RuleID)
		}
	}

	// 5. NFR Issues
	if len(rich.NFR) > 0 {
		sb.WriteString("## Non-Functional Requirements (NFR) Violations\n\n")
		for i, n := range rich.NFR {
			fmt.Fprintf(&sb, "### %d. [%s] %s\n", i+1, n.Severity, n.Name)
			fmt.Fprintf(&sb, "- **Message**: %s\n", n.Message)
			fmt.Fprintf(&sb, "- **Advice**: %s\n\n", n.Advice)
		}
	}

	// 6. Deploy Audit
	if len(rich.Deploy) > 0 {
		sb.WriteString("## Infrastructure/Deploy Risks\n\n")
		for i, d := range rich.Deploy {
			fmt.Fprintf(&sb, "### %d. [%s] %s\n", i+1, d.Severity, d.Issue)
			fmt.Fprintf(&sb, "- **File**: `%s:%d`\n", d.File, d.Line)
			fmt.Fprintf(&sb, "- **Recommendation**: %s\n\n", d.Advice)
		}
	}

	// 7. Network Probe
	if len(rich.Network) > 0 {
		sb.WriteString("## Live Network Exposure\n\n")
		sb.WriteString("> **Warning**: The following ports were found open during the live infrastructure probe. Close any ports that should not be publicly accessible.\n\n")
		for i, n := range rich.Network {
			fmt.Fprintf(&sb, "### %d. [%s] Port %d Open\n", i+1, n.Severity, n.Port)
			fmt.Fprintf(&sb, "- **Service**: `%s`\n", n.Service)
			fmt.Fprintf(&sb, "- **Message**: %s\n\n", n.Message)
		}
	}

	// 8. Context
	if rich.Diagram != "" {
		sb.WriteString("## System Architecture Context\n\n")
		fmt.Fprintf(&sb, "```mermaid\n%s\n```\n", rich.Diagram)
	}

	sb.WriteString("\n## Next Steps\n")
	sb.WriteString("1. Start by fixing the **Critical** findings.\n")
	sb.WriteString("2. After fixing, run `aitriage scan .` locally to verify the fix.\n")
	sb.WriteString("3. Ensure tests pass before pushing.\n")

	return sb.String()
}
