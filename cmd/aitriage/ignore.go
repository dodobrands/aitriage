package main

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/spf13/cobra"
)

// Dismissing a finding was possible from the Web UI and from an IDE agent, but
// not from the terminal — so anyone working from a shell could see a false
// positive and had no way to say so. The store is a project file, shared by all
// three surfaces.

var (
	ignoreSource string
	ignoreFile   string
	ignoreLine   int
	ignoreReason string
	ignoreNote   string
	ignoreEvid   string
)

var ignoreCmd = &cobra.Command{
	Use:   "ignore",
	Short: "Dismiss findings as false positives, accepted risks, or won't-fix",
	Long: `Record a decision about a finding so it stops blocking and stays recorded.

  aitriage ignore add SQLI-001 --file app/index.php --reason false-positive
  aitriage ignore add CVE-2026-1 --source trivy --reason accepted-risk --note "mitigated at the gateway"
  aitriage ignore list
  aitriage ignore remove SQLI-001

Decisions live in ` + suppression.File + ` and are shared with the Web UI and AI IDE tools.`,
}

var ignoreAddCmd = &cobra.Command{
	Use:   "add [rule-id] [path]",
	Short: "Dismiss a finding, with a reason",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runIgnoreAdd,
}

var ignoreListCmd = &cobra.Command{
	Use:   "list [path]",
	Short: "Show dismissed findings and why",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runIgnoreList,
}

var ignoreRemoveCmd = &cobra.Command{
	Use:   "remove [rule-id-or-fingerprint] [path]",
	Short: "Undo a dismissal so the finding is reported again",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runIgnoreRemove,
}

func init() {
	rootCmd.AddCommand(ignoreCmd)
	ignoreCmd.AddCommand(ignoreAddCmd, ignoreListCmd, ignoreRemoveCmd)

	ignoreAddCmd.Flags().StringVar(&ignoreSource, "source", "core", "Scanner that reported it: core, semgrep, trivy, gitleaks, bandit, nfr, deploy")
	ignoreAddCmd.Flags().StringVar(&ignoreFile, "file", "", "File the finding is in")
	ignoreAddCmd.Flags().IntVar(&ignoreLine, "line", 0, "Line number (recorded, but not part of the identity)")
	ignoreAddCmd.Flags().StringVar(&ignoreReason, "reason", "false-positive", "false-positive, accepted-risk or wont-fix")
	ignoreAddCmd.Flags().StringVar(&ignoreNote, "note", "", "Why. Required for an accepted risk")
	ignoreAddCmd.Flags().StringVar(&ignoreEvid, "evidence", "", "The matched text, so the dismissal applies to this finding and not to a later, different one")
}

func projectArg(args []string, index int) string {
	if len(args) > index && strings.TrimSpace(args[index]) != "" {
		return args[index]
	}
	return "."
}

func runIgnoreAdd(cmd *cobra.Command, args []string) error {
	ruleID := args[0]
	projectPath := projectArg(args, 1)

	store, err := suppression.Load(projectPath)
	if err != nil {
		return err
	}

	item := baseline.Item{
		Source: ignoreSource,
		RuleID: ruleID,
		// Stored relative to the project so the record is portable and does not
		// carry the local directory layout into the repository.
		File:     baseline.RelativePath(projectPath, ignoreFile),
		Line:     ignoreLine,
		Evidence: ignoreEvid,
	}

	entry, replaced, err := store.Add(item, ignoreReason, ignoreNote, currentUserName())
	if err != nil {
		return err
	}
	if err := suppression.Save(projectPath, store); err != nil {
		return err
	}

	action := "Dismissed"
	if replaced {
		action = "Updated dismissal for"
	}
	fmt.Fprintf(os.Stderr, "%s %s (%s) as %s\n", action, entry.RuleID, entry.Source, entry.Reason)
	if entry.Note != "" {
		fmt.Fprintf(os.Stderr, "  Reason: %s\n", entry.Note)
	}
	fmt.Fprintf(os.Stderr, "  Recorded in %s/%s\n", projectPath, suppression.File)

	if ignoreEvid == "" {
		// Without evidence the fingerprint is coarser, so a later, different
		// finding under the same rule and file would also be hidden.
		fmt.Fprintf(os.Stderr, "\n  Note: no --evidence given, so this dismissal covers any finding of %s in that file.\n", entry.RuleID)
	}
	return nil
}

func runIgnoreList(cmd *cobra.Command, args []string) error {
	projectPath := projectArg(args, 0)

	store, err := suppression.Load(projectPath)
	if err != nil {
		return err
	}

	entries := store.List()
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "No dismissed findings in %s.\n", projectPath)
		return nil
	}

	fmt.Fprintf(os.Stderr, "%d dismissed finding(s) in %s:\n\n", len(entries), projectPath)
	for _, entry := range entries {
		location := entry.File
		if location == "" {
			location = "(project-level)"
		}
		fmt.Fprintf(os.Stderr, "  %-28s %-9s %s\n", entry.RuleID, entry.Source, location)
		fmt.Fprintf(os.Stderr, "    %s", entry.Reason)
		if entry.Note != "" {
			fmt.Fprintf(os.Stderr, " — %s", entry.Note)
		}
		if entry.Author != "" {
			fmt.Fprintf(os.Stderr, " (%s)", entry.Author)
		}
		fmt.Fprintf(os.Stderr, ", %s\n", entry.CreatedAt.Format("2006-01-02"))
		fmt.Fprintf(os.Stderr, "    %s\n\n", entry.Fingerprint)
	}

	counts := store.CountByReason()
	fmt.Fprintf(os.Stderr, "  %d false positive(s), %d accepted risk(s), %d won't fix\n",
		counts[suppression.ReasonFalsePositive], counts[suppression.ReasonAcceptedRisk], counts[suppression.ReasonWontFix])
	return nil
}

func runIgnoreRemove(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	projectPath := projectArg(args, 1)

	store, err := suppression.Load(projectPath)
	if err != nil {
		return err
	}

	removed := store.Remove(identifier)
	if removed == 0 {
		return fmt.Errorf("no dismissal matches %q", identifier)
	}
	if err := suppression.Save(projectPath, store); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Removed %d dismissal(s) for %s. Those findings are reported again.\n", removed, identifier)
	return nil
}

// currentUserName records who made the decision, for the person reviewing it
// later. It is best-effort: an unnamed decision is better than none.
func currentUserName() string {
	if u, err := user.Current(); err == nil {
		if strings.TrimSpace(u.Username) != "" {
			return u.Username
		}
	}
	return ""
}
