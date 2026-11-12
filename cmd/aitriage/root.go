package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

// Version is set via -ldflags at build time (GoReleaser).
// Falls back to "dev" for local builds.
var Version = "dev"

func init() {
	// `go install module@version` does not apply our release ldflags, but Go
	// records the selected module version in build info.  Recover it here so
	// that the host CLI resolves the matching immutable container image instead
	// of falling back to the rolling development tag.
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			Version = resolvedBuildVersion(Version, info.Main.Version)
		}
	}
}

func resolvedBuildVersion(linkedVersion, moduleVersion string) string {
	if strings.TrimSpace(linkedVersion) != "" && linkedVersion != "dev" {
		return linkedVersion
	}

	moduleVersion = strings.TrimSpace(moduleVersion)
	if !isExactModuleVersion(moduleVersion) {
		return "dev"
	}
	return moduleVersion
}

func isExactModuleVersion(version string) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// ErrPolicyViolation is returned when the security policy gate fails.
// Commands should return this instead of calling os.Exit(1) directly,
// so that defers run and the error is testable.
var ErrPolicyViolation = errors.New("security policy violation: see blocking reasons above")

// ErrAuditIncomplete is returned when an audit could not be completed: the LLM
// provider failed during triage, a required scanner did not run, or the run
// could not finish for another operational reason. When triage was cut short
// the artifacts are still written. It exits with status 2, so that status 1
// keeps meaning exactly "the security policy gate failed" and CI can tell a
// finding to fix from an outage to retry.
var ErrAuditIncomplete = errors.New("audit incomplete")

// Process exit statuses.
const (
	exitPolicyViolation = 1
	exitAuditIncomplete = 2
)

// errSilentExit signals a non-zero exit whose user-facing message was already
// rendered (e.g. setup failures). Execute exits 1 without printing anything more.
var errSilentExit = errors.New("")

// exitStatusError carries the exit status of a child process that already
// printed its own output, such as the containerised agent, so the host CLI
// exits the same way instead of collapsing every status to 1.
type exitStatusError struct {
	code int
}

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("child process exited with status %d", e.code)
}

func auditIncomplete(err error) error {
	return fmt.Errorf("%w: %w", ErrAuditIncomplete, err)
}

// exitStatus maps a command error to the process exit status and reports
// whether Execute still has to print the error.
func exitStatus(err error) (int, bool) {
	var child *exitStatusError
	switch {
	case errors.As(err, &child):
		return child.code, false
	case errors.Is(err, ErrPolicyViolation), errors.Is(err, errSilentExit):
		return exitPolicyViolation, false
	case errors.Is(err, ErrAuditIncomplete):
		return exitAuditIncomplete, true
	default:
		return 1, true
	}
}

var rootCmd = &cobra.Command{
	Use:   "aitriage [path]",
	Short: "AITriage — AI-Powered Security Audit Engine",
	Long: `AITriage is a deterministic security presence-checker with AI-powered triage.

It scans your project for missing security practices, hardcoded secrets,
misconfigured deployments, and architectural risks — then optionally uses
an LLM to prioritize findings and generate fix specifications.

Running "aitriage" without a subcommand is equivalent to "aitriage scan .".`,
	Example: `  aitriage                    # Scan current directory
  aitriage ./my-project       # Scan specific path
  aitriage scan --format json # Scan with JSON output
  aitriage agent              # AI-powered audit with LLM
  aitriage agent --no-chat    # Non-interactive (CI/CD)`,
	// When called without a subcommand, run scan on the given path (or .)
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		// Call RunE directly instead of Execute() to avoid infinite recursion
		// through cobra's command chain (root → scan → root → ...)
		return scanCmd.RunE(scanCmd, []string{path})
	},
	Args:              cobra.MaximumNArgs(1),
	DisableAutoGenTag: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
//
// Exit statuses: 0 success, 1 security policy violation (and command usage
// errors), 2 audit incomplete (see ErrAuditIncomplete). A containerised agent's
// status is passed through unchanged.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		code, report := exitStatus(err)
		if report {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(code)
	}
}

func init() {
	// Root-level persistent flags can be added here
	lipgloss.SetColorProfile(termenv.TrueColor)
}
