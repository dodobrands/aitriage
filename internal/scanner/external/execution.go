package external

import (
	"context"
	"strings"
	"time"
)

// ScannerStatus is the typed outcome of a single scanner in a run. It exists to
// make the difference between "ran and found nothing" and "did not run" explicit
// and machine-checkable — a full audit must never silently skip a scanner.
type ScannerStatus string

const (
	// StatusCompleted means the scanner ran to completion (findings may be zero).
	StatusCompleted ScannerStatus = "completed"
	// StatusMissing means the scanner binary was not available.
	StatusMissing ScannerStatus = "missing"
	// StatusFailed means the scanner started but errored (infrastructure error).
	StatusFailed ScannerStatus = "failed"
	// StatusNotApplicable means a deterministic rule excluded the scanner (e.g.
	// Bandit on a project with no Python).
	StatusNotApplicable ScannerStatus = "not_applicable"
	// StatusTimedOut means the scanner exceeded its time budget.
	StatusTimedOut ScannerStatus = "timed_out"
)

// ScannerExecution is the audit record for one scanner in one run. It is safe to
// persist and surface: Error is redacted by the caller before storage.
type ScannerExecution struct {
	Scanner    string        `json:"scanner"`
	Status     ScannerStatus `json:"status"`
	Version    string        `json:"version,omitempty"`
	Findings   int           `json:"findings"`
	DurationMs int64         `json:"duration_ms"`
	Error      string        `json:"error,omitempty"`
}

// versionArgs maps a scanner to the argument that prints its version.
var versionArgs = map[string][]string{
	"semgrep":  {"--version"},
	"trivy":    {"--version"},
	"gitleaks": {"version"},
	"bandit":   {"--version"},
}

// ToolVersion returns a best-effort version string for a scanner binary. It
// never fails the run; an empty string means "version unknown".
//
// Only stdout is read: the bundled scanners print their version there, while
// stderr carries notices (Semgrep's "A new version of Semgrep is available")
// that used to be recorded as the version.
func ToolVersion(ctx context.Context, name string) string {
	args, ok := versionArgs[name]
	if !ok {
		args = []string{"--version"}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := toolCommand(cctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return normalizeToolVersion(string(out))
}

// normalizeToolVersion keeps the first line of a version banner and drops a
// leading "Version:" label (Trivy prints "Version: 0.72.0"), so manifests and
// summaries show the bare version like the other scanners.
func normalizeToolVersion(out string) string {
	line := strings.TrimSpace(out)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if rest, ok := strings.CutPrefix(line, "Version:"); ok {
		line = strings.TrimSpace(rest)
	}
	if len(line) > 80 {
		line = line[:80]
	}
	return line
}

// RequiredScannerExecutions is the mandatory logical execution set for a full
// audit. Trivy filesystem and configuration scans are deliberately separate:
// one successful mode must never hide a failure in the other.
var RequiredScannerExecutions = []string{"aitriage", "semgrep", "trivy_fs", "trivy_config", "gitleaks", "bandit"}

// RequiredExternalScanners is kept for callers that reason about installed
// binaries rather than logical executions.
var RequiredExternalScanners = []string{"semgrep", "trivy", "gitleaks", "bandit"}
