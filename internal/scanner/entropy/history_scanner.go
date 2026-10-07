package entropy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// HistoryLeak represents a secret or sensitive data found in git history.
type HistoryLeak struct {
	FilePath    string    `json:"file_path"`
	CommitHash  string    `json:"commit_hash"`
	CommitDate  time.Time `json:"commit_date"`
	Author      string    `json:"author"`
	Pattern     string    `json:"pattern"`      // "AWS Key", "Private Key", etc.
	LinePreview string    `json:"line_preview"` // truncated/redacted
	IsDeleted   bool      `json:"is_deleted"`   // true if the line was later removed
}

// secretPatterns are regex patterns for known secret formats.
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----`)},
	{"GitHub Token", regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`)},
	{"GitLab Token", regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}["']?`)},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret|password|passwd|token)\s*[=:]\s*["'][^"']{8,}["']`)},
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Stripe Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"SendGrid Key", regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
}

var redactRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{12,}`)

// ScanGitHistory searches git commit history for leaked secrets.
// Scans added lines (diff patches) across all commits.
func ScanGitHistory(projectPath string) []HistoryLeak {
	leaks, _ := ScanGitHistoryWithContext(context.Background(), projectPath)
	return leaks
}

// ScanGitHistoryWithContext distinguishes an empty history from a failed scan.
func ScanGitHistoryWithContext(parent context.Context, projectPath string) ([]HistoryLeak, error) {
	// Check prerequisites
	if _, err := exec.LookPath("git"); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(projectPath, ".git")); err != nil {
		return nil, err
	}

	var leaks []HistoryLeak

	// Get compact diff log: only added lines with commit metadata
	// Limit to last 50 commits and 30s timeout for performance
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "log", "-50", "--all",
		"--pretty=format:COMMIT:%H|%ae|%aI",
		"-p", "--diff-filter=ACMR",
		"--", "*.yaml", "*.yml", "*.json", "*.toml", "*.env",
		"*.env.*", "*.conf", "*.cfg", "*.ini", "*.properties",
		"*.go", "*.py", "*.js", "*.ts", "*.rb", "*.java",
	)
	cmd.Dir = projectPath
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var currentCommit, currentAuthor string
	var currentDate time.Time
	var currentFile string

	for _, line := range strings.Split(string(out), "\n") {
		// Parse commit header
		if strings.HasPrefix(line, "COMMIT:") {
			parts := strings.SplitN(line[7:], "|", 3)
			if len(parts) >= 3 {
				currentCommit = parts[0][:8] // short hash
				currentAuthor = parts[1]
				currentDate, _ = time.Parse(time.RFC3339, parts[2])
			}
			continue
		}

		// Track current file from diff header
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:]
			continue
		}

		// Only check added lines (lines starting with +, excluding +++)
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}

		addedLine := line[1:] // strip leading +

		// Check against all secret patterns
		for _, sp := range secretPatterns {
			if sp.pattern.MatchString(addedLine) {
				preview := redactLine(addedLine, 80)
				leaks = append(leaks, HistoryLeak{
					FilePath:    currentFile,
					CommitHash:  currentCommit,
					CommitDate:  currentDate,
					Author:      currentAuthor,
					Pattern:     sp.name,
					LinePreview: preview,
					IsDeleted:   false, // we'd need another pass to check deletion
				})
				break // one pattern match per line is enough
			}
		}
	}

	// Deduplicate: same file + same pattern → keep the oldest
	seen := make(map[string]bool)
	var deduped []HistoryLeak
	for _, leak := range leaks {
		key := leak.FilePath + "|" + leak.Pattern + "|" + leak.CommitHash
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, leak)
		}
	}

	// Cap at 50 results
	if len(deduped) > 50 {
		deduped = deduped[:50]
	}

	return deduped, nil
}

// redactLine truncates and partially redacts a line for safe display.
func redactLine(line string, maxLen int) string {
	line = strings.TrimSpace(line)
	if len(line) > maxLen {
		line = line[:maxLen] + "..."
	}
	// Redact long strings that look like keys (>12 alphanumeric chars)
	line = redactRe.ReplaceAllStringFunc(line, func(s string) string {
		if len(s) <= 12 {
			return s
		}
		return s[:4] + "****" + s[len(s)-4:]
	})
	return line
}
