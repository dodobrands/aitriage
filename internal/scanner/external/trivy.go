package external

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/config"
)

// trivyOutput is the part of Trivy's JSON report that AITriage reads. `trivy
// fs` fills Vulnerabilities and `trivy config` fills Misconfigurations; the
// envelope is shared, so one decoder serves both modes. Decoding only
// Vulnerabilities used to make every IaC scan report zero findings.
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string                  `json:"Target"`
	Vulnerabilities   []trivyVulnerability    `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	PrimaryURL       string `json:"PrimaryURL"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

type trivyMisconfiguration struct {
	// Trivy 0.72 reports ID as "AWS-0107" and omits AVDID; older releases
	// filled AVDID ("AVD-AWS-0107") as well.
	ID          string `json:"ID"`
	AVDID       string `json:"AVDID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	PrimaryURL  string `json:"PrimaryURL"`
	// Status is FAIL for a violated check. PASS and EXCEPTION entries only
	// appear with --include-non-failures or an exception policy and are not
	// findings.
	Status        string `json:"Status"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"CauseMetadata"`
}

// RunTrivy runs trivy and returns unified findings.
// scanType: "fs" (dependency vulnerabilities) or "config" (IaC misconfigurations).
// Options come from the project's .aitriage.yaml (scanners.trivy) and its
// Trivy ignore file.
func RunTrivy(ctx context.Context, path, scanType string) ([]UnifiedFinding, error) {
	if !IsInstalled("trivy") {
		return nil, fmt.Errorf("trivy not installed")
	}
	if scanType == "" {
		scanType = "fs"
	}
	args, err := trivyArgs(path, scanType, config.LoadConfig(path).Scanners.Trivy)
	if err != nil {
		return nil, err
	}
	result, err := RunTool(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}
	// Without --exit-code Trivy exits 0 whether or not it finds anything, so a
	// non-zero exit with no report is a failed run. The reason (an unknown
	// flag, an unreadable ignore file) is on stderr, and "failed to parse
	// trivy output" alone would hide it.
	if result.ExitCode != 0 && strings.TrimSpace(result.Stdout) == "" {
		return nil, fmt.Errorf("trivy %s exited with code %d: %s", scanType, result.ExitCode, trivyErrorLine(result.Stderr))
	}
	return parseTrivyReport([]byte(result.Stdout))
}

// parseTrivyReport converts a Trivy JSON report into unified findings.
func parseTrivyReport(data []byte) ([]UnifiedFinding, error) {
	var output trivyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}
	var findings []UnifiedFinding
	for _, res := range output.Results {
		if isGeneratedArtifactPath(res.Target) {
			continue
		}
		for _, v := range res.Vulnerabilities {
			findings = append(findings, UnifiedFinding{
				Source:   "trivy",
				RuleID:   v.VulnerabilityID,
				Severity: v.Severity,
				// The message doubles as baseline evidence for external
				// findings; its format is kept so accepted CVEs stay accepted.
				Message:          fmt.Sprintf("%s: %s", v.Title, v.Description),
				File:             res.Target,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				PrimaryURL:       v.PrimaryURL,
			})
		}
		for _, m := range res.Misconfigurations {
			// An entry without a status (the bundled Trivy always sets one) is
			// kept: a report format change must not silently empty the scan.
			if status := strings.ToUpper(strings.TrimSpace(m.Status)); status != "" && status != "FAIL" {
				continue
			}
			findings = append(findings, misconfigurationFinding(res.Target, m))
		}
	}
	return findings, nil
}

func misconfigurationFinding(target string, m trivyMisconfiguration) UnifiedFinding {
	id := strings.TrimSpace(m.ID)
	if id == "" {
		id = strings.TrimSpace(m.AVDID)
	}
	// Message names the concrete violation ("Bucket has a public ACL"); the
	// description is the generic text of the check and only a fallback.
	detail := strings.TrimSpace(m.Message)
	if detail == "" {
		detail = strings.TrimSpace(m.Description)
	}
	message := strings.TrimSpace(m.Title)
	switch {
	case message == "":
		message = detail
	case detail != "":
		message = message + ": " + detail
	}
	finding := UnifiedFinding{
		Kind:       KindMisconfiguration,
		Source:     "trivy",
		RuleID:     id,
		Severity:   m.Severity,
		Message:    message,
		File:       target,
		Suggestion: strings.TrimSpace(m.Resolution),
		PrimaryURL: m.PrimaryURL,
	}
	// A check about something absent (a Dockerfile without USER) has no
	// cause line; it stays a file-level finding.
	if m.CauseMetadata.StartLine > 0 {
		finding.Line = m.CauseMetadata.StartLine
		if m.CauseMetadata.EndLine >= m.CauseMetadata.StartLine {
			finding.EndLine = m.CauseMetadata.EndLine
		}
	}
	return finding
}

// trivyScanTypes are the Trivy subcommands AITriage drives. Their flag sets
// differ (`trivy config` rejects --ignore-unfixed and has no --scanners), so an
// unknown mode is refused rather than handed flags it may not accept.
var trivyScanTypes = map[string]bool{"fs": true, "config": true}

// trivyArgs builds the Trivy command line for one scan mode over root.
func trivyArgs(root, scanType string, opts config.TrivyScannerConfig) ([]string, error) {
	if !trivyScanTypes[scanType] {
		return nil, fmt.Errorf("unsupported trivy scan type %q: want fs or config", scanType)
	}
	severities, err := trivySeverities(opts.Severity)
	if err != nil {
		return nil, err
	}
	args := []string{scanType, "--format", "json", "--quiet"}
	if scanType == "fs" {
		// Dependency vulnerabilities only: secrets are Gitleaks' job, and with
		// Trivy's default "vuln,secret" its secret results were read and then
		// thrown away.
		args = append(args, "--scanners", "vuln")
		if opts.IgnoreUnfixed {
			args = append(args, "--ignore-unfixed")
		}
	}
	if len(severities) > 0 {
		args = append(args, "--severity", strings.Join(severities, ","))
	}
	if ignoreFile := trivyIgnoreFile(root); ignoreFile != "" {
		args = append(args, "--ignorefile", ignoreFile)
	}
	args = append(args, TrivySkipDirArgs(root)...)
	args = append(args, root)
	return args, nil
}

// trivySeverityNames is Trivy's severity vocabulary.
var trivySeverityNames = map[string]bool{"UNKNOWN": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

// trivySeverities normalizes scanners.trivy.severity. An unknown value is an
// error, not a silent drop: dropping "HIHG" from [CRITICAL, HIHG] would quietly
// narrow the scan, while an error fails the run with the reason attached.
func trivySeverities(values []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, value := range values {
		severity := strings.ToUpper(strings.TrimSpace(value))
		if severity == "" {
			continue
		}
		if !trivySeverityNames[severity] {
			return nil, fmt.Errorf("scanners.trivy.severity: unknown severity %q (want UNKNOWN, LOW, MEDIUM, HIGH or CRITICAL)", value)
		}
		if !seen[severity] {
			seen[severity] = true
			out = append(out, severity)
		}
	}
	return out, nil
}

// trivyIgnoreFileNames are the project ignore files Trivy understands, in the
// order AITriage prefers them. Trivy reads one ignore file per run. The YAML
// form wins when both exist: Trivy never loads it unless asked to, so its
// presence is a deliberate choice, and it can express everything the plain
// list can (plus paths and expiry dates).
var trivyIgnoreFileNames = []string{".trivyignore.yaml", ".trivyignore.yml", ".trivyignore"}

// trivyIgnoreWarned keeps one warning per project root: a scan runs Trivy
// twice (fs and config) and the conflict only needs reporting once.
var trivyIgnoreWarned sync.Map

// trivyIgnoreFile returns the absolute path of the project's Trivy ignore file,
// or "" when it has none.
//
// Trivy resolves its default ignore file (".trivyignore") against its working
// directory, not against the scan target. Scanner processes inherit AITriage's
// working directory, so in the container (working directory /project, the
// repository mounted at /github/workspace) a committed .trivyignore was never
// applied. Setting the working directory instead is not an option: scan paths
// may be relative to it and every other scanner would break. An explicit
// absolute path makes the result independent of where AITriage runs.
func trivyIgnoreFile(root string) string {
	// An ignore file chosen through Trivy's own environment variable is the
	// user's explicit decision; Trivy reads it without our help.
	if strings.TrimSpace(os.Getenv("TRIVY_IGNOREFILE")) != "" {
		return ""
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	var found []string
	for _, name := range trivyIgnoreFileNames {
		candidate := filepath.Join(abs, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			found = append(found, candidate)
		}
	}
	if len(found) == 0 {
		return ""
	}
	if len(found) > 1 {
		if _, warned := trivyIgnoreWarned.LoadOrStore(abs, true); !warned {
			skipped := make([]string, 0, len(found)-1)
			for _, path := range found[1:] {
				skipped = append(skipped, filepath.Base(path))
			}
			slog.Warn("Trivy reads one ignore file per run; merge the others into it",
				"using", filepath.Base(found[0]), "not_applied", strings.Join(skipped, ", "))
		}
	}
	return found[0]
}

// trivyErrorLine extracts the reason from Trivy's stderr: the last non-empty
// line, without the timestamp and level columns of Trivy's log format.
func trivyErrorLine(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	if line == "" {
		return "no error output"
	}
	if i := strings.LastIndexByte(line, '\t'); i >= 0 && i+1 < len(line) {
		line = strings.TrimSpace(line[i+1:])
	}
	if len(line) > 300 {
		line = line[:300] + "…"
	}
	return line
}
