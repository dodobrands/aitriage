package graph

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// classificationPromptFinding binds a model-visible batch position to a stable
// finding identity. A model cannot safely reuse an answer from another finding
// without echoing this identity back.
type classificationPromptFinding struct {
	FindingIndex int             `json:"finding_index"`
	FindingID    string          `json:"finding_id"`
	Fingerprint  string          `json:"fingerprint"`
	Finding      EnrichedFinding `json:"finding"`
}

type classificationAuditCollector struct {
	mu      sync.Mutex
	entries []ClassificationAuditEntry
}

func (c *classificationAuditCollector) record(entry ClassificationAuditEntry) {
	c.mu.Lock()
	c.entries = append(c.entries, entry)
	c.mu.Unlock()
}

func (c *classificationAuditCollector) snapshot() []ClassificationAuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ClassificationAuditEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

func newClassificationAuditEntry(attempt int, globalIndices []int, findings []EnrichedFinding, rawResponse string) ClassificationAuditEntry {
	entry := ClassificationAuditEntry{
		Attempt:              attempt,
		UniqueFindingIndices: append([]int(nil), globalIndices...),
		RawResponse:          rawResponse,
	}
	for _, finding := range findings {
		entry.FindingIDs = append(entry.FindingIDs, findingIdentity(finding))
		entry.Fingerprints = append(entry.Fingerprints, Fingerprint(finding))
	}
	return entry
}

func findingIdentity(f EnrichedFinding) string {
	if strings.TrimSpace(f.VulnID) != "" {
		return f.VulnID
	}
	return f.ID
}

// validateLLMDisposition checks one model verdict. A non-empty reject reason
// means the verdict is not trusted: the finding is retried and otherwise
// defaults to Needs Manual Review. A non-empty note means the verdict was
// accepted in a weaker form, such as a False Positive kept for manual review
// by policy; the note is recorded in the classification audit.
func validateLLMDisposition(projectPath string, finding EnrichedFinding, raw rawDisposition, policy validationPolicy) (FindingDisposition, string, string) {
	if raw.FindingID != findingIdentity(finding) {
		return FindingDisposition{}, "finding_id does not match requested finding", ""
	}
	if raw.Fingerprint != Fingerprint(finding) {
		return FindingDisposition{}, "fingerprint does not match requested finding", ""
	}
	confidence := normalizeConfidence(raw.Confidence)
	if raw.Disposition == "False Positive" {
		if err := validateFalsePositiveEvidence(projectPath, finding, raw.Evidence); err != nil {
			return FindingDisposition{}, err.Error(), ""
		}
		if violatesCriticalConfidencePolicy(policy, finding, confidence) {
			note := fmt.Sprintf("false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence requires high confidence, model reported %q", confidence)
			return FindingDisposition{
				Disposition: "Needs Manual Review",
				Rationale:   "Kept for manual review: a CRITICAL finding is only dismissed with high model confidence (policy fp_critical_requires_high_confidence). Model rationale: " + raw.Rationale,
				Confidence:  confidence,
				Evidence:    raw.Evidence,
			}, "", note
		}
	}
	return FindingDisposition{
		Disposition: raw.Disposition,
		Rationale:   raw.Rationale,
		Confidence:  confidence,
		Evidence:    raw.Evidence,
	}, "", ""
}

// violatesCriticalConfidencePolicy reports whether a False Positive for a
// CRITICAL finding lacks the high confidence the policy demands.
func violatesCriticalConfidencePolicy(policy validationPolicy, finding EnrichedFinding, confidence string) bool {
	return policy.fpCriticalRequiresHighConfidence &&
		strings.EqualFold(strings.TrimSpace(finding.Severity), "CRITICAL") &&
		normalizeConfidence(confidence) != "high"
}

func validateFalsePositiveEvidence(projectPath string, finding EnrichedFinding, evidence *DispositionEvidence) error {
	if evidence == nil {
		return fmt.Errorf("false positive has no evidence")
	}
	switch evidence.Basis {
	case "test_only":
		if !isTestPath(finding.File) {
			return fmt.Errorf("test_only evidence does not reference a test finding")
		}
		if evidence.File == "" {
			return fmt.Errorf("test_only evidence file is missing")
		}
		if _, err := matchingProjectFile(projectPath, finding.File, evidence.File); err != nil {
			return fmt.Errorf("test_only evidence file is invalid: %w", err)
		}
		if evidence.Line > 0 && finding.Line > 0 && evidence.Line != finding.Line {
			return fmt.Errorf("test_only evidence line does not match finding line")
		}
		return nil
	case "code_mitigation":
		return validateCodeMitigation(projectPath, finding, evidence)
	default:
		return fmt.Errorf("false positive evidence basis %q is not deterministically verifiable", evidence.Basis)
	}
}

// validateCodeMitigation accepts code_mitigation evidence only when it points
// at code, other than the flagged statement itself, that exists on the cited
// line. Quoting text that merely exists in the file was enough before: models
// cited comments, configuration, and the vulnerable line itself.
func validateCodeMitigation(projectPath string, finding EnrichedFinding, evidence *DispositionEvidence) error {
	observed := evidence.Observed
	if evidence.File == "" || evidence.Line < 1 || len(strings.TrimSpace(observed)) < 4 {
		return fmt.Errorf("code_mitigation evidence is incomplete")
	}
	if isConfigOrDataFile(finding.File) {
		return fmt.Errorf("code_mitigation evidence rejected: %s is a configuration or data file, which contains no code that mitigates", filepath.Base(normalizePath(finding.File)))
	}
	path, err := matchingProjectFile(projectPath, finding.File, evidence.File)
	if err != nil {
		return fmt.Errorf("code_mitigation evidence file is invalid: %w", err)
	}
	lines, err := readSourceLines(path)
	if err != nil {
		return fmt.Errorf("code_mitigation evidence is unreadable: %w", err)
	}
	if evidence.Line > len(lines) {
		return fmt.Errorf("code_mitigation evidence is unreadable: line %d is outside source file", evidence.Line)
	}
	line := lines[evidence.Line-1]
	if !strings.Contains(line, observed) {
		return fmt.Errorf("code_mitigation observed text is absent from source")
	}
	kinds := lineRegions(lines, evidence.Line-1, syntaxForPath(path))
	sameLine := finding.Line > 0 && evidence.Line == finding.Line
	if sameLine && isCriticalOrHigh(finding.Severity) {
		// A serious finding goes to a person rather than be dismissed by
		// anything on its own line.
		return fmt.Errorf("code_mitigation evidence rejected: a mitigation on the flagged line itself is not accepted for %s findings", strings.ToUpper(strings.TrimSpace(finding.Severity)))
	}
	if region := observedRegion(line, kinds, observed); region != "" {
		return fmt.Errorf("code_mitigation evidence rejected: observed text lies inside a %s, not in code", region)
	}
	if sameLine && coversStatement(statementText(line, kinds), observed) {
		return fmt.Errorf("code_mitigation evidence rejected: observed text is the flagged statement itself, which cannot be its own mitigation")
	}
	if !hasCodeTokens(observed) {
		return fmt.Errorf("code_mitigation evidence rejected: observed text has no code tokens (prose is not a mitigation)")
	}
	return nil
}

func isCriticalOrHigh(severity string) bool {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return true
	default:
		return false
	}
}

// coversStatement reports whether observed is (most of) the flagged
// statement. Whitespace is ignored so reformatting cannot dodge the check.
func coversStatement(statement, observed string) bool {
	stmt := stripWhitespace(statement)
	obs := stripWhitespace(observed)
	if stmt == "" || obs == "" {
		return true
	}
	return obs == stmt || 2*len(obs) > len(stmt)
}

func stripWhitespace(text string) string {
	return strings.Join(strings.Fields(text), "")
}

// codeTokenPatterns recognise text that is code rather than prose: an
// operator or bracket, a dotted member access, a snake_case or camelCase
// identifier.
var codeTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile("[(){}\\[\\]=<>;$@&|`]|::|->|=>"),
	regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_]`),
	regexp.MustCompile(`[A-Za-z0-9]_[A-Za-z0-9]`),
	regexp.MustCompile(`[a-z][A-Z]`),
}

func hasCodeTokens(observed string) bool {
	for _, pattern := range codeTokenPatterns {
		if pattern.MatchString(observed) {
			return true
		}
	}
	return false
}

// isConfigOrDataFile reports whether a path holds configuration or data
// rather than code. Such files can describe a mitigation but never perform
// one, so code_mitigation evidence is not accepted for them.
func isConfigOrDataFile(path string) bool {
	base := strings.ToLower(filepath.Base(normalizePath(path)))
	switch filepath.Ext(base) {
	case ".yaml", ".yml", ".json", ".jsonc", ".json5", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".tfvars":
		return true
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || base == ".htaccess" ||
		strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.")
}

func isTestPath(path string) bool {
	p := strings.ToLower("/" + normalizePath(path) + "/")
	base := strings.TrimSuffix(filepath.Base(p), "/")
	return strings.Contains(p, "/test/") || strings.Contains(p, "/tests/") ||
		strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

// matchingProjectFile resolves both the scanner's finding path and the model's
// evidence path to the same canonical file. Absolute paths are accepted only
// when they remain inside the scanned project. This is necessary for container
// scans, where findings intentionally use absolute /workspace paths, while still
// rejecting traversal and symlink escapes.
func matchingProjectFile(projectPath, findingPath, evidencePath string) (string, error) {
	if strings.TrimSpace(findingPath) == "" || strings.TrimSpace(evidencePath) == "" {
		return "", fmt.Errorf("finding and evidence paths are required")
	}
	findingResolved, err := resolveProjectFile(projectPath, findingPath)
	if err != nil {
		return "", fmt.Errorf("finding path: %w", err)
	}
	evidenceResolved, err := resolveProjectFile(projectPath, evidencePath)
	if err != nil {
		return "", fmt.Errorf("evidence path: %w", err)
	}
	if findingResolved != evidenceResolved {
		return "", fmt.Errorf("evidence file does not match finding file")
	}
	return evidenceResolved, nil
}

func resolveProjectFile(projectPath, candidate string) (string, error) {
	root, err := filepath.Abs(projectPath)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	path := candidate
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.Clean(path))
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes project root")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path is not a regular file")
	}
	return path, nil
}

// readSourceLines returns the file split into lines without line endings.
func readSourceLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines, nil
}
