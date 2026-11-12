package graph

import (
	"errors"
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
			if !errors.Is(err, errPersonMustDecide) {
				return FindingDisposition{}, err.Error(), ""
			}
			// The model did answer; the answer is just not one the tool may
			// act on alone. Asking again would only repeat it.
			return FindingDisposition{
				Disposition: "Needs Manual Review",
				Rationale:   "Kept for manual review: " + err.Error() + ". Model rationale: " + raw.Rationale,
				Confidence:  confidence,
				Evidence:    raw.Evidence,
			}, "", "false positive kept as Needs Manual Review: " + err.Error()
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

// Limits that tie code_mitigation evidence to its finding. A check that
// protects a statement normally sits a few lines above it, in the same
// function, and names the data the statement uses. Code further away, after
// the statement, or about other names is unrelated code that merely looks
// protective, which is what models cited to dismiss findings.
const (
	// maxMitigationDistance is how many lines above the flagged line the
	// cited code may sit. A fixed window works for every language and is
	// what the classification prompt states.
	maxMitigationDistance = 30
	// maxStatementLines bounds how many lines a flagged statement is followed
	// for when a parenthesis or bracket opened on the flagged line is still
	// open, as in a call with one argument per line.
	maxStatementLines = 10
	// minSharedIdentifierLength leaves out one-letter names (i, r, w, x):
	// they are too common to tie a line to a finding.
	minSharedIdentifierLength = 2
)

// errPersonMustDecide marks code_mitigation evidence for a finding that only a
// person may dismiss. The verdict is kept as Needs Manual Review rather than
// rejected and asked again: the model would only repeat it.
var errPersonMustDecide = errors.New("a person must decide")

// validateCodeMitigation accepts code_mitigation evidence only when it is tied
// to the finding: code only (no byte of it in a comment or string literal), in
// the same source file, above the flagged line and at most
// maxMitigationDistance lines away, and naming a variable or function of the
// flagged statement. Quoting code-looking text anywhere in the file was
// enough before: models cited comments, configuration, the vulnerable line
// itself and unrelated assignments. CRITICAL findings and hardcoded secrets
// are never dismissed by code_mitigation.
func validateCodeMitigation(projectPath string, finding EnrichedFinding, evidence *DispositionEvidence) error {
	if subject := personOnlyFinding(finding); subject != "" {
		return fmt.Errorf("code_mitigation evidence is not accepted for %s: %w", subject, errPersonMustDecide)
	}
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
	if err := checkMitigationPlacement(finding.Line, evidence.Line); err != nil {
		return err
	}
	syntax := syntaxForPath(path)
	if syntax.leadingOnly {
		return fmt.Errorf("code_mitigation evidence rejected: %s is not a recognised source language, so the cited text cannot be checked for comments and string literals", filepath.Base(path))
	}
	lines, err := readSourceLines(path)
	if err != nil {
		return fmt.Errorf("code_mitigation evidence is unreadable: %w", err)
	}
	if finding.Line > len(lines) {
		return fmt.Errorf("code_mitigation evidence is unreadable: flagged line %d is outside source file", finding.Line)
	}
	// The evidence line is above the flagged line, so both are scanned.
	regions := fileRegions(lines, finding.Line-1+maxStatementLines, syntax)
	line, kinds := lines[evidence.Line-1], regions[evidence.Line-1]
	if !strings.Contains(line, observed) {
		return fmt.Errorf("code_mitigation observed text is absent from source")
	}
	starts, where := codeOccurrences(line, kinds, observed)
	if len(starts) == 0 {
		return fmt.Errorf("code_mitigation evidence rejected: observed text %s", where)
	}
	if !hasCodeTokens(observed) {
		return fmt.Errorf("code_mitigation evidence rejected: observed text has no code tokens (prose is not a mitigation)")
	}
	cited := citedIdentifiers(line, starts, len(observed))
	flagged := statementIdentifiers(lines, regions, finding.Line-1)
	if !sharesIdentifier(cited, flagged) {
		return fmt.Errorf("code_mitigation evidence rejected: observed text shares no identifier with the flagged statement on line %d; cite the code that checks or transforms the data it uses", finding.Line)
	}
	return nil
}

// personOnlyFinding names why code_mitigation evidence can never dismiss a
// finding, or returns "". A CRITICAL finding is too severe to drop on the
// strength of nearby code, and a hardcoded secret is exposed in the source
// whatever code surrounds it.
func personOnlyFinding(f EnrichedFinding) string {
	switch {
	case strings.EqualFold(strings.TrimSpace(f.Severity), "CRITICAL"):
		return "a CRITICAL finding"
	case isHardcodedSecret(f):
		return "a hardcoded secret"
	default:
		return ""
	}
}

// checkMitigationPlacement requires the cited line to run before the flagged
// line and close to it. The flagged line itself never qualifies: a statement
// is not its own mitigation, and nothing else on its line can be told apart
// from it reliably.
func checkMitigationPlacement(findingLine, evidenceLine int) error {
	switch {
	case findingLine < 1:
		return fmt.Errorf("code_mitigation evidence rejected: the finding has no line, so no mitigation can be tied to it")
	case evidenceLine == findingLine:
		return fmt.Errorf("code_mitigation evidence rejected: evidence.line must cite code other than the flagged line itself")
	case evidenceLine > findingLine:
		return fmt.Errorf("code_mitigation evidence rejected: line %d is after the flagged line %d; a mitigation must run before the flagged statement", evidenceLine, findingLine)
	case findingLine-evidenceLine > maxMitigationDistance:
		return fmt.Errorf("code_mitigation evidence rejected: line %d is more than %d lines above the flagged line %d", evidenceLine, maxMitigationDistance, findingLine)
	default:
		return nil
	}
}

// sharesIdentifier reports whether two name sets intersect.
func sharesIdentifier(a, b map[string]bool) bool {
	for name := range a {
		if b[name] {
			return true
		}
	}
	return false
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
