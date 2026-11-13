package graph

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/regions"
)

// classificationPromptFinding binds a model-visible batch position to a stable
// finding identity. A model cannot safely reuse an answer from another finding
// without echoing this identity back. The display id is that identity: it is
// unique within a run, and models echo it faithfully (see
// validateLLMDisposition).
type classificationPromptFinding struct {
	FindingIndex int             `json:"finding_index"`
	FindingID    string          `json:"finding_id"`
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
//
// A verdict is bound to its finding by finding_index, which the caller
// resolves, and finding_id: display ids are unique within a run
// (assignVulnIDs), so the pair names exactly one finding. The fingerprint is
// neither asked for nor checked. Models echo a short display id faithfully
// but often garble a 32-digit hex string (truncated, unrelated digits, the
// neighbouring finding's), and rejecting those verdicts only bought retries
// whose answers could differ from the first.
func validateLLMDisposition(projectPath string, finding EnrichedFinding, raw rawDisposition, policy validationPolicy) (FindingDisposition, string, string) {
	if raw.FindingID != findingIdentity(finding) {
		return FindingDisposition{}, "finding_id does not match requested finding", ""
	}
	confidence := normalizeConfidence(raw.Confidence)
	evidence := raw.Evidence
	if raw.Disposition == "False Positive" {
		accepted, err := validateFalsePositiveEvidence(projectPath, finding, raw.Evidence)
		if err != nil {
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
		evidence = accepted
		if violatesCriticalConfidencePolicy(policy, finding, confidence) {
			note := fmt.Sprintf("false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence requires high confidence, model reported %q", confidence)
			return FindingDisposition{
				Disposition: "Needs Manual Review",
				Rationale:   "Kept for manual review: a CRITICAL finding is only dismissed with high model confidence (policy fp_critical_requires_high_confidence). Model rationale: " + raw.Rationale,
				Confidence:  confidence,
				Evidence:    evidence,
			}, "", note
		}
	}
	return FindingDisposition{
		Disposition: raw.Disposition,
		Rationale:   raw.Rationale,
		Confidence:  confidence,
		Evidence:    evidence,
	}, "", ""
}

// violatesCriticalConfidencePolicy reports whether a False Positive for a
// CRITICAL finding lacks the high confidence the policy demands.
func violatesCriticalConfidencePolicy(policy validationPolicy, finding EnrichedFinding, confidence string) bool {
	return policy.fpCriticalRequiresHighConfidence &&
		strings.EqualFold(strings.TrimSpace(finding.Severity), "CRITICAL") &&
		normalizeConfidence(confidence) != "high"
}

// validateFalsePositiveEvidence checks the evidence of a False Positive and
// returns it as accepted, which is what the disposition records: test_only
// evidence as given, code_mitigation evidence on the line its text was found
// on (see validateCodeMitigation).
func validateFalsePositiveEvidence(projectPath string, finding EnrichedFinding, evidence *DispositionEvidence) (*DispositionEvidence, error) {
	if isHardcodedSecret(finding) {
		// A committed credential is exposed wherever it sits, a test fixture
		// included: whether it is real, revoked or a placeholder is for a
		// person to decide. No evidence basis dismisses it automatically.
		return nil, fmt.Errorf("a hardcoded secret is never dismissed automatically, whatever the evidence: %w", errPersonMustDecide)
	}
	if evidence == nil {
		return nil, fmt.Errorf("false positive has no evidence")
	}
	switch evidence.Basis {
	case "test_only":
		// The finding's own line, exactly: the evidence says the flagged line
		// is test code, so it has no other line to drift to.
		if !isTestPath(finding.File) {
			return nil, fmt.Errorf("test_only evidence does not reference a test finding")
		}
		if evidence.File == "" {
			return nil, fmt.Errorf("test_only evidence file is missing")
		}
		if _, err := matchingProjectFile(projectPath, finding.File, evidence.File); err != nil {
			return nil, fmt.Errorf("test_only evidence file is invalid: %w", err)
		}
		if evidence.Line > 0 && finding.Line > 0 && evidence.Line != finding.Line {
			return nil, fmt.Errorf("test_only evidence line does not match finding line")
		}
		return evidence, nil
	case "code_mitigation":
		return validateCodeMitigation(projectPath, finding, evidence)
	default:
		return nil, fmt.Errorf("false positive evidence basis %q is not deterministically verifiable", evidence.Basis)
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
	// maxEvidenceLineDrift is how many lines away from evidence.line the
	// observed text is looked for when that line does not hold it. Models
	// often quote the right code with a line number a few lines off, and
	// rejecting those answers sent real false positives to manual review.
	// Every check runs on the line the text is found on, so the tolerance
	// accepts nothing the right line number would not; a window this small
	// keeps the text from being matched in some unrelated part of the file.
	maxEvidenceLineDrift = 5
)

// errPersonMustDecide marks code_mitigation evidence for a finding that only a
// person may dismiss. The verdict is kept as Needs Manual Review rather than
// rejected and asked again: the model would only repeat it.
var errPersonMustDecide = errors.New("a person must decide")

// validateCodeMitigation accepts code_mitigation evidence only when it is tied
// to the finding: code only (no byte of it in a comment or string literal), in
// the same source file, above the flagged line and at most
// maxMitigationDistance lines away, naming a variable or function of the
// flagged statement, and shaped like a mitigation of it: a guard of that name
// or a re-assignment of it through a call, in the same function (see
// checkMitigationShape). Quoting code-looking text anywhere in the file was
// enough before: models cited comments, configuration, the vulnerable line
// itself, unrelated assignments, the tainted assignment, log calls and checks
// in other functions. CRITICAL findings and hardcoded secrets are never
// dismissed by code_mitigation.
//
// The observed text is the first non-blank line of evidence.observed (see
// firstObservedLine), looked up on evidence.line or, when that line does not
// hold it, on the nearest line within maxEvidenceLineDrift (see
// nearestLineWith). Every check then runs on the line the text was found on,
// and the evidence is returned with that line and text, so the disposition
// cites the code that was checked.
func validateCodeMitigation(projectPath string, finding EnrichedFinding, evidence *DispositionEvidence) (*DispositionEvidence, error) {
	if subject := personOnlyFinding(finding); subject != "" {
		return nil, fmt.Errorf("code_mitigation evidence is not accepted for %s: %w", subject, errPersonMustDecide)
	}
	observed := firstObservedLine(evidence.Observed)
	if evidence.File == "" || evidence.Line < 1 || len(strings.TrimSpace(observed)) < 4 {
		return nil, fmt.Errorf("code_mitigation evidence is incomplete")
	}
	if isConfigOrDataFile(finding.File) {
		return nil, fmt.Errorf("code_mitigation evidence rejected: %s is a configuration or data file, which contains no code that mitigates", filepath.Base(normalizePath(finding.File)))
	}
	path, err := matchingProjectFile(projectPath, finding.File, evidence.File)
	if err != nil {
		return nil, fmt.Errorf("code_mitigation evidence file is invalid: %w", err)
	}
	syntax := regions.SyntaxForPath(path)
	if !syntax.Known() {
		return nil, fmt.Errorf("code_mitigation evidence rejected: %s is not a recognised source language, so the cited text cannot be checked for comments and string literals", filepath.Base(path))
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("code_mitigation evidence is unreadable: %w", err)
	}
	lines := splitSourceLines(source)
	if finding.Line > len(lines) {
		return nil, fmt.Errorf("code_mitigation evidence is unreadable: flagged line %d is outside source file", finding.Line)
	}
	found := nearestLineWith(lines, evidence.Line, observed)
	if found == 0 {
		return nil, fmt.Errorf("code_mitigation observed text is absent from source: it is neither on line %d nor within %d lines of it", evidence.Line, maxEvidenceLineDrift)
	}
	accepted := *evidence
	accepted.Line, accepted.Observed = found, observed
	if err := checkCitedMitigation(path, source, lines, syntax, finding, &accepted); err != nil {
		if found != evidence.Line {
			return nil, fmt.Errorf("%w (the observed text is on line %d, not on the cited line %d)", err, found, evidence.Line)
		}
		return nil, err
	}
	return &accepted, nil
}

// checkCitedMitigation runs the checks that tie code_mitigation evidence to
// its finding on evidence.Line, the line that holds evidence.Observed:
// placement, code only, shared names and the shape of a mitigation.
func checkCitedMitigation(path string, source []byte, lines []string, syntax regions.Syntax, finding EnrichedFinding, evidence *DispositionEvidence) error {
	if err := checkMitigationPlacement(finding.Line, evidence.Line); err != nil {
		return err
	}
	// The evidence line is above the flagged line, so both are scanned.
	fileRegions := regions.Lines(lines, finding.Line-1+maxStatementLines, syntax)
	line, kinds := lines[evidence.Line-1], fileRegions[evidence.Line-1]
	starts, where := codeOccurrences(line, kinds, evidence.Observed)
	if len(starts) == 0 {
		return fmt.Errorf("code_mitigation evidence rejected: observed text %s", where)
	}
	if !hasCodeTokens(evidence.Observed) {
		return fmt.Errorf("code_mitigation evidence rejected: observed text has no code tokens (prose is not a mitigation)")
	}
	cited := citedIdentifiers(line, starts, len(evidence.Observed))
	flagged := statementIdentifiers(lines, fileRegions, finding.Line-1)
	shared := sharedIdentifiers(cited, flagged)
	if len(shared) == 0 {
		return fmt.Errorf("code_mitigation evidence rejected: observed text shares no identifier with the flagged statement on line %d; cite the code that checks or transforms the data it uses", finding.Line)
	}
	return checkMitigationShape(path, source, lines, fileRegions, finding, evidence, starts, shared)
}

// firstObservedLine is the part of evidence.observed that is looked up and
// checked: its first non-blank line, without trailing whitespace. Models
// quote a guard together with the statement under it (the if line and its
// raise or return); the first line is the one evidence.line should name, and
// text spanning several lines is never found on a single source line.
// Leading whitespace is kept: it matches the line's indentation.
func firstObservedLine(observed string) string {
	for _, line := range strings.Split(observed, "\n") {
		if line = strings.TrimRight(line, " \t\r"); line != "" {
			return line
		}
	}
	return ""
}

// nearestLineWith returns the number of the line, counted from 1, that holds
// text: cited itself when it does, otherwise the nearest line at most
// maxEvidenceLineDrift lines away, or 0 when no line in that window holds
// text. Of two lines equally near, the one above wins. Any fixed choice keeps
// the result reproducible; the line above is chosen because a mitigation runs
// before the flagged statement, so it is the likelier of the two to be one.
// The nearest line is taken even when it then fails a check: the search
// fixes a miscounted line number, it does not look for a line that passes.
func nearestLineWith(lines []string, cited int, text string) int {
	holds := func(n int) bool {
		return n >= 1 && n <= len(lines) && strings.Contains(lines[n-1], text)
	}
	if holds(cited) {
		return cited
	}
	for distance := 1; distance <= maxEvidenceLineDrift; distance++ {
		if holds(cited - distance) {
			return cited - distance
		}
		if holds(cited + distance) {
			return cited + distance
		}
	}
	return 0
}

// personOnlyFinding names why code_mitigation evidence can never dismiss a
// finding, or returns "". A CRITICAL finding is too severe to drop on the
// strength of nearby code, and a hardcoded secret is exposed in the source
// whatever code surrounds it (validateFalsePositiveEvidence stops those
// before any basis is considered).
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

// sharedIdentifiers returns the names two sets have in common.
func sharedIdentifiers(a, b map[string]bool) map[string]bool {
	shared := map[string]bool{}
	for name := range a {
		if b[name] {
			shared[name] = true
		}
	}
	return shared
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

// splitSourceLines splits a file into lines without line endings. Byte
// offsets within a line are the same as in the file, which the syntax tree
// checks rely on.
func splitSourceLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}
