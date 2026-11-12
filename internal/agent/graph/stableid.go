package graph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

// ── Stable finding identity ──────────────────────────────────────────────────
//
// CS-* ids used to be a running counter per keyword-guessed class, so adding
// one finding renumbered others, and Fingerprint includes the line number, so
// a line inserted above a finding made it "new" and cost a verdict-cache miss.
// stable_id follows GitHub code scanning's primaryLocationLineHash instead: it
// hashes the class, the project-relative file, the content of the flagged line
// and the occurrence of that content in the file, but never the line number.
// Edits elsewhere in the file leave it unchanged; a change to the flagged line
// gives a new identity, as it should.
//
//   - Dependency advisories are identified by advisory, package and manifest.
//   - File-scoped classes (a Dockerfile without USER) by class and file.
//   - Project-level findings by class, or by rule when no class covers it.
//
// Findings that still share an identity (two reports on one line that no
// class merges) are told apart by their position in the canonical order.

const stableIDLength = 32

// minVulnIDHex is the length of the stable-id prefix in a display id. A
// collision within one run extends the colliding ids.
const minVulnIDHex = 6

// assignStableIDs sets StableID on every finding. findings must already be in
// canonical order, which makes the tie-break for shared identities
// deterministic.
func assignStableIDs(projectPath string, findings []EnrichedFinding) {
	lines := newLineIndex(projectPath)
	seen := make(map[string]int, len(findings))
	for i := range findings {
		base := stableIdentity(findings[i], lines)
		n := seen[base]
		seen[base] = n + 1
		if n > 0 {
			base += "\x00#" + strconv.Itoa(n)
		}
		sum := sha256.Sum256([]byte(base))
		findings[i].StableID = hex.EncodeToString(sum[:])[:stableIDLength]
	}
}

func stableIdentity(f EnrichedFinding, lines *lineIndex) string {
	identity := "rule:" + strings.ToLower(strings.TrimSpace(f.Type)) + ":" +
		strings.ToLower(strings.TrimSpace(f.Source)) + ":" + strings.ToLower(strings.TrimSpace(f.ID))
	class, classified := findingClass(f)
	if classified {
		identity = "class:" + class.Key
	}
	file := normalizePath(f.File)
	switch {
	case isDependencyFinding(f):
		return strings.Join([]string{"advisory", strings.ToLower(strings.TrimSpace(f.ID)), strings.ToLower(strings.TrimSpace(f.Package)), file}, "\x00")
	case isEnvironmentFinding(f):
		// A probe result has no source location; the message names the host
		// and service.
		return strings.Join([]string{"environment", identity, strings.TrimSpace(f.Message)}, "\x00")
	case file == "":
		return strings.Join([]string{"project", identity}, "\x00")
	case classified && class.Scope == healthcheck.ScopeFile:
		return strings.Join([]string{"file", identity, file}, "\x00")
	default:
		content, occurrence := lines.lineIdentity(f.File, f.Line)
		return strings.Join([]string{"line", identity, file, content, strconv.Itoa(occurrence)}, "\x00")
	}
}

// assignVulnIDs sets the display id CS-<CLASS>-<hex> of every finding from
// its class code and stable id. Ids are unique within a run: colliding
// prefixes are lengthened until they differ.
func assignVulnIDs(findings []EnrichedFinding) {
	width := make([]int, len(findings))
	for i := range width {
		width[i] = minVulnIDHex
	}
	ids := make([]string, len(findings))
	for {
		groups := make(map[string][]int, len(findings))
		for i := range findings {
			ids[i] = vulnIDFor(findings[i], width[i])
			groups[ids[i]] = append(groups[ids[i]], i)
		}
		widened := false
		for _, group := range groups {
			if len(group) < 2 {
				continue
			}
			for _, i := range group {
				if width[i] < len(stableIDOf(findings[i])) {
					width[i] += 2
					widened = true
				}
			}
		}
		if !widened {
			break
		}
	}
	for i := range findings {
		findings[i].VulnID = ids[i]
	}
}

func vulnIDFor(f EnrichedFinding, width int) string {
	stable := stableIDOf(f)
	if width > len(stable) {
		width = len(stable)
	}
	return "CS-" + classCode(f) + "-" + strings.ToUpper(stable[:width])
}

// stableIDOf returns the finding's stable id, or its fingerprint for a finding
// built without enrichment.
func stableIDOf(f EnrichedFinding) string {
	if f.StableID != "" {
		return f.StableID
	}
	return Fingerprint(f)
}

// verdictCacheKey identifies a cached LLM verdict. It is built from what the
// model judged, without line numbers: the stable identity (which covers the
// flagged line), the rule and message, and the code window sent with the
// finding. A pure line shift therefore reuses the verdict; editing the flagged
// line or the code around it invalidates it.
func verdictCacheKey(f EnrichedFinding) string {
	payload := strings.Join([]string{
		"verdict-key-v1",
		stableIDOf(f),
		strings.ToLower(strings.TrimSpace(f.Type)),
		strings.ToLower(strings.TrimSpace(f.Source)),
		strings.ToLower(strings.TrimSpace(f.ID)),
		strings.TrimSpace(f.Message),
		normalizedSnippetWindow(f.Snippet),
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])[:stableIDLength]
}

// snippetLineRefs match the line numbers extractFullContext writes into the
// snippet header ("(lines 10-24)", "(around line 12)").
var snippetLineRefs = regexp.MustCompile(`\((?:lines \d+-\d+|around line \d+)\)`)

// normalizedSnippetWindow is the code window without its line numbers and
// without whitespace differences.
func normalizedSnippetWindow(snippet string) string {
	var out []string
	for _, line := range strings.Split(snippet, "\n") {
		line = snippetLineRefs.ReplaceAllString(line, "")
		if normalized := normalizeLineContent(line); normalized != "" {
			out = append(out, normalized)
		}
	}
	return strings.Join(out, "\n")
}

// normalizeLineContent collapses whitespace, so re-indenting a line does not
// change its identity.
func normalizeLineContent(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// maxIdentityFileBytes bounds the files read for line identities; the context
// extractor does not read larger ones either.
const maxIdentityFileBytes = 10 << 20

// lineIndex reads each file findings point at once.
type lineIndex struct {
	paths pathResolver
	files map[string][]string // normalized lines; nil when unreadable
}

func newLineIndex(projectPath string) *lineIndex {
	return &lineIndex{paths: newPathResolver(projectPath), files: map[string][]string{}}
}

// lineIdentity returns the hash of the flagged line's normalized content and
// how many earlier lines of the file have the same content. A finding without
// a line has neither; an unreadable file yields a marker so the identity
// stays line-number free.
func (x *lineIndex) lineIdentity(file string, line int) (string, int) {
	if line <= 0 {
		return "", 0
	}
	lines, ok := x.files[file]
	if !ok {
		lines = readNormalizedLines(x.paths.absolute(file))
		x.files[file] = lines
	}
	if lines == nil || line > len(lines) {
		return "unreadable", 0
	}
	target := lines[line-1]
	occurrence := 0
	for _, earlier := range lines[:line-1] {
		if earlier == target {
			occurrence++
		}
	}
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:16]), occurrence
}

func readNormalizedLines(path string) []string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxIdentityFileBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	raw := bytes.Split(data, []byte("\n"))
	lines := make([]string, len(raw))
	for i, line := range raw {
		lines[i] = normalizeLineContent(string(line))
	}
	return lines
}
