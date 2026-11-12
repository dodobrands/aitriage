package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// configFileNames lists, in priority order, the names a project configuration
// may have. LoadConfig and LoadIgnore must agree on it, or the built-in engine
// and the external scanners would read different files.
var configFileNames = []string{"aitriage.yaml", ".aitriage.yaml", "aitriage.yml", ".aitriage.yml"}

// ConfigFileNames returns the configuration file names in priority order.
func ConfigFileNames() []string {
	return append([]string(nil), configFileNames...)
}

// LoadIgnore reads only the ignore section of the project configuration.
//
// Scanners outside the built-in engine need ignore.paths and ignore.rules and
// nothing else. LoadConfig also resolves LLM credentials from the environment,
// which has no business in a file walker, so they get this narrower loader.
func LoadIgnore(rootPath string) IgnoreConfig {
	for _, name := range configFileNames {
		data, err := os.ReadFile(filepath.Join(rootPath, name))
		if err != nil {
			continue
		}
		var partial struct {
			Ignore IgnoreConfig `yaml:"ignore"`
		}
		// Expand variables exactly as LoadConfig does, so both loaders see the
		// same patterns.
		if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &partial); err != nil {
			// LoadConfig already warns about a broken file on every scan;
			// repeating it here would double each warning.
			slog.Debug("Failed to parse the ignore section of the configuration", "file", name, "error", err)
		}
		return partial.Ignore
	}
	return IgnoreConfig{}
}

// PathMatcher decides whether a project path is excluded by a list of
// .gitignore patterns: the ignore.paths entries of the configuration, or the
// lines of .gitignore or .aitriageignore. All three are read by this one
// matcher, so every scanner and walker draws the same line.
//
// Patterns follow gitignore(5) and are matched against paths relative to the
// project root:
//   - a pattern with a slash at its start or in its middle is anchored at the
//     root: "app/legacy/" matches app/legacy/ but not services/app/legacy/,
//     and "config/settings.py" only the top-level config directory's file. A
//     pattern without one ("vendor/", "*.min.js") matches at any depth;
//   - a trailing slash matches a directory and everything below it, never a
//     file of that name;
//   - "*", "?" and "[...]" never match "/"; a leading "**/" matches in every
//     directory, "/**/" spans zero or more directories and a trailing "/**"
//     matches everything inside a directory, not the directory itself;
//   - "!" re-includes, and the last pattern that matches a path decides it;
//   - a path is excluded with any directory above it that is excluded.
//
// A path is decided the way git decides it, from the top: each directory above
// it first, then the path itself, each by the patterns that match that
// directory or path itself. A negated directory pattern therefore re-includes
// the directory, not the files inside it that a pattern still excludes: with
// "*", "!*/" and "!*.go" every directory is entered but only the .go files are
// in scope, and with "*/" and "!src/" the subdirectories of src/ stay
// excluded. The matcher used to let such a negation cover every file below
// the directory, which scanned everything the whitelist was written to leave
// out.
//
// One rule deliberately differs from git. Git cannot re-include a path whose
// parent directory is excluded, so "infra/" followed by "!infra/prod/" leaves
// infra/prod/ ignored there, as "logs/" followed by "!keep.log" leaves
// logs/keep.log. Here a negation that comes after the pattern excluding the
// parent and names the path itself re-includes it, and what is below it is
// then decided as usual: it is what the entry asks for, and scanning more
// never hides a finding.
//
// ignore.paths entries used to be matched as plain substrings, which silently
// dropped the project's own code: "vendor" also excluded "src/vendors/", ".git"
// excluded ".github/", and a project checked out under a directory whose name
// contained a pattern was not scanned at all. The library that matched the
// patterns afterwards did not anchor patterns with a slash in the middle, so
// "app/legacy/" also hid services/billing/app/legacy/.
type PathMatcher struct {
	rules    []pathRule
	negation bool
}

// PathRule is one parsed pattern, for callers that translate patterns into
// another tool's syntax.
type PathRule struct {
	// Glob is the pattern without its "!", its leading "/" and its trailing "/".
	Glob string
	// Negated patterns re-include what they match.
	Negated bool
	// Anchored patterns match from the project root only: git anchors every
	// pattern with a slash before its last character.
	Anchored bool
	// DirOnly patterns end in "/": they match a directory and everything below
	// it, never a file.
	DirOnly bool
}

// pathRule is a compiled pattern.
type pathRule struct {
	PathRule
	// self matches a path the pattern names itself.
	self *regexp.Regexp
	// tree matches a path the pattern names, or a path below a directory it
	// names. Without negated patterns that is all exclusion needs.
	tree *regexp.Regexp
	// segments match an anchored pattern one path segment at a time, with nil
	// standing for "**". They are nil when the pattern cannot be split safely;
	// mayMatchBelow then assumes the worst.
	segments []*regexp.Regexp
}

// NewPathMatcher compiles ignore.paths entries.
func NewPathMatcher(patterns []string) *PathMatcher {
	m := &PathMatcher{}
	for _, raw := range patterns {
		if pattern := normalizeIgnorePattern(raw); pattern != "" {
			m.add(pattern)
		}
	}
	return m
}

// ParseIgnoreFile compiles the content of a .gitignore or .aitriageignore
// file. Lines are read as git reads them: "#" starts a comment, trailing spaces
// are dropped unless escaped with a backslash, and leading spaces are part of
// the pattern.
func ParseIgnoreFile(content string) *PathMatcher {
	m := &PathMatcher{}
	for _, line := range strings.Split(strings.TrimPrefix(content, "\xEF\xBB\xBF"), "\n") {
		m.add(line)
	}
	return m
}

// ReadIgnoreFile reads and compiles an ignore file. A file that cannot be read
// yields nil, which excludes nothing.
func ReadIgnoreFile(path string) *PathMatcher {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParseIgnoreFile(string(data))
}

func (m *PathMatcher) add(line string) {
	line = trimTrailingSpaces(strings.TrimSuffix(line, "\r"))
	rule, ok := parsePathRule(line)
	if !ok {
		return
	}
	m.rules = append(m.rules, rule)
	m.negation = m.negation || rule.Negated
}

// normalizeIgnorePattern trims an entry and anchors a "./"-prefixed one at the
// root. Git would not match "./dist/" at all, but in a YAML list it plainly
// means the top-level dist directory, and dropping it silently would leave the
// directory in scope.
func normalizeIgnorePattern(raw string) string {
	pattern := strings.TrimSpace(raw)
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return ""
	}
	negate := strings.HasPrefix(pattern, "!")
	if negate {
		pattern = pattern[1:]
	}
	if strings.HasPrefix(pattern, "./") {
		for strings.HasPrefix(pattern, "./") {
			pattern = strings.TrimPrefix(pattern, "./")
		}
		pattern = "/" + pattern
	}
	if strings.Trim(pattern, "/") == "" {
		return ""
	}
	if negate {
		return "!" + pattern
	}
	return pattern
}

// Empty reports whether no pattern is configured.
func (m *PathMatcher) Empty() bool {
	return m == nil || len(m.rules) == 0
}

// Rules returns the parsed patterns in configuration order.
func (m *PathMatcher) Rules() []PathRule {
	if m == nil {
		return nil
	}
	rules := make([]PathRule, len(m.rules))
	for i, rule := range m.rules {
		rules[i] = rule.PathRule
	}
	return rules
}

// HasNegation reports whether a "!pattern" re-includes something.
func (m *PathMatcher) HasNegation() bool {
	return m != nil && m.negation
}

// Excludes reports whether rel, a path relative to the project root, is
// excluded. isDir matters for patterns ending in "/", which match directories
// (and everything below them) but never a file of the same name. The project
// root itself is never excluded.
func (m *PathMatcher) Excludes(rel string, isDir bool) bool {
	rel, ok := projectRelative(rel)
	if m == nil || !ok {
		return false
	}
	excluded, _ := m.decide(rel, isDir)
	return excluded
}

// ExcludesTree reports whether a directory and everything below it are
// excluded, so a walker may skip it without looking inside. A directory that
// is excluded is still entered when a later negated pattern could re-include
// something below it ("!infra/prod/" under "infra/", or "!*.keep" at any
// depth); a negation that cannot reach below it ("!.vscode/settings.json" for
// dist/) does not stop the walker from skipping it.
func (m *PathMatcher) ExcludesTree(rel string) bool {
	rel, ok := projectRelative(rel)
	if m == nil || !ok {
		return false
	}
	excluded, by := m.decide(rel, true)
	if !excluded {
		return false
	}
	// Below an excluded directory, only a negation later than every pattern
	// that excluded it or a directory on the way down can re-include a path
	// (see decide), so the others cannot keep the walker going.
	for _, later := range m.rules[by+1:] {
		if later.Negated && later.mayMatchBelow(rel) {
			return false
		}
	}
	return true
}

// decide reports whether rel is excluded and, when it is, the index of the
// latest pattern that excluded it or a directory on the way down to it.
//
// Without a negated pattern, a path is excluded when any pattern names it or
// a directory above it. With one, the path is decided as git decides it, from
// the top: each directory above rel, then rel itself, by the last pattern that
// names that path itself. Below an excluded directory everything is excluded,
// except a path that a later negated pattern names (the deliberate difference
// from git described at PathMatcher). A negation that names a directory never
// decides the files below it.
func (m *PathMatcher) decide(rel string, isDir bool) (bool, int) {
	if !m.negation {
		for i := len(m.rules) - 1; i >= 0; i-- {
			if m.rules[i].inTree(rel, isDir) {
				return true, i
			}
		}
		return false, -1
	}
	excluded, by := false, -1
	for start := 0; ; {
		path, dir := rel, isDir
		slash := strings.IndexByte(rel[start:], '/')
		if slash >= 0 {
			path, dir = rel[:start+slash], true
		}
		// Under an excluded directory only a later pattern changes anything:
		// a later negation re-includes, a later exclusion raises the bar a
		// negation has to clear further down.
		if i := m.lastSelfMatch(path, dir); i >= 0 && (!excluded || i > by) {
			excluded, by = !m.rules[i].Negated, i
		}
		if slash < 0 {
			return excluded, by
		}
		start += slash + 1
	}
}

// lastSelfMatch returns the index of the last pattern that names path itself,
// or -1. A directory pattern names directories only.
func (m *PathMatcher) lastSelfMatch(path string, isDir bool) int {
	for i := len(m.rules) - 1; i >= 0; i-- {
		if rule := &m.rules[i]; (isDir || !rule.DirOnly) && rule.self.MatchString(path) {
			return i
		}
	}
	return -1
}

// projectRelative cleans a root-relative path. Paths outside the project, and
// the project root itself, are never excluded.
func projectRelative(rel string) (string, bool) {
	rel = strings.Trim(filepath.ToSlash(filepath.Clean(rel)), "/")
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// inTree reports whether the pattern names rel itself or a directory above
// it: everything below an excluded directory is excluded with it.
func (r *pathRule) inTree(rel string, isDir bool) bool {
	if r.DirOnly && !isDir {
		// A file is never matched by a directory pattern itself, only through
		// the directory it is in.
		slash := strings.LastIndexByte(rel, '/')
		if slash < 0 {
			return false
		}
		rel = rel[:slash]
	}
	return r.tree.MatchString(rel)
}

// mayMatchBelow reports whether the pattern could match a path strictly below
// the directory dir. It answers true whenever it cannot rule that out, so a
// walker never skips a directory a negated pattern could re-include from.
func (r *pathRule) mayMatchBelow(dir string) bool {
	if !r.Anchored || r.segments == nil {
		// An unanchored pattern matches a name at any depth.
		return true
	}
	parts := strings.Split(dir, "/")
	for i, segment := range r.segments {
		if segment == nil || i >= len(parts) {
			// "**" spans any number of directories, and a pattern longer than
			// dir continues below it.
			return true
		}
		if !segment.MatchString(parts[i]) {
			return false
		}
	}
	// The pattern ends at dir or above it: without "**", each segment names
	// one path segment, so it names dir or a directory above it, and nothing
	// below dir. A negation that names a directory re-includes that directory,
	// not what is below it (see decide).
	return false
}

// trimTrailingSpaces drops trailing spaces that are not escaped with a
// backslash, as git does.
func trimTrailingSpaces(line string) string {
	end := len(line)
	for end > 0 && line[end-1] == ' ' {
		backslashes := 0
		for i := end - 2; i >= 0 && line[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			break
		}
		end--
	}
	return line[:end]
}

// parsePathRule compiles one pattern line. It reports false for blank lines,
// comments and patterns that can never match, such as an unterminated "[".
func parsePathRule(line string) (pathRule, bool) {
	if line == "" || line[0] == '#' {
		return pathRule{}, false
	}
	var rule pathRule
	if line[0] == '!' {
		rule.Negated = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		rule.DirOnly = true
		line = line[:len(line)-1]
	}
	// Git anchors a pattern with a slash at its start or in its middle; the
	// trailing slash was removed above. "**/" at the start still matches at
	// any depth: it spans every directory above.
	rule.Anchored = strings.Contains(line, "/")
	rule.Glob = strings.TrimPrefix(line, "/")
	if rule.Glob == "" {
		return pathRule{}, false
	}

	body, ok := globRegexp(rule.Glob, rule.Anchored)
	if !ok {
		return pathRule{}, false
	}
	prefix := "^"
	if !rule.Anchored {
		prefix = "^(?:.*/)?"
	}
	self, err := regexp.Compile(prefix + body + "$")
	if err != nil {
		return pathRule{}, false
	}
	tree, err := regexp.Compile(prefix + body + "(?:/|$)")
	if err != nil {
		return pathRule{}, false
	}
	rule.self, rule.tree = self, tree

	// Brackets and escapes may hide a "/" that is not a separator; such a
	// pattern is not split, and mayMatchBelow assumes the worst for it.
	if rule.Anchored && !strings.ContainsAny(rule.Glob, `[\`) {
		for _, segment := range strings.Split(rule.Glob, "/") {
			if len(segment) >= 2 && strings.Trim(segment, "*") == "" {
				rule.segments = append(rule.segments, nil)
				continue
			}
			body, _ := globRegexp(segment, false)
			rule.segments = append(rule.segments, regexp.MustCompile("^"+body+"$"))
		}
	}
	return rule, true
}

// globRegexp translates a gitignore glob into a regexp body, following git's
// wildmatch: "*", "?" and bracket expressions stay within a path segment, and
// for a pattern matched against the whole path (pathname) "**" between slashes
// or at either end spans directories. It reports false for a glob that can
// never match.
func globRegexp(glob string, pathname bool) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(glob); {
		switch c := glob[i]; c {
		case '\\':
			if i+1 >= len(glob) {
				return "", false // git never matches a trailing backslash
			}
			r, size := utf8.DecodeRuneInString(glob[i+1:])
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += 1 + size
		case '*':
			j := i
			for j < len(glob) && glob[j] == '*' {
				j++
			}
			special := pathname && j-i >= 2 && (i == 0 || glob[i-1] == '/') && (j == len(glob) || glob[j] == '/')
			switch {
			case special && j < len(glob):
				// "**/": zero or more directories.
				b.WriteString(`(?:.*/)?`)
				j++
			case special:
				// A trailing "**": everything below, but not the directory itself.
				b.WriteString(`.+`)
			default:
				b.WriteString(`[^/]*`)
			}
			i = j
		case '?':
			b.WriteString(`[^/]`)
			i++
		case '[':
			class, next, ok := bracketRegexp(glob, i)
			if !ok {
				return "", false
			}
			b.WriteString(class)
			i = next
		default:
			r, size := utf8.DecodeRuneInString(glob[i:])
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
		}
	}
	return b.String(), true
}

// posixClasses are the character classes wildmatch accepts inside brackets,
// as ASCII ranges.
var posixClasses = map[string][][2]rune{
	"alnum":  {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}},
	"alpha":  {{'A', 'Z'}, {'a', 'z'}},
	"blank":  {{' ', ' '}, {'\t', '\t'}},
	"cntrl":  {{0, 0x1f}, {0x7f, 0x7f}},
	"digit":  {{'0', '9'}},
	"graph":  {{0x21, 0x7e}},
	"lower":  {{'a', 'z'}},
	"print":  {{0x20, 0x7e}},
	"punct":  {{0x21, 0x2f}, {0x3a, 0x40}, {0x5b, 0x60}, {0x7b, 0x7e}},
	"space":  {{'\t', '\r'}, {' ', ' '}},
	"upper":  {{'A', 'Z'}},
	"xdigit": {{'0', '9'}, {'A', 'F'}, {'a', 'f'}},
}

// bracketRegexp translates the bracket expression starting at glob[start] into
// a regexp character class and returns the index just past it. "!" or "^"
// negates the class, a "]" right after the opening bracket is literal, and, as
// in git, the class never matches "/". It reports false for an unterminated or
// malformed expression, which git never matches.
func bracketRegexp(glob string, start int) (string, int, bool) {
	i := start + 1
	negated := i < len(glob) && (glob[i] == '!' || glob[i] == '^')
	if negated {
		i++
	}
	var ranges [][2]rune
	prev, hasPrev := rune(0), false
	for first := true; ; first = false {
		if i >= len(glob) {
			return "", 0, false
		}
		c, size := utf8.DecodeRuneInString(glob[i:])
		switch {
		case c == ']' && !first:
			return classRegexp(ranges, negated), i + size, true
		case c == '\\':
			i += size
			if i >= len(glob) {
				return "", 0, false
			}
			c, size = utf8.DecodeRuneInString(glob[i:])
			ranges = append(ranges, [2]rune{c, c})
			prev, hasPrev = c, true
			i += size
		case c == '-' && hasPrev && i+1 < len(glob) && glob[i+1] != ']':
			i += size
			hi, hiSize := utf8.DecodeRuneInString(glob[i:])
			if hi == '\\' {
				i += hiSize
				if i >= len(glob) {
					return "", 0, false
				}
				hi, hiSize = utf8.DecodeRuneInString(glob[i:])
			}
			if prev <= hi {
				ranges = append(ranges, [2]rune{prev, hi})
			}
			hasPrev = false
			i += hiSize
		case c == '[' && strings.HasPrefix(glob[i:], "[:"):
			end := strings.IndexByte(glob[i+2:], ']')
			if end < 0 {
				return "", 0, false
			}
			if end == 0 || glob[i+2+end-1] != ':' {
				// Not a class name after all: a literal "[".
				ranges = append(ranges, [2]rune{'[', '['})
				prev, hasPrev = '[', true
				i++
				continue
			}
			class, known := posixClasses[glob[i+2:i+2+end-1]]
			if !known {
				return "", 0, false
			}
			ranges = append(ranges, class...)
			hasPrev = false
			i += 2 + end + 1
		default:
			ranges = append(ranges, [2]rune{c, c})
			prev, hasPrev = c, true
			i += size
		}
	}
}

// classRegexp renders character ranges as a regexp class that excludes "/".
func classRegexp(ranges [][2]rune, negated bool) string {
	var b strings.Builder
	b.WriteByte('[')
	if negated {
		b.WriteString("^/")
	}
	empty := true
	for _, r := range ranges {
		parts := [][2]rune{r}
		if !negated && r[0] <= '/' && '/' <= r[1] {
			parts = [][2]rune{{r[0], '/' - 1}, {'/' + 1, r[1]}}
		}
		for _, part := range parts {
			if part[0] > part[1] {
				continue
			}
			empty = false
			b.WriteString(classChar(part[0]))
			if part[1] != part[0] {
				b.WriteByte('-')
				b.WriteString(classChar(part[1]))
			}
		}
	}
	if empty && !negated {
		return `[^\x00-\x{10FFFF}]` // matches nothing
	}
	b.WriteByte(']')
	return b.String()
}

func classChar(r rune) string {
	switch r {
	case '\\', ']', '[', '^', '-':
		return `\` + string(r)
	}
	if r < 0x20 || r == 0x7f {
		return `\x{` + strconv.FormatInt(int64(r), 16) + `}`
	}
	return string(r)
}

// Source names a finding answers to in an ignore.rules qualifier such as
// "gitleaks:generic-api-key". Checks built into AITriage answer to "aitriage"
// and to their own kind, because reports label NFR, deploy and network findings
// with the "aitriage" source. External findings answer to their scanner name.
var (
	CoreRuleSources    = []string{"aitriage", "core"}
	NFRRuleSources     = []string{"aitriage", "nfr"}
	DeployRuleSources  = []string{"aitriage", "deploy"}
	NetworkRuleSources = []string{"aitriage", "network"}
)

// ruleSources are the qualifiers ParseRuleRef recognises. Anything else before
// a colon is treated as part of the rule id, so an id that happens to contain a
// colon still works.
var ruleSources = map[string]bool{
	"aitriage":    true,
	"core":        true,
	"nfr":         true,
	"deploy":      true,
	"network":     true,
	"semgrep":     true,
	"gitleaks":    true,
	"trivy":       true,
	"bandit":      true,
	"securecoder": true,
	"wiz":         true,
	"external":    true,
}

// RuleRef is one rule reference from ignore.rules or an inline directive: a
// rule id, optionally qualified with the source that reports it.
type RuleRef struct {
	// Source is the lower-cased qualifier; empty matches every source.
	Source string
	ID     string
}

// ParseRuleRef splits "source:rule-id" into its parts. A bare id, or one whose
// prefix is not a known source, is returned whole with no qualifier.
func ParseRuleRef(entry string) RuleRef {
	entry = strings.TrimSpace(entry)
	if i := strings.IndexByte(entry, ':'); i > 0 {
		if source := strings.ToLower(strings.TrimSpace(entry[:i])); ruleSources[source] {
			return RuleRef{Source: source, ID: strings.TrimSpace(entry[i+1:])}
		}
	}
	return RuleRef{ID: entry}
}

// Matches compares rule ids whole and case-insensitively. A qualified reference
// also requires the finding to answer to its source.
func (r RuleRef) Matches(ruleID string, sources ...string) bool {
	if r.ID == "" || !strings.EqualFold(r.ID, strings.TrimSpace(ruleID)) {
		return false
	}
	if r.Source == "" {
		return true
	}
	for _, source := range sources {
		if strings.EqualFold(r.Source, strings.TrimSpace(source)) {
			return true
		}
	}
	return false
}

// RuleMatcher applies ignore.rules to findings from any source.
type RuleMatcher struct {
	entries []string
	refs    []RuleRef
}

// NewRuleMatcher compiles ignore.rules entries.
func NewRuleMatcher(entries []string) *RuleMatcher {
	m := &RuleMatcher{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		ref := ParseRuleRef(entry)
		if ref.ID == "" {
			continue
		}
		m.entries = append(m.entries, entry)
		m.refs = append(m.refs, ref)
	}
	return m
}

// Empty reports whether no rule is ignored.
func (m *RuleMatcher) Empty() bool {
	return m == nil || len(m.refs) == 0
}

// Match returns the ignore.rules entry, as written in the configuration, that
// silences a finding. Reports key their "ignored by configuration" counts on it.
func (m *RuleMatcher) Match(ruleID string, sources ...string) (string, bool) {
	if m == nil {
		return "", false
	}
	for i, ref := range m.refs {
		if ref.Matches(ruleID, sources...) {
			return m.entries[i], true
		}
	}
	return "", false
}
