package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
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

// PathMatcher decides whether a project path is excluded by ignore.paths.
//
// Patterns use .gitignore syntax and are matched against paths relative to the
// project root, with the same library that reads .gitignore and .aitriageignore.
// They used to be matched as plain substrings, which silently dropped the
// project's own code: "vendor" also excluded "src/vendors/", ".git" excluded
// ".github/", and a project checked out under a directory whose name contained
// a pattern was not scanned at all.
type PathMatcher struct {
	patterns []string
	matcher  *ignore.GitIgnore
	negation bool
}

// NewPathMatcher compiles ignore.paths entries.
func NewPathMatcher(patterns []string) *PathMatcher {
	m := &PathMatcher{}
	for _, raw := range patterns {
		pattern := normalizeIgnorePattern(raw)
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "!") {
			m.negation = true
		}
		m.patterns = append(m.patterns, pattern)
	}
	if len(m.patterns) > 0 {
		m.matcher = ignore.CompileIgnoreLines(m.patterns...)
	}
	return m
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

// Patterns returns the compiled patterns in configuration order.
func (m *PathMatcher) Patterns() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.patterns...)
}

// Empty reports whether no pattern is configured.
func (m *PathMatcher) Empty() bool {
	return m == nil || len(m.patterns) == 0
}

// HasNegation reports whether a "!pattern" re-includes something. A walker
// cannot skip a matched directory wholesale when one is present.
func (m *PathMatcher) HasNegation() bool {
	return m != nil && m.negation
}

// Excludes reports whether rel, a path relative to the project root, is
// excluded. isDir matters for patterns ending in "/", which match directories
// (and everything below them) but never a file of the same name. The project
// root itself is never excluded.
func (m *PathMatcher) Excludes(rel string, isDir bool) bool {
	if m == nil || m.matcher == nil {
		return false
	}
	rel = strings.Trim(filepath.ToSlash(filepath.Clean(rel)), "/")
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
		return false
	}
	if isDir {
		return m.matcher.MatchesPath(rel + "/")
	}
	return m.matcher.MatchesPath(rel)
}

// ExcludesTree reports whether a directory and everything below it are
// excluded, so a walker may skip it without looking inside. With a negated
// pattern present the answer is always false: the walker has to descend and
// ask about each file, or it would drop a path the configuration re-includes.
func (m *PathMatcher) ExcludesTree(rel string) bool {
	return !m.HasNegation() && m.Excludes(rel, true)
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
