package models

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Ecosystem describes one package manager: the manifest that proves the project
// uses it, and the lockfiles that pin it.
type Ecosystem struct {
	Name      string   `yaml:"name" json:"name"`
	Manifests []string `yaml:"manifests" json:"manifests"`
	Lockfiles []string `yaml:"lockfiles" json:"lockfiles"`
}

type Rule struct {
	ID         string   `yaml:"id" json:"id"`
	Name       string   `yaml:"name" json:"name"`
	Stack      string   `yaml:"stack" json:"stack"`
	Extensions []string `yaml:"extensions" json:"extensions"`
	Target     string   `yaml:"target" json:"target"`
	Pattern    string   `yaml:"pattern" json:"pattern"`
	Condition  string   `yaml:"condition" json:"condition"`
	Files      []string `yaml:"files" json:"files"`
	// Ecosystems pairs a dependency manifest with the lockfiles that satisfy it.
	// A lockfile rule then only applies to the ecosystems a project actually
	// uses, instead of demanding a Go checksum file from a PHP project.
	Ecosystems   []Ecosystem `yaml:"ecosystems" json:"ecosystems,omitempty"`
	ExcludeTests bool        `yaml:"exclude_tests" json:"exclude_tests"`
	ExcludePaths []string    `yaml:"exclude_paths" json:"exclude_paths"` // path fragments to skip (e.g. "seed", "migration")
	Suggestion   string      `yaml:"suggestion" json:"suggestion"`
	Severity     string      `yaml:"severity" json:"severity"`
	Message      string      `yaml:"message" json:"message"`
	Languages    []string    `yaml:"languages" json:"languages"`

	// Semgrep-like logical patterns
	Patterns         []Rule `yaml:"patterns" json:"patterns,omitempty"`
	PatternEither    []Rule `yaml:"pattern-either" json:"pattern_either,omitempty"`
	PatternNot       string `yaml:"pattern-not" json:"pattern_not,omitempty"`
	PatternInside    string `yaml:"pattern-inside" json:"pattern_inside,omitempty"`
	PatternNotInside string `yaml:"pattern-not-inside" json:"pattern_not_inside,omitempty"`

	// Semgrep taint-mode fields. When Mode == "taint" the rule is NOT executed by
	// the AITriage regex/AST engine; it is compiled into a trusted Semgrep config
	// and executed by the bundled Semgrep during a full audit. The source/sink/
	// sanitizer definitions are kept as raw YAML nodes so arbitrary Semgrep
	// sub-structure (pattern, patterns, pattern-either, focus-metavariable, …) is
	// preserved verbatim when re-serialized.
	Mode              string            `yaml:"mode" json:"mode,omitempty"`
	Metadata          map[string]string `yaml:"metadata" json:"metadata,omitempty"`
	PatternSources    []yaml.Node       `yaml:"pattern-sources" json:"-"`
	PatternSinks      []yaml.Node       `yaml:"pattern-sinks" json:"-"`
	PatternSanitizers []yaml.Node       `yaml:"pattern-sanitizers" json:"-"`

	CompiledPattern *regexp.Regexp `yaml:"-" json:"-"`
}

// IsTaint reports whether the rule is a Semgrep taint-mode rule. Taint rules are
// executed by the bundled Semgrep, never by the AITriage regex/AST engine.
func (r Rule) IsTaint() bool {
	return strings.EqualFold(strings.TrimSpace(r.Mode), "taint")
}

type Ruleset struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}
