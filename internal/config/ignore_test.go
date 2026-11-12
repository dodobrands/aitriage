package config

import (
	"testing"
)

func TestLoadIgnoreReadsTheIgnoreSectionOfTheSameFileAsLoadConfig(t *testing.T) {
	dir := t.TempDir()
	// LoadConfig prefers aitriage.yaml over .aitriage.yaml; LoadIgnore must
	// read the same file, or the engine and the external scanners would
	// disagree about what is excluded.
	writeConfig(t, dir, ".aitriage.yaml", "ignore:\n  paths: [hidden/]\n")
	writeConfig(t, dir, "aitriage.yaml", `
ignore:
  paths:
    - wp-content/plugins/akismet/
  rules:
    - ENTR-SLOP-01
    - gitleaks:generic-api-key
llm:
  provider: openai
`)

	got := LoadIgnore(dir)

	if len(got.Paths) != 1 || got.Paths[0] != "wp-content/plugins/akismet/" {
		t.Errorf("paths = %q; want the entry from aitriage.yaml", got.Paths)
	}
	if len(got.Rules) != 2 || got.Rules[1] != "gitleaks:generic-api-key" {
		t.Errorf("rules = %q", got.Rules)
	}
	if want := LoadConfig(dir).Ignore.Paths; len(want) != 1 || want[0] != got.Paths[0] {
		t.Errorf("LoadConfig read paths %q, LoadIgnore %q", want, got.Paths)
	}
}

func TestLoadIgnoreWithoutConfigIsEmpty(t *testing.T) {
	got := LoadIgnore(t.TempDir())
	if len(got.Paths) != 0 || len(got.Rules) != 0 {
		t.Errorf("ignore section = %+v; want empty", got)
	}
}

func TestPathMatcherUsesGitignoreSemanticsNotSubstrings(t *testing.T) {
	m := NewPathMatcher([]string{"vendor/", "dist", "tests", "./build/", "*.min.js", "wp-content/plugins/akismet/"})

	cases := []struct {
		rel   string
		isDir bool
		want  bool
	}{
		{"vendor", true, true},
		{"vendor/aws/sdk.php", false, true},
		{"src/vendor/lib.go", false, true},
		{"src/vendors/api.py", false, false}, // substring of "vendor", not the directory
		{"src/vendors", true, false},
		{"vendor", false, false}, // a file named vendor is not the vendor/ directory
		{"distribution/app.py", false, false},
		{"dist/app.js", false, true},
		{"tests/test_app.py", false, true},
		{"unit_tests/test_app.py", false, false},
		{"unit_tests", true, false},
		{"build/out.js", false, true},
		{"src/build/out.js", false, false}, // "./build/" is anchored at the root
		{"static/app.min.js", false, true},
		{"wp-content/plugins/akismet/akismet.php", false, true},
		{"wp-content/plugins/other/plugin.php", false, false},
		{".", true, false}, // the project root is never excluded
		{"", true, false},
	}
	for _, tc := range cases {
		if got := m.Excludes(tc.rel, tc.isDir); got != tc.want {
			t.Errorf("Excludes(%q, dir=%t) = %t; want %t", tc.rel, tc.isDir, got, tc.want)
		}
	}
}

func TestPathMatcherNegationDisablesTreePruning(t *testing.T) {
	m := NewPathMatcher([]string{"generated/", "!generated/keep.go"})

	if !m.HasNegation() {
		t.Fatal("negated entry not detected")
	}
	if m.ExcludesTree("generated") {
		t.Error("a walker must descend into a directory a negated entry may re-include")
	}
	if !m.Excludes("generated/other.go", false) {
		t.Error("generated/other.go must stay excluded")
	}
	if m.Excludes("generated/keep.go", false) {
		t.Error("generated/keep.go is re-included by the negated entry")
	}
}

func TestPathMatcherIgnoresBlankEntries(t *testing.T) {
	m := NewPathMatcher([]string{"", "  ", "/", "# comment"})
	if !m.Empty() {
		t.Fatalf("patterns = %q; want none", m.Patterns())
	}
	if m.Excludes("src/app.go", false) {
		t.Error("an empty matcher excluded a path")
	}
}

func TestRuleRefQualifiers(t *testing.T) {
	cases := []struct {
		entry   string
		ruleID  string
		sources []string
		want    bool
	}{
		{"generic-api-key", "generic-api-key", []string{"gitleaks"}, true},
		{"generic-api-key", "generic-api-key", []string{"semgrep"}, true},
		{"gitleaks:generic-api-key", "generic-api-key", []string{"gitleaks"}, true},
		{"gitleaks:generic-api-key", "generic-api-key", []string{"semgrep"}, false},
		{"Trivy:cve-2024-1234", "CVE-2024-1234", []string{"trivy"}, true},
		{"b105", "B105", []string{"bandit"}, true},
		{"B10", "B105", []string{"bandit"}, false}, // ids compare whole
		{"aitriage:port-53", "port-53", NetworkRuleSources, true},
		{"network:port-53", "port-53", NetworkRuleSources, true},
		{"deploy:port-53", "port-53", NetworkRuleSources, false},
		{"semgrep:python.lang.security.audit.subprocess-shell-true", "python.lang.security.audit.subprocess-shell-true", []string{"semgrep"}, true},
		// An unknown prefix is part of the id, so an id with a colon still works.
		{"custom:rule", "custom:rule", CoreRuleSources, true},
	}
	for _, tc := range cases {
		if got := ParseRuleRef(tc.entry).Matches(tc.ruleID, tc.sources...); got != tc.want {
			t.Errorf("%q matches %q from %v = %t; want %t", tc.entry, tc.ruleID, tc.sources, got, tc.want)
		}
	}
}

func TestRuleMatcherReportsTheMatchingEntry(t *testing.T) {
	m := NewRuleMatcher([]string{" ", "gitleaks:generic-api-key", "ENTR-SLOP-01"})

	if entry, ok := m.Match("entr-slop-01", CoreRuleSources...); !ok || entry != "ENTR-SLOP-01" {
		t.Errorf("Match = %q, %t; want the configuration entry", entry, ok)
	}
	if entry, ok := m.Match("generic-api-key", "gitleaks"); !ok || entry != "gitleaks:generic-api-key" {
		t.Errorf("Match = %q, %t; want the qualified entry", entry, ok)
	}
	if _, ok := m.Match("generic-api-key", "semgrep"); ok {
		t.Error("a gitleaks-qualified entry silenced a semgrep finding")
	}
}

// IsRuleIgnored guards the built-in engine's YAML rules. A qualifier for
// another scanner must not switch an engine rule off.
func TestIsRuleIgnoredHonoursQualifiersAndCase(t *testing.T) {
	cfg := &Config{Ignore: IgnoreConfig{Rules: []string{"entr-01", "aitriage:ENTR-04", "semgrep:ENTR-09"}}}

	if !cfg.IsRuleIgnored("ENTR-01") {
		t.Error("ids must compare case-insensitively")
	}
	if !cfg.IsRuleIgnored("ENTR-04") {
		t.Error("an aitriage-qualified entry must apply to the built-in engine")
	}
	if cfg.IsRuleIgnored("ENTR-09") {
		t.Error("a semgrep-qualified entry must not silence the built-in engine")
	}
	var nilCfg *Config
	if nilCfg.IsRuleIgnored("ENTR-01") {
		t.Error("a nil config ignores nothing")
	}
}
