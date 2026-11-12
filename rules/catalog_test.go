package rules

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
	"gopkg.in/yaml.v3"
)

// TestCatalogRuleIDsAreUnique guards the identity every decision about a
// finding is keyed by: baselines, suppressions, ignore lists and inline
// `aitriage-ignore` comments all name a rule by its id.
//
// The engine keeps the first definition it loads for an id and silently drops
// the others, so a duplicate id is a rule that never runs. Three such pairs
// went unnoticed for months. Ids are compared ignoring case and surrounding
// space, because two ids that differ only there are indistinguishable to the
// people writing those decisions down.
func TestCatalogRuleIDsAreUnique(t *testing.T) {
	firstSeen := map[string]string{} // normalized id → file that defines it
	err := fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return nil
		}
		data, err := fs.ReadFile(FS, p)
		if err != nil {
			return err
		}
		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return err
		}
		for _, r := range rs.Rules {
			id := strings.TrimSpace(r.ID)
			if id == "" {
				t.Errorf("%s: rule %q has no id", p, r.Name)
				continue
			}
			key := strings.ToUpper(id)
			if first, dup := firstSeen[key]; dup {
				t.Errorf("%s: rule id %q is already used in %s. Give this rule an id of its own: ids must be unique, ignoring case.", p, id, first)
				continue
			}
			firstSeen[key] = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk catalog: %v", err)
	}
	if len(firstSeen) == 0 {
		t.Fatal("no rules found in the embedded catalog")
	}
}

// legacySeverityPrefix matches the old convention of encoding severity in the
// suggestion text ("HIGH: ..." or "HIGH [OWASP LLM05]: ...").
var legacySeverityPrefix = regexp.MustCompile(`^(?i)(?:CRITICAL|HIGH|MEDIUM|LOW)\b[^:]{0,40}:`)

// TestCatalogRulesDeclareSeverity requires every built-in rule to state its
// severity in the `severity` field. The engine no longer reads it from the
// suggestion text for built-in rules: that text drifted from the intended
// value (all OWASP LLM rules silently ran as LOW), and a severity must be
// reviewable in one place.
func TestCatalogRulesDeclareSeverity(t *testing.T) {
	forEachCatalogRule(t, func(file string, r models.Rule) {
		switch r.Severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		default:
			t.Errorf("%s: rule %s has severity %q; want one of CRITICAL, HIGH, MEDIUM, LOW", file, r.ID, r.Severity)
		}
		if legacySeverityPrefix.MatchString(r.Suggestion) {
			t.Errorf("%s: rule %s still encodes a severity in its suggestion: %q", file, r.ID, r.Suggestion)
		}
	})
}

// forEachCatalogRule calls fn for every top-level rule of the embedded catalog.
func forEachCatalogRule(t *testing.T, fn func(file string, r models.Rule)) {
	t.Helper()
	err := fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return nil
		}
		data, err := fs.ReadFile(FS, p)
		if err != nil {
			return err
		}
		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return err
		}
		for _, r := range rs.Rules {
			fn(p, r)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk catalog: %v", err)
	}
}
