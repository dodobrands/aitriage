package rules

import (
	"io/fs"
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
