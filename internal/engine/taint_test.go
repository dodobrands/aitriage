package engine

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/rules"
	"gopkg.in/yaml.v3"
)

// expectedEngineRules replicates loadEmbeddedRules' selection semantics exactly:
// skip entropy-analysis and taint rules, then deduplicate by ID (first wins). It
// returns the number of rules the engine is expected to load and how many taint
// rules exist in the catalog.
func expectedEngineRules(t *testing.T) (wantLoaded, taint int) {
	t.Helper()
	seen := map[string]bool{}
	err := fs.WalkDir(rules.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, err := fs.ReadFile(rules.FS, path)
		if err != nil {
			return err
		}
		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return err
		}
		for _, r := range rs.Rules {
			if r.Target == "entropy-analysis" {
				continue
			}
			if r.IsTaint() {
				taint++
				continue
			}
			if !seen[r.ID] {
				seen[r.ID] = true
				wantLoaded++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk catalog: %v", err)
	}
	return wantLoaded, taint
}

// TestEngineSkipsTaintRules proves that taint-mode rules are executed by the
// bundled Semgrep, not by the regex/AST engine: no mandatory taint rule (such
// as FAST-XSS) may appear in the engine's loaded rule set, and no loaded rule
// may be taint-mode. The other (regex/AST) rules must continue to load
// unchanged.
func TestEngineSkipsTaintRules(t *testing.T) {
	loaded, err := loadEmbeddedRules()
	if err != nil {
		t.Fatalf("loadEmbeddedRules: %v", err)
	}

	want, taint := expectedEngineRules(t)
	if taint == 0 {
		t.Fatal("expected at least one taint rule (FAST-XSS) in the catalog")
	}

	// The engine loads every catalog rule except taint-mode and entropy-analysis
	// (deduplicated by ID).
	if len(loaded) != want {
		t.Fatalf("engine loaded %d rules, want %d (taint rules excluded=%d)",
			len(loaded), want, taint)
	}

	taintIDs := map[string]bool{}
	for _, id := range rules.RequiredTaintRuleIDs {
		taintIDs[id] = true
	}
	for _, r := range loaded {
		if r.IsTaint() {
			t.Errorf("taint rule %q must not be loaded by the regex/AST engine", r.ID)
		}
		if taintIDs[r.ID] {
			t.Errorf("%s (taint) must not be in the engine rule set; it runs via Semgrep", r.ID)
		}
	}
}

// TestEngineStillLoadsRegexAndASTRules is the "the other rules keep working"
// guard: a representative set of non-taint rules (regex and AST, FastAPI,
// Django and cross-stack) must still be present after taint support was added,
// while the FastAPI taint rules (FAST-XSS, FAST-SQLI, ...) must not.
func TestEngineStillLoadsRegexAndASTRules(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	present := map[string]bool{}
	for _, r := range eng.Rules {
		present[r.ID] = true
	}
	for _, id := range []string{"FAST-CORS-WILDCARD", "FAST-SYNC-ASYNC", "FAST-AUTH", "DJANGO-DEBUG", "LLM-OUTPUT-EXEC"} {
		if !present[id] {
			t.Errorf("expected regex/AST rule %q to still load, but it is missing", id)
		}
	}
	for _, id := range rules.RequiredTaintRuleIDs {
		if present[id] {
			t.Errorf("%s must not be a regex/AST engine rule", id)
		}
	}
}
