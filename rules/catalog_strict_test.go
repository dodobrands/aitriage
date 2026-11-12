package rules

import (
	"bytes"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/scanner/ast"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	"gopkg.in/yaml.v3"
)

// retiredRuleIDs are ids of rules removed from the catalog. Baselines,
// suppressions and inline directives may still name them, so an id must never
// be given to a different rule.
var retiredRuleIDs = map[string]string{
	"ENTR-21":                "third copy of the weak-hash finding; ENTR-WEAK-CRYPTO and PY-HASHLIB-WEAK cover it",
	"ENTR-HALLUCINATION":     "a fixed list of four made-up package names; registry checks belong in the dependency scanner",
	"ENTR-FRAGILE-LOGIC":     "matched idiomatic Go error handling",
	"ENTROPY-SECRET":         "documented an id the engine never emitted; the detector reports SECRET-* ids",
	"ENTROPY-SECRET-LEAK":    "documented an id the engine never emitted; the detector reports SECRET-LEAK-LOG",
	"FLASK-ORM":              "absence of an ORM is not SQL injection; the rule never ran",
	"FLASK-SECRETS":          "duplicate of FLASK-SECRET-HARDCODED; the rule never ran",
	"NEXT-AUTH":              "absence of a middleware file is not a vulnerability; Next.js advises auth checks in each route",
	"NEXT-CSRF":              "Server Actions check the Origin header and cookies default to SameSite=Lax",
	"NEXT-AUTHZ":             "absence of the word role is not a vulnerability",
	"NEXT-VAL":               "absence of a validation library is not a vulnerability",
	"NEXT-ORM":               "absence of an ORM is not SQL injection",
	"NEXT-LOGGING":           "absence of a logging library is not a vulnerability",
	"NEXT-ERROR":             "a missing error.tsx is not a vulnerability",
	"NEXT-SECRETS":           "a missing .env.example is documentation hygiene",
	"NEXT-MATH-RANDOM":       "duplicate of ENTR-INSECURE-RANDOM",
	"REACT-HAPPY-PATH":       "reliability, not security; the query never compiled",
	"EXPRESS-MONGO-SANITIZE": "fired on projects without MongoDB; NoSQL injection rules cover the defect",
}

var (
	knownTargets = map[string]bool{"all": true, "ast": true, "docs": true, "filename": true, "condition": true, "entropy-analysis": true}
	knownRegions = map[string]bool{"code": true, "code_and_strings": true, "comments": true, "all": true}
	knownConds   = map[string]bool{"required_pattern": true, "missing": true, "missing_lockfile": true, "large_file": true}
)

// TestCatalogRulesAreWellFormed rejects rules that cannot work as written: a
// misspelled key (YAML drops unknown keys silently), a pattern RE2 or
// tree-sitter cannot compile (the engine used to swallow both errors, so such
// rules never fired), an unimplemented target or condition, a file rule with
// no extensions or pattern, a regex rule without a region filter, or the reuse
// of a retired id.
func TestCatalogRulesAreWellFormed(t *testing.T) {
	if os.Getenv("AITRIAGE_STRICT_CATALOG") != "1" {
		t.Skip("set AITRIAGE_STRICT_CATALOG=1 (enforced once the catalog review lands)")
	}
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
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var rs models.Ruleset
		if err := dec.Decode(&rs); err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		for _, r := range rs.Rules {
			checkRule(t, p, r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkRule(t *testing.T, file string, r models.Rule) {
	t.Helper()
	where := file + ": " + r.ID
	if reason, ok := retiredRuleIDs[r.ID]; ok {
		t.Errorf("%s: id is retired (%s) and must not be reused", where, reason)
	}
	if r.IsTaint() || r.Target == "entropy-analysis" {
		return
	}
	if !knownTargets[r.Target] {
		t.Errorf("%s: target %q is not implemented (use all, ast, docs, filename or condition)", where, r.Target)
	}
	if c := r.Condition; c != "" && !knownConds[c] && !strings.HasPrefix(c, "not_contains:") && !strings.HasPrefix(c, "contains:") {
		t.Errorf("%s: condition %q is not implemented", where, c)
	}
	if len(r.Extensions) == 0 && r.Condition != "missing_lockfile" {
		t.Errorf("%s: no extensions, so the rule never reads a file", where)
	}
	if len(r.Files) > 0 && r.Condition != "missing_lockfile" {
		t.Errorf("%s: files is only read by missing_lockfile", where)
	}
	if r.Pattern == "" && r.Condition != "missing_lockfile" && r.Condition != "large_file" {
		t.Errorf("%s: no pattern", where)
	}
	switch r.Target {
	case "ast":
		for _, ext := range r.Extensions {
			lang, err := ast.GetLanguage(ext)
			if err != nil || lang == nil {
				t.Errorf("%s: no tree-sitter grammar for %s", where, ext)
				continue
			}
			q, qerr := tree_sitter.NewQuery(lang, r.Pattern)
			if qerr != nil {
				t.Errorf("%s: query does not compile for %s: %v", where, ext, qerr)
				continue
			}
			for i := uint(0); i < q.PatternCount(); i++ {
				for _, pred := range q.GeneralPredicates(i) {
					t.Errorf("%s: predicate #%s is not supported and would be ignored", where, pred.Operator)
				}
			}
			q.Close()
		}
	case "all", "docs", "filename":
		if r.Pattern != "" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				t.Errorf("%s: pattern is not valid RE2: %v", where, err)
			}
		}
		if r.PatternNot != "" {
			if _, err := regexp.Compile(r.PatternNot); err != nil {
				t.Errorf("%s: pattern-not is not valid RE2: %v", where, err)
			}
		}
		if r.Target == "all" && !knownRegions[r.Regions] {
			t.Errorf("%s: regions must be code, code_and_strings, comments or all (got %q)", where, r.Regions)
		}
	}
}
