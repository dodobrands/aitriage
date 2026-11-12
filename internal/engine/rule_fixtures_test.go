package engine

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/models"
)

// Per-rule fixtures live in testdata/rules/<RULE-ID>/{bad,good}/<case>, where
// a case is one file or a directory holding a small project. A bad case must
// make the rule report; a good case is similar, safe code that must stay
// silent. In a bad file, a comment containing "ruleid: <RULE-ID>" marks the
// line below it as the expected location. The text "__JOIN__" is removed when
// a case is copied, so a fixture can hold a credential-shaped value without
// the repository itself containing one.
const ruleFixturesRoot = "../../testdata/rules"

// joinMarker splits credential-shaped values in fixture files.
const joinMarker = "__JOIN__"

func TestRuleFixtures(t *testing.T) {
	rules := fixtureCatalog(t)
	dirs, err := os.ReadDir(ruleFixturesRoot)
	if err != nil {
		t.Fatalf("read %s: %v", ruleFixturesRoot, err)
	}
	covered := map[string]map[string]bool{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		id := d.Name()
		rule, ok := rules[id]
		if !ok {
			t.Errorf("testdata/rules/%s: no catalog rule with this id", id)
			continue
		}
		covered[id] = map[string]bool{}
		for _, kind := range []string{"bad", "good"} {
			cases, err := os.ReadDir(filepath.Join(ruleFixturesRoot, id, kind))
			if err != nil {
				continue
			}
			for _, c := range cases {
				covered[id][kind] = true
				path := filepath.Join(ruleFixturesRoot, id, kind, c.Name())
				t.Run(id+"/"+kind+"/"+c.Name(), func(t *testing.T) {
					checkFixtureCase(t, rule, path, kind == "bad", false)
				})
				// Files written on Windows end lines with CRLF; a rule must give
				// the same answer for them.
				t.Run(id+"/"+kind+"/"+c.Name()+"/crlf", func(t *testing.T) {
					checkFixtureCase(t, rule, path, kind == "bad", true)
				})
			}
		}
	}

	// Every rule needs at least one case of each kind.
	var missing []string
	for id := range rules {
		if !covered[id]["bad"] || !covered[id]["good"] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	for _, id := range missing {
		t.Errorf("rule %s needs at least one bad and one good case under testdata/rules/%s/", id, id)
	}
}

// fixtureCatalog returns the built-in regex and AST rules, compiled as the
// engine compiles them, keyed by id.
func fixtureCatalog(t *testing.T) map[string]models.Rule {
	t.Helper()
	loaded, err := loadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	rules := map[string]models.Rule{}
	for i := range loaded {
		resolveSeverity(&loaded[i], false)
		e.compileRule(&loaded[i])
		rules[loaded[i].ID] = loaded[i]
	}
	return rules
}

type fixtureLocation struct {
	file string // slash-separated path relative to the case root
	line int
}

func checkFixtureCase(t *testing.T, rule models.Rule, src string, wantFinding, crlf bool) {
	t.Helper()
	root := t.TempDir()
	expected := copyFixtureCase(t, src, root, rule.ID, crlf)

	ws, err := core.NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	stack := rule.Stack
	if stack == "universal" {
		stack = "unknown"
	}
	e := &Engine{Rules: []models.Rule{rule}}
	ctx := &core.ProjectContext{RootPath: root, ScanRoot: root, Files: ws.Files, Stack: stack, Config: ws.Config}

	var got []fixtureLocation
	for _, r := range e.Run(ctx) {
		if r.ID != rule.ID {
			continue
		}
		rel := ""
		if r.File != "" {
			if p, err := filepath.Rel(root, r.File); err == nil {
				rel = filepath.ToSlash(p)
			}
		}
		got = append(got, fixtureLocation{rel, r.Line})
	}

	if !wantFinding {
		if len(got) > 0 {
			t.Errorf("rule %s fired on a good case at %v; fix the pattern, region or condition rather than the case", rule.ID, got)
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("rule %s did not fire on a bad case", rule.ID)
	}
	if len(expected) == 0 {
		return
	}
	for _, g := range got {
		for _, want := range expected {
			if g == want {
				return
			}
		}
	}
	t.Errorf("rule %s fired at %v; want one of the marked lines %v", rule.ID, got, expected)
}

// copyFixtureCase copies a case (file or directory) into root, removing join
// markers and optionally converting line endings to CRLF, and returns the
// locations marked with "ruleid: <id>".
func copyFixtureCase(t *testing.T, src, root, id string, crlf bool) []fixtureLocation {
	t.Helper()
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	base := src
	if !info.IsDir() {
		base = filepath.Dir(src)
	}
	var marks []fixtureLocation
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(data), joinMarker, "")
		if crlf {
			text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(text), 0o644); err != nil {
			return err
		}
		marks = append(marks, ruleMarks(text, filepath.ToSlash(rel), id)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return marks
}

func ruleMarks(text, rel, id string) []fixtureLocation {
	var marks []fixtureLocation
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if strings.Contains(sc.Text(), "ruleid: "+id) {
			marks = append(marks, fixtureLocation{rel, line + 1})
		}
	}
	return marks
}
