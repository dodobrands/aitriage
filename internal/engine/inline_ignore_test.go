package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/core"
)

func runOnFile(t *testing.T, name, content string, extra ...Rule) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	eng.Rules = append(eng.Rules, extra...)
	ws, err := core.NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	found := map[string]bool{}
	for _, r := range eng.Run(&core.ProjectContext{RootPath: dir, Files: ws.Files, Stack: "universal", Config: cfg}) {
		if r.Status == core.Absent {
			found[r.ID] = true
		}
	}
	return found
}

// passwordRule needs a stack: the engine skips a rule whose stack matches
// neither "universal" nor the project's.
var passwordRule = Rule{
	ID:              "TEST-PASSWORD",
	Stack:           "universal",
	Pattern:         "password",
	CompiledPattern: regexp.MustCompile("password"),
	Extensions:      []string{".py"},
}

// "# aitriage-ignore: B105 (allowed in tests)" used to silence every rule on
// the line: the old check looked for "all" anywhere, and "allowed" has it.
func TestInlineIgnoreSilencesOnlyTheNamedRule(t *testing.T) {
	found := runOnFile(t, "app/settings.py",
		"password = load()  # aitriage-ignore: B105 (allowed in tests)\n"+
			"aws_key = \"AKIAIOSFODNN7EXAMPLE\"  # aitriage-ignore: B105 (allowed in tests)\n",
		passwordRule)

	if !found["TEST-PASSWORD"] {
		t.Error("a YAML rule was silenced by a directive that names only B105")
	}
	if !found["SECRET-AWS-AKID"] {
		t.Error("the secret heuristic was silenced by a directive that names only B105")
	}
}

func TestInlineIgnoreStillSilencesTheNamedRule(t *testing.T) {
	found := runOnFile(t, "app/settings.py",
		"password = load()  # aitriage-ignore: test-password (reviewed)\n"+
			"# aitriage-ignore-next-line: SECRET-AWS-AKID\n"+
			"aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
		passwordRule)

	if found["TEST-PASSWORD"] {
		t.Error("the named YAML rule must be silenced (ids compare case-insensitively)")
	}
	if found["SECRET-AWS-AKID"] {
		t.Error("the named heuristic must be silenced by a next-line directive")
	}
}
