package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// slopResults runs the ENTR-SLOP-01 heuristic over one file.
func slopResults(t *testing.T, name, content string) []core.CheckResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{}
	return eng.evaluateEntropyPattern(&core.FileInfo{Path: path, Extension: filepath.Ext(name)})
}

const signUpForm = `import { useState } from "react";

export function SignUpForm() {
  const [email, setEmail] = useState("");
  return (
    <form>
      <input name="first" placeholder="First name" />
      <input name="last" placeholder="Last name" />
      <input name="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input name="phone" placeholder='+1 555 0100' />
      <input name="company" placeholder={"Company"} />
      <input name="password" type="password" placeholder="Temporary password" />
      <textarea name="notes" placeholder="Anything else? (placeholder text)" />
    </form>
  );
}
`

// A sign-up form with seven placeholder="…" inputs used to be reported as HIGH
// "Excessive AI Scaffolding Residue".
func TestSlopIgnoresPlaceholderAttributesAndStrings(t *testing.T) {
	if got := slopResults(t, "SignUpForm.tsx", signUpForm); len(got) != 0 {
		t.Fatalf("ordinary form reported as scaffolding residue: %+v", got)
	}
}

func TestSlopIgnoresStringLiterals(t *testing.T) {
	src := `const messages = {
  empty: "Nothing to do yet. Add a TODO to get started.",
  draft: 'This draft is temporary and will be deleted.',
  hint: ` + "`" + `Use the placeholder {name}
or FIXME tags in the template.` + "`" + `,
  sql: "SELECT result1, var2 FROM placeholder",
  more: "todo todo todo todo",
};
export default messages;
`
	if got := slopResults(t, "messages.ts", src); len(got) != 0 {
		t.Fatalf("text inside string literals was counted: %+v", got)
	}
}

func TestSlopIgnoresPlaceholderAsPropName(t *testing.T) {
	src := `interface FieldProps {
  label: string;
  placeholder?: string;
}

const fields = [
  { name: "email", placeholder: "Email" },
  { name: "phone", placeholder: "Phone" },
  { name: "city", placeholder: "City" },
  { name: "zip", placeholder: "ZIP" },
  { name: "street", placeholder: "Street" },
  { name: "country", placeholder: "Country" },
];

export function Field(props: FieldProps) {
  return <input aria-label={props.label} placeholder={props.placeholder} />;
}
`
	if got := slopResults(t, "fields.tsx", src); len(got) != 0 {
		t.Fatalf("placeholder used as a prop name was counted: %+v", got)
	}
}

func TestSlopReportsResidueAsLowWithFirstLine(t *testing.T) {
	src := `package handlers

import "net/http"

// TODO: implement validation
func Create(w http.ResponseWriter, r *http.Request) {
	result1 := parse(r) // FIXME: placeholder parser
	var2 := result1
	// TODO: error handling
	_ = var2
}
`
	got := slopResults(t, "create.go", src)
	if len(got) != 1 {
		t.Fatalf("got %d results, want one ENTR-SLOP-01: %+v", len(got), got)
	}
	r := got[0]
	if r.ID != "ENTR-SLOP-01" {
		t.Fatalf("id = %q", r.ID)
	}
	if r.Severity != "LOW" {
		t.Errorf("severity = %q; want LOW (code quality, not a vulnerability)", r.Severity)
	}
	if !strings.HasPrefix(r.Suggestion, "LOW:") {
		t.Errorf("suggestion %q does not match the LOW severity", r.Suggestion)
	}
	if r.Line != 5 {
		t.Errorf("line = %d; want 5, the first marker (the TODO comment)", r.Line)
	}
}

func TestSlopCountsPythonCommentsButNotStrings(t *testing.T) {
	src := `def handler(request):
    # TODO: validate input
    message = "TODO TODO TODO TODO TODO TODO"
    doc = """placeholder placeholder placeholder
    FIXME FIXME FIXME"""
    # FIXME: temporary workaround
    return message  # placeholder
`
	count, line := countScaffoldingResidue(src, "handler.py")
	if count != 4 || line != 2 {
		t.Fatalf("count, first line = %d, %d; want 4 comment markers starting on line 2", count, line)
	}
}

// A fixed "more than five" count punishes size: six notes in a 1,000-line
// file are routine; six in a short file mean it is mostly scaffolding.
func TestSlopThresholdScalesWithFileSize(t *testing.T) {
	var b strings.Builder
	b.WriteString("package big\n\n")
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&b, "// TODO: follow-up %d\n", i)
	}
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "func f%d() int { return %d }\n", i, i)
	}
	if got := slopResults(t, "big.go", b.String()); len(got) != 0 {
		t.Fatalf("six notes in a 1,000-line file were reported: %+v", got)
	}

	if !excessiveResidue(6, 600) || excessiveResidue(6, 601) || excessiveResidue(5, 10) {
		t.Error("threshold must be more than five markers and at least one per 100 lines")
	}
}

func TestSlopMatchesWholeWordsOnly(t *testing.T) {
	src := `const todos = useTodos();
const autodownload = true;
const photodocument = "x";
const TodoList = todos.map(render);
const temporaryFile = path;
const placeholderData = [];
`
	if count, _ := countScaffoldingResidue(src, "app.ts"); count != 0 {
		t.Fatalf("count = %d; want 0, markers inside longer identifiers are not residue", count)
	}
}

func TestSlopHonoursInlineSuppression(t *testing.T) {
	src := "// aitriage-ignore-file\n" + strings.Repeat("// TODO: later\n", 8)
	if got := slopResults(t, "notes.js", src); len(got) != 0 {
		t.Fatalf("file-level suppression ignored: %+v", got)
	}
}

func TestLexSourceKeepsOffsetsAndLines(t *testing.T) {
	src := "a = \"x\ny\"\nb = `p\nq` // c 'd'\n/* e \"f\" */ g = 'h'\n"
	lexed := lexSource(src, slopC)
	if len(lexed.masked) != len(src) || strings.Count(lexed.masked, "\n") != strings.Count(src, "\n") {
		t.Fatalf("masking changed offsets or lines:\n%q\n%q", src, lexed.masked)
	}
	for _, kept := range []string{"// c 'd'", "/* e \"f\" */", "g = '"} {
		if !strings.Contains(lexed.masked, kept) {
			t.Errorf("code or comment %q was masked: %q", kept, lexed.masked)
		}
	}
	for _, gone := range []string{"x", "p\nq", "h"} {
		if strings.Contains(lexed.masked, gone) {
			t.Errorf("string content %q survived masking: %q", gone, lexed.masked)
		}
	}
	if !lexed.inComment(strings.Index(src, "c 'd'")) || lexed.inComment(strings.Index(src, "g =")) {
		t.Error("comment ranges are wrong")
	}
}
