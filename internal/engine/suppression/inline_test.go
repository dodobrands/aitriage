package suppression

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseLineReadsOnlyTheIDList(t *testing.T) {
	cases := []struct {
		line string
		want []Directive
	}{
		{`x = 1  # aitriage-ignore: B105 (allowed in tests)`, []Directive{{Scope: ScopeLine, IDs: []string{"B105"}}}},
		{`x = 1  // aitriage:ignore ENTR-01`, []Directive{{Scope: ScopeLine, IDs: []string{"ENTR-01"}}}},
		{`# aitriage-ignore: B105, B106 (fixture)`, []Directive{{Scope: ScopeLine, IDs: []string{"B105", "B106"}}}},
		{`# aitriage-ignore:B105,gitleaks:generic-api-key`, []Directive{{Scope: ScopeLine, IDs: []string{"B105", "gitleaks:generic-api-key"}}}},
		{`# aitriage-ignore: B105 we accept all of this`, []Directive{{Scope: ScopeLine, IDs: []string{"B105"}}}},
		{`# aitriage-ignore-next-line: SECRET-ASSIGN`, []Directive{{Scope: ScopeNextLine, IDs: []string{"SECRET-ASSIGN"}}}},
		{`// aitriage:ignore-next-line FAST-XSS.`, []Directive{{Scope: ScopeNextLine, IDs: []string{"FAST-XSS"}}}},
		{`# aitriage-ignore-file`, []Directive{{Scope: ScopeFile}}},
		{`# aitriage-ignore-file: B101`, []Directive{{Scope: ScopeFile, IDs: []string{"B101"}}}},
		{`<!-- aitriage-ignore: XSS-01 -->`, []Directive{{Scope: ScopeLine, IDs: []string{"XSS-01"}}}},
		{`<!--aitriage-ignore:XSS-01-->`, []Directive{{Scope: ScopeLine, IDs: []string{"XSS-01"}}}},
		{`/* aitriage-ignore: all */`, []Directive{{Scope: ScopeLine, IDs: []string{"all"}}}},
		{`# aitriage-ignore`, []Directive{{Scope: ScopeLine}}},
		{`# the aitriage-ignored list is empty`, nil},
		{`# nothing to see`, nil},
	}
	for _, tc := range cases {
		got := ParseLine(tc.line)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseLine(%q) = %+v; want %+v", tc.line, got, tc.want)
		}
	}
}

// The reported bug: the reason "(allowed in tests)" contains "all", and the
// old check looked for "all" anywhere on the line, so one narrow suppression
// silenced every rule on that line.
func TestReasonTextDoesNotWidenASuppression(t *testing.T) {
	content := []byte("import os\nPASSWORD = 'x'  # aitriage-ignore: B105 (allowed in tests)\nos.system(cmd)\n")

	if !Suppressed(content, 2, "B105", "bandit") {
		t.Error("B105 on the directive's line must be silenced")
	}
	for _, rule := range []string{"SECRET-ASSIGN", "B602", "generic-api-key", "ENTR-01"} {
		if Suppressed(content, 2, rule, "aitriage") {
			t.Errorf("%s was silenced by a directive that names only B105", rule)
		}
	}
}

// IDs separated by a space were accepted by the earlier substring matching, and
// a real repository relied on it: "# aitriage-ignore: ENTR-18 PY-BINDING-ALL"
// silenced both rules until the token parser stopped at the first id and
// PY-BINDING-ALL resurfaced.
func TestIDsSeparatedBySpacesAreAllRead(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`settings.ALLOWED_HOSTS = ["*"]  # aitriage-ignore: ENTR-18 PY-BINDING-ALL`, []string{"ENTR-18", "PY-BINDING-ALL"}},
		{`// aitriage-ignore: B105 B106 (fixture data)`, []string{"B105", "B106"}},
		{`# aitriage-ignore: B105, B106 B107`, []string{"B105", "B106", "B107"}},
		{`# aitriage-ignore: B105 B106, B107`, []string{"B105", "B106", "B107"}},
		{`# aitriage-ignore: nginx_missing_csp CVE-2024-1234 python.lang.security.audit.eval`, []string{"nginx_missing_csp", "CVE-2024-1234", "python.lang.security.audit.eval"}},
		{`# aitriage-ignore: gitleaks:jwt semgrep:sqli SECRET`, []string{"gitleaks:jwt", "semgrep:sqli", "SECRET"}},
		{`<!-- aitriage-ignore: XSS-01 XSS-02 -->`, []string{"XSS-01", "XSS-02"}},
		{`# aitriage-ignore: R1 R2. Reviewed with the team`, []string{"R1", "R2"}},
		// The first id and ids after a comma are read as written, so a
		// lower-case id such as gitleaks' jwt still works.
		{`# aitriage-ignore: jwt`, []string{"jwt"}},
		{`# aitriage-ignore: generic-api-key, jwt`, []string{"generic-api-key", "jwt"}},
	}
	for _, tc := range cases {
		got := ParseLine(tc.line)
		if len(got) != 1 || !reflect.DeepEqual(got[0].IDs, tc.want) {
			t.Errorf("ParseLine(%q) = %+v; want IDs %q", tc.line, got, tc.want)
		}
	}

	content := []byte("settings.ALLOWED_HOSTS = ['*']  # aitriage-ignore: ENTR-18 PY-BINDING-ALL\nDEBUG = True\n")
	for _, rule := range []string{"ENTR-18", "PY-BINDING-ALL"} {
		for _, line := range []int{1, 2} {
			if !Suppressed(content, line, rule) {
				t.Errorf("%s on line %d was not silenced by a directive that names it", rule, line)
			}
		}
	}
	if Suppressed(content, 1, "PY-DEBUG") {
		t.Error("a rule the directive does not name was silenced")
	}
}

// A reason written after the ids, with or without parentheses, is prose: none
// of its words may become an id, and "all" in it never silences every rule.
func TestProseAfterTheIDsIsNotRead(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`# aitriage-ignore: B105 allowed in tests`, []string{"B105"}},
		{`# aitriage-ignore: B105 (allowed in tests)`, []string{"B105"}},
		{`# aitriage-ignore: ENTR-18 because the value is a test fixture`, []string{"ENTR-18"}},
		{`# aitriage-ignore: B105 all good`, []string{"B105"}},
		{`# aitriage-ignore: B105 ALL of it is fake`, []string{"B105"}},
		{`# aitriage-ignore: B105 Allowed by the security team`, []string{"B105"}},
		{`# aitriage-ignore: B105 reviewed, see the PR`, []string{"B105"}},
		{`# aitriage-ignore: B105 tests.`, []string{"B105"}},
		{`# aitriage-ignore: B105 -- reviewed`, []string{"B105"}},
		{`# aitriage-ignore: B105(allowed) B106`, []string{"B105"}},
	}
	for _, tc := range cases {
		got := ParseLine(tc.line)
		if len(got) != 1 || !reflect.DeepEqual(got[0].IDs, tc.want) {
			t.Errorf("ParseLine(%q) = %+v; want IDs %q", tc.line, got, tc.want)
		}
	}

	content := []byte("password = 'x'  # aitriage-ignore: B105 all good, allowed in tests\n")
	if !Suppressed(content, 1, "B105") {
		t.Error("the named rule was not silenced")
	}
	for _, rule := range []string{"B106", "SECRET-ASSIGN", "allowed", "good", "tests"} {
		if Suppressed(content, 1, rule) {
			t.Errorf("%s was silenced by words of the reason", rule)
		}
	}
}

func TestIDsCompareWholeAndCaseInsensitively(t *testing.T) {
	content := []byte("x = 1  # aitriage-ignore: ENTR-10, b105\n")

	if !Suppressed(content, 1, "ENTR-10") || !Suppressed(content, 1, "B105") {
		t.Error("listed ids must be silenced regardless of case")
	}
	// "ENTR-10" used to silence ENTR-1, and a long id every id it contained.
	for _, rule := range []string{"ENTR-1", "B10", "ENTR-100"} {
		if Suppressed(content, 1, rule) {
			t.Errorf("%s was silenced by a directive naming a different id", rule)
		}
	}
}

func TestAllMustBeAStandaloneToken(t *testing.T) {
	if !Suppressed([]byte("call(x)  # aitriage-ignore: all\n"), 1, "ANY-RULE") {
		t.Error("an explicit all must silence every rule")
	}
	for _, line := range []string{
		"subprocess.call(cmd)  # aitriage-ignore",
		"x = install()  # aitriage-ignore: B105 (allowed)",
		"# aitriage-ignore: allowlist-check",
	} {
		if Suppressed([]byte(line+"\n"), 1, "B602") {
			t.Errorf("%q silenced an unnamed rule", line)
		}
	}
}

func TestDirectiveScopes(t *testing.T) {
	content := []byte(strings.Join([]string{
		"line one",
		"# aitriage-ignore: R1",
		"covered by the line above",
		"# aitriage-ignore-next-line: R2",
		"covered by next-line",
		"not covered",
	}, "\n"))

	cases := []struct {
		line int
		rule string
		want bool
	}{
		{2, "R1", true},  // the directive's own line
		{3, "R1", true},  // the line below it
		{4, "R1", false}, // two lines below
		{4, "R2", false}, // next-line does not cover its own line
		{5, "R2", true},
		{6, "R2", false},
		{0, "R1", false}, // no line: only a file-level directive applies
	}
	for _, tc := range cases {
		if got := Suppressed(content, tc.line, tc.rule); got != tc.want {
			t.Errorf("Suppressed(line %d, %s) = %t; want %t", tc.line, tc.rule, got, tc.want)
		}
	}
}

func TestFileLevelDirective(t *testing.T) {
	header := "#!/usr/bin/env python\n# aitriage-ignore-file\n"
	if !Suppressed([]byte(header+strings.Repeat("x = 1\n", 50)), 40, "B105") {
		t.Error("a bare file-level directive silences every rule in the file")
	}
	if !Suppressed([]byte(header), 0, "CVE-2024-1234", "trivy") {
		t.Error("a file-level directive also covers findings without a line")
	}

	named := "# aitriage-ignore-file: B101\n" + strings.Repeat("assert x\n", 20)
	if !Suppressed([]byte(named), 15, "B101") || Suppressed([]byte(named), 15, "B105") {
		t.Error("a file-level directive with ids silences only those ids")
	}

	late := strings.Repeat("x = 1\n", FileHeaderLines) + "# aitriage-ignore-file\n" + "y = 2\n"
	if Suppressed([]byte(late), FileHeaderLines+2, "B105") {
		t.Error("a file-level directive below the header must be ignored")
	}
}

// A directive was recognised anywhere on a line, so prose or a string that
// merely mentioned the file directive silenced every finding in its file,
// including gitleaks, Trivy and deploy findings.
func TestMentionsOfADirectiveAreNotDirectives(t *testing.T) {
	cases := map[string]string{
		"readme prose":           "# Project notes\n\nTo skip a generated file, add aitriage-ignore-file.\n\nAWS_KEY = 'AKIA...'\n",
		"string literal":         "HELP = \"put aitriage-ignore-file\"\nTOKEN = 'ghp_xxx'\n",
		"comment that refers":    "// see `aitriage-ignore-file`\nmodule example.com/x\n",
		"comment prose":          "# use aitriage-ignore-file to skip generated code\nTOKEN = 'x'\n",
		"marker inside a string": "HELP = \" # aitriage-ignore-file\"\nTOKEN = 'x'\n",
		"raw string":             "const doc = `# aitriage-ignore-file`\nvar token = \"x\"\n",
		"markdown link":          "See [inline directives](#aitriage-ignore-file).\nAWS_KEY=AKIA\n",
		"url fragment":           "Docs: https://example.com/inline#aitriage-ignore-file\nAWS_KEY=AKIA\n",
		"markdown bullet":        "* aitriage-ignore-file silences a whole file\nAWS_KEY=AKIA\n",
		"glob is not a comment":  "cp src/* /app/\n * aitriage-ignore-file\nAWS_KEY=AKIA\n",
		"closed block comment":   "/* header */\n * aitriage-ignore-file\nAWS_KEY=AKIA\n",
	}
	for name, content := range cases {
		lines := strings.Count(content, "\n")
		if Suppressed([]byte(content), lines, "generic-api-key", "gitleaks") {
			t.Errorf("%s: %q silenced a finding on its last line", name, content)
		}
	}

	if Suppressed([]byte(`password = "x"  # see aitriage-ignore: B105`+"\n"), 1, "B105", "bandit") {
		t.Error("a comment that mentions a line directive silenced the line")
	}
}

func TestDirectivesInEveryCommentSyntax(t *testing.T) {
	for _, line := range []string{
		`x = 1  # aitriage-ignore: R1`,
		`x := 1 // aitriage-ignore: R1`,
		`x = 1; // aitriage-ignore: R1`,
		`/* aitriage-ignore: R1 */`,
		`/** aitriage-ignore: R1 */`,
		`/// aitriage-ignore: R1`,
		`<!-- aitriage-ignore: R1 -->`,
		`SELECT 1 -- aitriage-ignore: R1`,
		`; aitriage-ignore: R1`,
		`{# aitriage-ignore: R1 #}`,
		`{{/* aitriage-ignore: R1 */}}`,
		`{{- /* aitriage-ignore: R1 */ -}}`,
		`<%# aitriage-ignore: R1 %>`,
		`x = load()  # noqa: S105  # aitriage-ignore: R1`,
		`key := "k" //nolint:gosec // aitriage-ignore: R1`,
		`description: Don't run as root  # aitriage-ignore: R1`,
		`password = 'x'  # aitriage-ignore: R1`,
		`fn f<'a>(x: &'a str) {} // aitriage-ignore: R1`,
	} {
		got := ParseLine(line)
		if len(got) != 1 || got[0].Scope != ScopeLine || len(got[0].IDs) != 1 || got[0].IDs[0] != "R1" {
			t.Errorf("ParseLine(%q) = %+v; want one directive for R1", line, got)
		}
	}
}

// A directive may stand on a line of its own inside a block comment.
func TestDirectiveOnItsOwnLineInsideABlockComment(t *testing.T) {
	for name, content := range map[string]string{
		"doc block": "/**\n * aitriage-ignore-file\n */\npackage x\nvar key = \"AKIA\"\n",
		"c block":   "/*\n   aitriage-ignore-file: generic-api-key\n*/\nvar key = \"AKIA\"\n",
		"markup":    "<!--\naitriage-ignore-file\n-->\n<p>AKIA</p>\n",
	} {
		if !Suppressed([]byte(content), 5, "generic-api-key", "gitleaks") {
			t.Errorf("%s: %q did not silence the file", name, content)
		}
	}
}

// A string literal ended with its line, so a directive in a string spanning
// lines was read as a comment: "# aitriage-ignore-file" in the second line of
// a docstring silenced every finding in the file.
func TestDirectivesInsideStringsThatSpanLinesAreText(t *testing.T) {
	cases := map[string]struct {
		content string
		line    int
	}{
		"python docstring":            {"\"\"\"Usage notes.\n# aitriage-ignore-file\n\"\"\"\nTOKEN = 'ghp_example'\n", 4},
		"python single-quoted triple": {"HELP = '''\n# aitriage-ignore-file\n'''\nTOKEN = 'ghp_example'\n", 4},
		"python prefixed docstring":   {"HELP = r\"\"\"\\d+\n# aitriage-ignore-file\n\"\"\"\nTOKEN = 'ghp_example'\n", 4},
		"js template literal":         {"const help = `\n// aitriage-ignore-file\n`;\nconst token = 'ghp_example';\n", 4},
		"ts tagged template":          {"const q = sql`\n  -- aitriage-ignore-file\n  SELECT 1`;\nconst token = 'ghp_example';\n", 4},
		"go raw string":               {"package x\nconst doc = `\n# aitriage-ignore-file\n`\nvar token = \"ghp_example\"\n", 5},
		"line directive in a string":  {"HELP = \"\"\"\n# aitriage-ignore: generic-api-key\nTOKEN = 'ghp_example'\n\"\"\"\n", 3},
		"next-line directive":         {"HELP = `\n// aitriage-ignore-next-line: generic-api-key\nTOKEN = 'ghp_example'\n`\n", 3},
		"block marker in a string":    {"HELP = \"\"\"\n/* aitriage-ignore-file */\n\"\"\"\nTOKEN = 'ghp_example'\n", 4},
		"bare line in a string":       {"HELP = \"\"\"\naitriage-ignore-file\n\"\"\"\nTOKEN = 'ghp_example'\n", 4},
	}
	for name, tc := range cases {
		if Suppressed([]byte(tc.content), tc.line, "generic-api-key", "gitleaks") {
			t.Errorf("%s: a directive inside a string silenced the finding on line %d", name, tc.line)
		}
	}
}

// Once a string that spans lines is closed, comments count again, including
// one on the line that closes it, and strings that do not span lines change
// nothing. A Go raw string has no escapes: `\` is a complete string, and the
// escaped backticks of a template literal come in pairs.
func TestDirectivesAfterAStringThatSpansLinesCount(t *testing.T) {
	cases := map[string]struct {
		content string
		line    int
	}{
		"after a docstring":         {"\"\"\"Module notes.\n\nMore notes.\n\"\"\"\nTOKEN = 'x'  # aitriage-ignore: generic-api-key\n", 5},
		"on the closing line":       {"HELP = \"\"\"\ntext\n\"\"\"  # aitriage-ignore: generic-api-key\n", 3},
		"one-line docstring":        {"def f():\n    \"\"\"Docs.\"\"\"\n    return 'x'  # aitriage-ignore: generic-api-key\n", 3},
		"escaped quote":             {"HELP = \"\"\"a \\\"\"\" b\n\"\"\"\nTOKEN = 'x'  # aitriage-ignore: generic-api-key\n", 3},
		"after a template":          {"const t = `\n${a}\n`;\nconst key = 'x'; // aitriage-ignore: generic-api-key\n", 4},
		"go raw backslash":          {"package x\nvar sep = `\\`\nvar key = \"x\" // aitriage-ignore: generic-api-key\n", 3},
		"two go raw strings":        {"package x\nvar s = strings.ReplaceAll(p, `\\`, `\\\\`)\nvar key = \"x\" // aitriage-ignore: generic-api-key\n", 3},
		"escaped backticks in pair": {"const md = `\\`\\`\\`js\\n${code}\\n\\`\\`\\``;\nconst key = 'x'; // aitriage-ignore: generic-api-key\n", 2},
		"quotes inside a comment":   {"/* say \"\"\" or ` here */\nconst key = 'x'; // aitriage-ignore: generic-api-key\n", 2},
		"triple quote in a string":  {"x = \"'''\" + '\"\"\"'\nkey = 'x'  # aitriage-ignore: generic-api-key\n", 2},
		"file directive after one":  {"\"\"\"Docs.\"\"\"\n# aitriage-ignore-file\nTOKEN = 'x'\n", 3},
	}
	for name, tc := range cases {
		if !Suppressed([]byte(tc.content), tc.line, "generic-api-key", "gitleaks") {
			t.Errorf("%s: the directive did not silence the finding on line %d", name, tc.line)
		}
	}
}

// The state is carried across every line, also lines far from the finding: a
// docstring opened at the top of the file still hides a directive deep inside
// it, and one closed above still lets a directive below count.
func TestStringStateIsTrackedAcrossTheWholeFile(t *testing.T) {
	var b strings.Builder
	b.WriteString("\"\"\"Long module documentation.\n")
	for i := 0; i < 40; i++ {
		b.WriteString("Some text.\n")
	}
	b.WriteString("Example: x = 1  # aitriage-ignore: R1\n") // line 42, inside the docstring
	b.WriteString("x = 1\n")                                 // line 43
	b.WriteString("\"\"\"\n")                                // line 44 closes it
	b.WriteString("y = 2  # aitriage-ignore: R1\n")          // line 45
	content := []byte(b.String())

	if Suppressed(content, 43, "R1") {
		t.Error("a directive inside a docstring silenced the line below it")
	}
	if !Suppressed(content, 45, "R1") {
		t.Error("a directive after the docstring did not count")
	}
}

func TestQualifiedIDsMatchOnlyTheirSource(t *testing.T) {
	content := []byte("TOKEN = 'abc'  # aitriage-ignore: gitleaks:generic-api-key\n")

	if !Suppressed(content, 1, "generic-api-key", "gitleaks") {
		t.Error("the qualified id must silence the gitleaks finding")
	}
	if Suppressed(content, 1, "generic-api-key", "semgrep") {
		t.Error("a gitleaks-qualified id must not silence another scanner")
	}
}
