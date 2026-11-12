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

func TestQualifiedIDsMatchOnlyTheirSource(t *testing.T) {
	content := []byte("TOKEN = 'abc'  # aitriage-ignore: gitleaks:generic-api-key\n")

	if !Suppressed(content, 1, "generic-api-key", "gitleaks") {
		t.Error("the qualified id must silence the gitleaks finding")
	}
	if Suppressed(content, 1, "generic-api-key", "semgrep") {
		t.Error("a gitleaks-qualified id must not silence another scanner")
	}
}
