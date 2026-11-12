package regions

import "testing"

func kindsOf(t *testing.T, path, src, needle string) Kind {
	t.Helper()
	i := indexOf(src, needle)
	if i < 0 {
		t.Fatalf("%q not in source", needle)
	}
	return Bytes([]byte(src), SyntaxForPath(path))[i]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestBytesClassifiesWholeFile(t *testing.T) {
	src := "import os\n# os.system(cmd) in a comment\nx = \"os.system\"\nos.system(cmd)\n\"\"\"\nos.system(doc)\n\"\"\"\n"
	tests := []struct {
		needle string
		want   Kind
	}{
		{"# os.system", Comment},
		{"os.system\"", String},
		{"os.system(cmd)\n\"\"\"", Code},
		{"os.system(doc)", String},
	}
	for _, tt := range tests {
		if got := kindsOf(t, "app.py", src, tt.needle); got != tt.want {
			t.Errorf("%q: got %v, want %v", tt.needle, got, tt.want)
		}
	}
}

func TestBytesKeepsOffsetsAcrossBlockComments(t *testing.T) {
	src := "/*\n eval(x)\n*/\neval(y);\n"
	if got := kindsOf(t, "a.js", src, "eval(x)"); got != Comment {
		t.Errorf("eval in block comment: got %v", got)
	}
	if got := kindsOf(t, "a.js", src, "eval(y)"); got != Code {
		t.Errorf("eval after block comment: got %v", got)
	}
}

func TestHashCommentsForConfig(t *testing.T) {
	src := "cap_add:\n  - SYS_ADMIN # needed\n# privileged: true\nimage: \"app#1\"\n"
	kinds := Bytes([]byte(src), HashComments)
	if k := kinds[indexOf(src, "SYS_ADMIN")]; k != Code {
		t.Errorf("value: got %v", k)
	}
	if k := kinds[indexOf(src, "# needed")]; k != Comment {
		t.Errorf("trailing comment: got %v", k)
	}
	if k := kinds[indexOf(src, "# privileged")]; k != Comment {
		t.Errorf("comment line: got %v", k)
	}
	if k := kinds[indexOf(src, "#1")]; k != String {
		t.Errorf("hash inside quotes: got %v", k)
	}
}

func TestUnknownSyntaxOnlyWholeLineComments(t *testing.T) {
	s := SyntaxForPath("notes.md")
	if s.Known() {
		t.Fatal("markdown should be unknown")
	}
	src := "# heading\ntext # not a comment\n"
	kinds := Bytes([]byte(src), s)
	if kinds[0] != Comment || kinds[indexOf(src, "# not")] != Code {
		t.Errorf("unexpected kinds for unknown syntax")
	}
}
