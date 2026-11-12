package agentcontext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scanner output can be stale: a finding may point at a line of a file that
// has since been shortened. Extracting its context sliced the file's lines
// with an unclamped window and panicked ("slice bounds out of range [9:4]"),
// which took the whole run down.
func TestExtractFunctionClampsALinePastTheEndOfTheFile(t *testing.T) {
	sources := map[string]string{
		"main.go":   "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n",
		"app.py":    "import os\n\ndef run():\n    os.system('ls')\n",
		"index.js":  "import x from 'x';\n\nfunction f() {\n  return x;\n}\n",
		"notes.txt": "one\ntwo\nthree\n",
		"empty.py":  "",
	}
	dir := t.TempDir()
	for name, content := range sources {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		lines := strings.Count(content, "\n")
		for _, line := range []int{lines + 2, lines + 31, lines + 40, 100_000} {
			fc, err := ExtractFunction(path, line)
			if err != nil {
				t.Fatalf("%s line %d: %v", name, line, err)
			}
			if fc.StartLine < 1 || fc.EndLine < fc.StartLine-1 {
				t.Errorf("%s line %d: window %d-%d is not a range of the file", name, line, fc.StartLine, fc.EndLine)
			}
			if content != "" && !strings.Contains(content, strings.TrimSpace(fc.Body)) {
				t.Errorf("%s line %d: body %q is not taken from the file", name, line, fc.Body)
			}
			if !strings.Contains(fc.Name, "past the end of the file") {
				t.Errorf("%s line %d: name %q does not say the line is past the end", name, line, fc.Name)
			}
		}
	}
}

// The window around a line inside the file, and around a missing line, is
// unchanged.
func TestExtractFallbackWindow(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		b.WriteString("line\n")
	}
	content := []byte(b.String())

	for _, tc := range []struct {
		line, start, end int
	}{
		{50, 20, 79},
		{1, 1, 30},
		{0, 1, 30},
		{-5, 1, 30},
		{100, 70, 101},
		{131, 71, 101}, // past the end: the last lines of the file
	} {
		fc := extractFallback(content, tc.line, "notes.txt")
		if fc.StartLine != tc.start || fc.EndLine != tc.end {
			t.Errorf("line %d: window %d-%d; want %d-%d", tc.line, fc.StartLine, fc.EndLine, tc.start, tc.end)
		}
	}
}
