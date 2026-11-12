// Package regions classifies each byte of a source file as code, comment or
// string literal with a small per-language scanner. It is deliberately not a
// parser: it knows the comment and string delimiters of common languages and
// config formats, and treats a file of unknown type as code except for whole
// lines that start with a common comment marker.
//
// Callers decide what an ambiguous construct means for them. Evidence
// validation prefers "not code" (the finding goes to manual review), while a
// detection rule that drops matches outside code would lose a finding, so rule
// authors pick a region filter that fits the pattern.
package regions

import (
	"path/filepath"
	"strings"
)

// Kind is the region a byte belongs to.
type Kind uint8

const (
	Code Kind = iota
	Comment
	String
)

// Syntax describes the comment and string delimiters of a language.
type Syntax struct {
	lineComments    []string
	blockComments   [][2]string
	quotes          string   // single-line string delimiters
	multilineQuotes []string // delimiters of strings that may span lines
	// hashNeedsSpace: "#" opens a comment only at the start of a word (shell).
	hashNeedsSpace bool
	// cLike: a line starting with "*" is a block-comment continuation.
	cLike bool
	// leadingOnly: the language is unknown; only a whole line that starts
	// with a common comment marker is treated as a comment.
	leadingOnly bool
}

var (
	cFamilySyntax = Syntax{
		lineComments:  []string{"//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
		cLike:         true,
	}
	jsFamilySyntax = Syntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
		cLike:           true,
	}
	goSyntax = Syntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
		cLike:           true,
	}
	jvmSyntax = Syntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{`"""`},
		cLike:           true,
	}
	// Rust: a single quote also starts a lifetime ('a), so only double
	// quotes delimit strings.
	rustSyntax = Syntax{
		lineComments:  []string{"//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"`,
		cLike:         true,
	}
	pythonSyntax = Syntax{
		lineComments:    []string{"#"},
		quotes:          `"'`,
		multilineQuotes: []string{`"""`, `'''`},
	}
	hashSyntax = Syntax{
		lineComments: []string{"#"},
		quotes:       `"'`,
	}
	shellSyntax = Syntax{
		lineComments:   []string{"#"},
		quotes:         `"'`,
		hashNeedsSpace: true,
	}
	phpSyntax = Syntax{
		lineComments:  []string{"//", "#"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
		cLike:         true,
	}
	sqlSyntax = Syntax{
		lineComments:  []string{"--"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `'"`,
	}
	luaSyntax = Syntax{
		lineComments: []string{"--"},
		quotes:       `"'`,
	}
	markupSyntax = Syntax{
		blockComments: [][2]string{{"<!--", "-->"}},
		quotes:        `"'`,
	}
	componentSyntax = Syntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"<!--", "-->"}, {"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
	}
	cssSyntax = Syntax{
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
	}
	semicolonSyntax = Syntax{
		lineComments: []string{";"},
		quotes:       `"'`,
	}
	hclSyntax = Syntax{
		lineComments:  []string{"#", "//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"`,
	}
	unknownSyntax = Syntax{leadingOnly: true}
)

var syntaxByExtension = map[string]Syntax{
	".go":     goSyntax,
	".js":     jsFamilySyntax,
	".jsx":    jsFamilySyntax,
	".mjs":    jsFamilySyntax,
	".cjs":    jsFamilySyntax,
	".ts":     jsFamilySyntax,
	".tsx":    jsFamilySyntax,
	".mts":    jsFamilySyntax,
	".cts":    jsFamilySyntax,
	".java":   jvmSyntax,
	".kt":     jvmSyntax,
	".kts":    jvmSyntax,
	".scala":  jvmSyntax,
	".groovy": jvmSyntax,
	".swift":  jvmSyntax,
	".c":      cFamilySyntax,
	".h":      cFamilySyntax,
	".cc":     cFamilySyntax,
	".cpp":    cFamilySyntax,
	".cxx":    cFamilySyntax,
	".hpp":    cFamilySyntax,
	".m":      cFamilySyntax,
	".mm":     cFamilySyntax,
	".cs":     cFamilySyntax,
	".rs":     rustSyntax,
	".dart":   cFamilySyntax,
	".py":     pythonSyntax,
	".pyw":    pythonSyntax,
	".pyi":    pythonSyntax,
	".rb":     hashSyntax,
	".pl":     hashSyntax,
	".pm":     hashSyntax,
	".r":      hashSyntax,
	".ex":     hashSyntax,
	".exs":    hashSyntax,
	".sh":     shellSyntax,
	".bash":   shellSyntax,
	".zsh":    shellSyntax,
	".ps1":    hashSyntax,
	".php":    phpSyntax,
	".sql":    sqlSyntax,
	".lua":    luaSyntax,
	".hs":     luaSyntax,
	".html":   markupSyntax,
	".htm":    markupSyntax,
	".xhtml":  markupSyntax,
	".xml":    markupSyntax,
	".svg":    markupSyntax,
	".jsp":    markupSyntax,
	".vue":    componentSyntax,
	".svelte": componentSyntax,
	".astro":  componentSyntax,
	".css":    cssSyntax,
	".scss":   jsFamilySyntax,
	".less":   jsFamilySyntax,
	".clj":    semicolonSyntax,
	".el":     semicolonSyntax,
	".lisp":   semicolonSyntax,
	".asm":    semicolonSyntax,
	".tf":     hclSyntax,
	".hcl":    hclSyntax,
}

// SyntaxForPath returns the syntax of a file from its name.
func SyntaxForPath(path string) Syntax {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile"):
		return shellSyntax
	case base == "makefile" || base == "gnumakefile":
		return hashSyntax
	case base == "jenkinsfile":
		return jvmSyntax
	}
	if syntax, ok := syntaxByExtension[filepath.Ext(base)]; ok {
		return syntax
	}
	return unknownSyntax
}

// scanState carries multi-line constructs from one line to the next.
type scanState struct {
	blockEnd  string // closing delimiter of an open block comment
	stringEnd string // closing delimiter of an open multi-line string
}

// Lines classifies every byte of lines[0..last], scanning the file from
// the top so block comments and multi-line strings opened earlier are known.
func Lines(lines []string, last int, syntax Syntax) [][]Kind {
	last = min(last, len(lines)-1)
	if last < 0 {
		return nil
	}
	regions := make([][]Kind, last+1)
	var state scanState
	for i := range regions {
		if syntax.leadingOnly {
			regions[i] = leadingOnlyRegions(lines[i])
			continue
		}
		regions[i] = scanLine(lines[i], syntax, &state)
	}
	return regions
}

func scanLine(line string, syntax Syntax, state *scanState) []Kind {
	kinds := make([]Kind, len(line))
	mark := func(from, to int, kind Kind) {
		for i := from; i < to && i < len(kinds); i++ {
			kinds[i] = kind
		}
	}
	singleLineString := ""
	if state.blockEnd == "" && state.stringEnd == "" && syntax.cLike && isCommentContinuation(line) {
		mark(0, len(line), Comment)
		return kinds
	}

	for i := 0; i < len(line); {
		switch {
		case state.blockEnd != "":
			if strings.HasPrefix(line[i:], state.blockEnd) {
				mark(i, i+len(state.blockEnd), Comment)
				i += len(state.blockEnd)
				state.blockEnd = ""
				continue
			}
			kinds[i] = Comment
			i++
		case singleLineString != "" || state.stringEnd != "":
			end := singleLineString
			if end == "" {
				end = state.stringEnd
			}
			if line[i] == '\\' && end != "`" {
				mark(i, i+2, String)
				i += 2
				continue
			}
			if strings.HasPrefix(line[i:], end) {
				mark(i, i+len(end), String)
				i += len(end)
				singleLineString, state.stringEnd = "", ""
				continue
			}
			kinds[i] = String
			i++
		default:
			if lineCommentAt(line, i, syntax) {
				mark(i, len(line), Comment)
				return kinds
			}
			if open, closing, ok := blockCommentAt(line[i:], syntax); ok {
				mark(i, i+len(open), Comment)
				i += len(open)
				state.blockEnd = closing
				continue
			}
			if delimiter, ok := prefixIn(line[i:], syntax.multilineQuotes); ok {
				mark(i, i+len(delimiter), String)
				i += len(delimiter)
				state.stringEnd = delimiter
				continue
			}
			if strings.IndexByte(syntax.quotes, line[i]) >= 0 {
				kinds[i] = String
				singleLineString = line[i : i+1]
				i++
				continue
			}
			kinds[i] = Code
			i++
		}
	}
	// A single-line string cannot continue past the end of the line.
	return kinds
}

func lineCommentAt(line string, i int, syntax Syntax) bool {
	for _, marker := range syntax.lineComments {
		if !strings.HasPrefix(line[i:], marker) {
			continue
		}
		if marker == "#" && syntax.hashNeedsSpace && i > 0 && line[i-1] != ' ' && line[i-1] != '\t' {
			continue
		}
		return true
	}
	return false
}

func blockCommentAt(rest string, syntax Syntax) (string, string, bool) {
	for _, pair := range syntax.blockComments {
		if strings.HasPrefix(rest, pair[0]) {
			return pair[0], pair[1], true
		}
	}
	return "", "", false
}

func prefixIn(rest string, prefixes []string) (string, bool) {
	for _, prefix := range prefixes {
		if strings.HasPrefix(rest, prefix) {
			return prefix, true
		}
	}
	return "", false
}

// isCommentContinuation recognises the " * text" lines of a C-style block
// comment. A pointer dereference ("*ptr = 1") is not followed by a space.
func isCommentContinuation(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "*" || strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "*/")
}

var leadingCommentMarkers = []string{"#", "//", "--", ";", "/*", "*", "<!--"}

func leadingOnlyRegions(line string) []Kind {
	kinds := make([]Kind, len(line))
	trimmed := strings.TrimSpace(line)
	if _, ok := prefixIn(trimmed, leadingCommentMarkers); ok {
		for i := range kinds {
			kinds[i] = Comment
		}
	}
	return kinds
}

// HashComments is the syntax of configuration formats where "#" starts a
// comment at the start of a line or after whitespace (YAML, .env, TOML,
// properties). SyntaxForPath leaves these formats unknown, because evidence
// validation must not treat them as source code; detection rules opt in.
var HashComments = Syntax{lineComments: []string{"#"}, quotes: `"'`, hashNeedsSpace: true}

// Bytes classifies every byte of content, a whole file, with the given
// syntax. Line breaks are reported as Code.
func Bytes(content []byte, syntax Syntax) []Kind {
	kinds := make([]Kind, len(content))
	if len(content) == 0 {
		return kinds
	}
	lines := strings.Split(string(content), "\n")
	offset := 0
	for _, lineKinds := range Lines(lines, len(lines)-1, syntax) {
		copy(kinds[offset:], lineKinds)
		offset += len(lineKinds) + 1 // the "\n" stays Code
	}
	return kinds
}

// Known reports whether the syntax belongs to a recognised language. For an
// unknown file type only whole-line comments are detected.
func (s Syntax) Known() bool { return !s.leadingOnly }
