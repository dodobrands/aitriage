package graph

import (
	"path/filepath"
	"strings"
)

// ── Comment and string-literal regions ───────────────────────────────────────
//
// code_mitigation evidence must point at code. A model citing a comment
// ("# Local smoke test only - NOT for production.") or a string literal was
// enough to suppress a finding, because the validator only checked that the
// quoted text existed on the cited line. This file classifies each byte of a
// source line as code, comment or string literal with a small per-language
// scanner. It is deliberately not a parser: when a construct is ambiguous it
// leans towards "not code", which can only send a finding to manual review,
// never suppress one.

type regionKind uint8

const (
	regionCode regionKind = iota
	regionComment
	regionString
)

// sourceSyntax describes the comment and string delimiters of a language.
type sourceSyntax struct {
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
	cFamilySyntax = sourceSyntax{
		lineComments:  []string{"//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
		cLike:         true,
	}
	jsFamilySyntax = sourceSyntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
		cLike:           true,
	}
	goSyntax = sourceSyntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
		cLike:           true,
	}
	jvmSyntax = sourceSyntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{`"""`},
		cLike:           true,
	}
	// Rust: a single quote also starts a lifetime ('a), so only double
	// quotes delimit strings.
	rustSyntax = sourceSyntax{
		lineComments:  []string{"//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"`,
		cLike:         true,
	}
	pythonSyntax = sourceSyntax{
		lineComments:    []string{"#"},
		quotes:          `"'`,
		multilineQuotes: []string{`"""`, `'''`},
	}
	hashSyntax = sourceSyntax{
		lineComments: []string{"#"},
		quotes:       `"'`,
	}
	shellSyntax = sourceSyntax{
		lineComments:   []string{"#"},
		quotes:         `"'`,
		hashNeedsSpace: true,
	}
	phpSyntax = sourceSyntax{
		lineComments:  []string{"//", "#"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
		cLike:         true,
	}
	sqlSyntax = sourceSyntax{
		lineComments:  []string{"--"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `'"`,
	}
	luaSyntax = sourceSyntax{
		lineComments: []string{"--"},
		quotes:       `"'`,
	}
	markupSyntax = sourceSyntax{
		blockComments: [][2]string{{"<!--", "-->"}},
		quotes:        `"'`,
	}
	componentSyntax = sourceSyntax{
		lineComments:    []string{"//"},
		blockComments:   [][2]string{{"<!--", "-->"}, {"/*", "*/"}},
		quotes:          `"'`,
		multilineQuotes: []string{"`"},
	}
	cssSyntax = sourceSyntax{
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"'`,
	}
	semicolonSyntax = sourceSyntax{
		lineComments: []string{";"},
		quotes:       `"'`,
	}
	hclSyntax = sourceSyntax{
		lineComments:  []string{"#", "//"},
		blockComments: [][2]string{{"/*", "*/"}},
		quotes:        `"`,
	}
	unknownSyntax = sourceSyntax{leadingOnly: true}
)

var syntaxByExtension = map[string]sourceSyntax{
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

func syntaxForPath(path string) sourceSyntax {
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

// lineRegions classifies every byte of lines[target], scanning the file from
// the top so block comments and multi-line strings opened earlier are known.
func lineRegions(lines []string, target int, syntax sourceSyntax) []regionKind {
	if target < 0 || target >= len(lines) {
		return nil
	}
	if syntax.leadingOnly {
		return leadingOnlyRegions(lines[target])
	}
	var state scanState
	var kinds []regionKind
	for i := 0; i <= target; i++ {
		kinds = scanLine(lines[i], syntax, &state)
	}
	return kinds
}

func scanLine(line string, syntax sourceSyntax, state *scanState) []regionKind {
	kinds := make([]regionKind, len(line))
	mark := func(from, to int, kind regionKind) {
		for i := from; i < to && i < len(kinds); i++ {
			kinds[i] = kind
		}
	}
	singleLineString := ""
	if state.blockEnd == "" && state.stringEnd == "" && syntax.cLike && isCommentContinuation(line) {
		mark(0, len(line), regionComment)
		return kinds
	}

	for i := 0; i < len(line); {
		switch {
		case state.blockEnd != "":
			if strings.HasPrefix(line[i:], state.blockEnd) {
				mark(i, i+len(state.blockEnd), regionComment)
				i += len(state.blockEnd)
				state.blockEnd = ""
				continue
			}
			kinds[i] = regionComment
			i++
		case singleLineString != "" || state.stringEnd != "":
			end := singleLineString
			if end == "" {
				end = state.stringEnd
			}
			if line[i] == '\\' && end != "`" {
				mark(i, i+2, regionString)
				i += 2
				continue
			}
			if strings.HasPrefix(line[i:], end) {
				mark(i, i+len(end), regionString)
				i += len(end)
				singleLineString, state.stringEnd = "", ""
				continue
			}
			kinds[i] = regionString
			i++
		default:
			if lineCommentAt(line, i, syntax) {
				mark(i, len(line), regionComment)
				return kinds
			}
			if open, closing, ok := blockCommentAt(line[i:], syntax); ok {
				mark(i, i+len(open), regionComment)
				i += len(open)
				state.blockEnd = closing
				continue
			}
			if delimiter, ok := prefixIn(line[i:], syntax.multilineQuotes); ok {
				mark(i, i+len(delimiter), regionString)
				i += len(delimiter)
				state.stringEnd = delimiter
				continue
			}
			if strings.IndexByte(syntax.quotes, line[i]) >= 0 {
				kinds[i] = regionString
				singleLineString = line[i : i+1]
				i++
				continue
			}
			kinds[i] = regionCode
			i++
		}
	}
	// A single-line string cannot continue past the end of the line.
	return kinds
}

func lineCommentAt(line string, i int, syntax sourceSyntax) bool {
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

func blockCommentAt(rest string, syntax sourceSyntax) (string, string, bool) {
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

func leadingOnlyRegions(line string) []regionKind {
	kinds := make([]regionKind, len(line))
	trimmed := strings.TrimSpace(line)
	if _, ok := prefixIn(trimmed, leadingCommentMarkers); ok {
		for i := range kinds {
			kinds[i] = regionComment
		}
	}
	return kinds
}

// observedRegion returns "" when at least one occurrence of observed on the
// line contains code, otherwise what the text lies in: "comment", "string
// literal" or "comment or string literal".
func observedRegion(line string, kinds []regionKind, observed string) string {
	if observed == "" || len(kinds) != len(line) {
		return ""
	}
	sawComment, sawString := false, false
	for start := 0; start <= len(line)-len(observed); {
		offset := strings.Index(line[start:], observed)
		if offset < 0 {
			break
		}
		from := start + offset
		hasCode := false
		for i := from; i < from+len(observed); i++ {
			if line[i] == ' ' || line[i] == '\t' {
				continue
			}
			switch kinds[i] {
			case regionCode:
				hasCode = true
			case regionComment:
				sawComment = true
			case regionString:
				sawString = true
			}
		}
		if hasCode {
			return ""
		}
		start = from + 1
	}
	switch {
	case sawComment && sawString:
		return "comment or string literal"
	case sawComment:
		return "comment"
	case sawString:
		return "string literal"
	default:
		return ""
	}
}

// statementText returns the line without its comments: the statement a
// scanner flagged.
func statementText(line string, kinds []regionKind) string {
	if len(kinds) != len(line) {
		return line
	}
	var sb strings.Builder
	for i := 0; i < len(line); i++ {
		if kinds[i] != regionComment {
			sb.WriteByte(line[i])
		}
	}
	return sb.String()
}
