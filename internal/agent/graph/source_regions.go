package graph

import (
	"path/filepath"
	"regexp"
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

// fileRegions classifies every byte of lines[0..last], scanning the file from
// the top so block comments and multi-line strings opened earlier are known.
func fileRegions(lines []string, last int, syntax sourceSyntax) [][]regionKind {
	last = min(last, len(lines)-1)
	if last < 0 {
		return nil
	}
	regions := make([][]regionKind, last+1)
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

// codeOccurrences returns the offsets of the occurrences of observed on the
// line in which every non-whitespace byte is code. One byte of code is not
// enough: "x = 1  # input validated upstream" is a comment with a statement
// in front of it, not a mitigation. When no occurrence qualifies, where says
// where the text lies instead, phrased to follow "observed text".
func codeOccurrences(line string, kinds []regionKind, observed string) (starts []int, where string) {
	if observed == "" || len(kinds) != len(line) {
		return nil, "could not be located in the source line"
	}
	sawCode, sawComment, sawString := false, false, false
	for start := 0; start <= len(line)-len(observed); {
		offset := strings.Index(line[start:], observed)
		if offset < 0 {
			break
		}
		from := start + offset
		codeOnly := true
		for i := from; i < from+len(observed); i++ {
			if line[i] == ' ' || line[i] == '\t' {
				continue
			}
			switch kinds[i] {
			case regionCode:
				sawCode = true
			case regionComment:
				sawComment, codeOnly = true, false
			case regionString:
				sawString, codeOnly = true, false
			}
		}
		if codeOnly {
			starts = append(starts, from)
		}
		start = from + 1
	}
	if len(starts) > 0 {
		return starts, ""
	}
	region := "comment or string literal"
	switch {
	case sawComment && !sawString:
		region = "comment"
	case sawString && !sawComment:
		region = "string literal"
	case !sawComment && !sawString:
		return nil, "could not be located in the source line"
	}
	if sawCode {
		return nil, "is not code only: part of it lies inside a " + region
	}
	return nil, "lies inside a " + region + ", not in code"
}

// ── Identifiers ──────────────────────────────────────────────────────────────
//
// code_mitigation evidence must name something the flagged statement uses: a
// check of an unrelated variable does not protect it. These helpers extract
// the names on both sides. They work on bytes the region scanner classified,
// so names in comments never count and names in string literals count only
// where they are interpolated.

// interpolationPattern finds the {expression} parts of a string literal:
// Python f-strings, JavaScript template literals (${expr}), C# and Kotlin
// interpolation.
var interpolationPattern = regexp.MustCompile(`\{([^{}]*)\}`)

// commonIdentifiers never tie a mitigation to a finding: keywords, literals,
// built-in types and the receiver and context names present in almost every
// statement of a language. Compared in lower case.
var commonIdentifiers = stringSet(
	"and", "as", "assert", "async", "await", "break", "case", "catch", "class", "const", "continue",
	"def", "default", "defer", "del", "do", "echo", "elif", "else", "elsif", "end", "except", "export",
	"extends", "false", "final", "finally", "fn", "for", "foreach", "from", "func", "function",
	"go", "if", "implements", "import", "in", "include", "instanceof", "interface", "is", "lambda",
	"let", "local", "match", "mut", "new", "nil", "none", "not", "null", "of", "or", "package",
	"pass", "private", "protected", "pub", "public", "raise", "require", "return", "static",
	"struct", "super", "switch", "then", "throw", "throws", "true", "try", "type", "typeof",
	"undefined", "unless", "use", "using", "val", "var", "void", "while", "with", "yield",
	"bool", "boolean", "byte", "char", "double", "error", "float", "int", "len", "long", "object",
	"print", "printf", "println", "range", "str", "string",
	"self", "this", "cls", "ctx", "err",
)

// sqlKeywords are common identifiers in upper case only: in SQL sources they
// are keywords, elsewhere a lower-case "values" or "order" is a real name.
var sqlKeywords = stringSet(
	"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "INTO", "VALUES", "SET", "TABLE",
	"JOIN", "GRANT", "REVOKE", "ON", "TO", "AND", "OR", "NOT", "NULL", "AS", "BY", "ORDER",
	"GROUP", "LIMIT", "CREATE", "DROP", "ALTER", "EXEC", "EXECUTE", "UNION", "ALL", "IN", "IS", "LIKE",
)

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

func isIdentifierStart(c byte) bool {
	return c == '_' || c == '$' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isIdentifierPart(c byte) bool {
	return isIdentifierStart(c) || ('0' <= c && c <= '9')
}

// identifierSpans returns the [start, end) byte spans of the names in text. A
// token that starts with a digit is a number (0x1F, 1e9, 3.14), not a name.
func identifierSpans(text string) [][2]int {
	var spans [][2]int
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case isIdentifierStart(c):
			j := i + 1
			for j < len(text) && isIdentifierPart(text[j]) {
				j++
			}
			spans = append(spans, [2]int{i, j})
			i = j
		case '0' <= c && c <= '9':
			j := i + 1
			for j < len(text) && (isIdentifierPart(text[j]) || text[j] == '.') {
				j++
			}
			i = j
		default:
			i++
		}
	}
	return spans
}

// addIdentifier records a name unless it is too short or too common to tie a
// line to a finding. A leading $ (PHP, shell) is not part of the name.
func addIdentifier(names map[string]bool, name string) {
	name = strings.TrimLeft(name, "$")
	if len(name) < minSharedIdentifierLength || commonIdentifiers[strings.ToLower(name)] || sqlKeywords[name] {
		return
	}
	names[name] = true
}

// citedIdentifiers returns the names that lie wholly inside the code-only
// occurrences of a cited text of the given length. A name the citation cuts
// ("lex.quote(cm" out of "shlex.quote(cmd)") names nothing.
func citedIdentifiers(line string, starts []int, length int) map[string]bool {
	names := map[string]bool{}
	spans := identifierSpans(line)
	for _, start := range starts {
		for _, span := range spans {
			if span[0] >= start && span[1] <= start+length {
				addIdentifier(names, line[span[0]:span[1]])
			}
		}
	}
	return names
}

// statementIdentifiers returns the names of the statement on lines[flagged]:
// those in its code and in the interpolations of its string literals. A
// statement that continues past the flagged line while a parenthesis or
// bracket opened on it is still open (a call with one argument per line) is
// followed for up to maxStatementLines lines. Braces are not followed: they
// open blocks as often as literals.
func statementIdentifiers(lines []string, regions [][]regionKind, flagged int) map[string]bool {
	names := map[string]bool{}
	depth := 0
	for i := flagged; i >= 0 && i < len(regions) && i < flagged+maxStatementLines; i++ {
		line, kinds := lines[i], regions[i]
		if len(kinds) != len(line) {
			break
		}
		for _, span := range identifierSpans(line) {
			if kinds[span[0]] == regionCode {
				addIdentifier(names, line[span[0]:span[1]])
			}
		}
		for _, literal := range stringRuns(line, kinds) {
			for _, match := range interpolationPattern.FindAllStringSubmatch(literal, -1) {
				for _, span := range identifierSpans(match[1]) {
					addIdentifier(names, match[1][span[0]:span[1]])
				}
			}
		}
		for j := 0; j < len(line); j++ {
			if kinds[j] != regionCode {
				continue
			}
			switch line[j] {
			case '(', '[':
				depth++
			case ')', ']':
				depth--
			}
		}
		if depth <= 0 {
			break
		}
	}
	return names
}

// stringRuns returns the maximal runs of string-literal bytes on a line.
func stringRuns(line string, kinds []regionKind) []string {
	var runs []string
	for i := 0; i < len(line); {
		if kinds[i] != regionString {
			i++
			continue
		}
		j := i
		for j < len(line) && kinds[j] == regionString {
			j++
		}
		runs = append(runs, line[i:j])
		i = j
	}
	return runs
}
