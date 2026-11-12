package graph

import (
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/regions"
)

// ── Comment and string-literal regions ───────────────────────────────────────
//
// code_mitigation evidence must point at code. A model citing a comment
// ("# Local smoke test only - NOT for production.") or a string literal was
// enough to suppress a finding, because the validator only checked that the
// quoted text existed on the cited line. The regions package classifies each
// byte of a source line as code, comment or string literal. When a construct
// is ambiguous it leans towards "not code", which can only send a finding to
// manual review, never suppress one.

// codeOccurrences returns the offsets of the occurrences of observed on the
// line in which every non-whitespace byte is code. One byte of code is not
// enough: "x = 1  # input validated upstream" is a comment with a statement
// in front of it, not a mitigation. When no occurrence qualifies, where says
// where the text lies instead, phrased to follow "observed text".
func codeOccurrences(line string, kinds []regions.Kind, observed string) (starts []int, where string) {
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
			case regions.Code:
				sawCode = true
			case regions.Comment:
				sawComment, codeOnly = true, false
			case regions.String:
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
func statementIdentifiers(lines []string, lineKinds [][]regions.Kind, flagged int) map[string]bool {
	names := map[string]bool{}
	depth := 0
	for i := flagged; i >= 0 && i < len(lineKinds) && i < flagged+maxStatementLines; i++ {
		line, kinds := lines[i], lineKinds[i]
		if len(kinds) != len(line) {
			break
		}
		for _, span := range identifierSpans(line) {
			if kinds[span[0]] == regions.Code {
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
			if kinds[j] != regions.Code {
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
func stringRuns(line string, kinds []regions.Kind) []string {
	var runs []string
	for i := 0; i < len(line); {
		if kinds[i] != regions.String {
			i++
			continue
		}
		j := i
		for j < len(line) && kinds[j] == regions.String {
			j++
		}
		runs = append(runs, line[i:j])
		i = j
	}
	return runs
}
